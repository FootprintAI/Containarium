# Container Env-Var Introspection Risk (Audit C-MED-4)

This is a design note about how Containarium currently delivers tenant
secrets into containers, the risk that comes with it, and the
tmpfs-mount alternative we plan to offer as opt-in.

## Today: env-var stamping

`internal/server/secrets_server.go:stampSecretsOnLXC` calls
`incus config set environment.<NAME>=<value>` for every secret a tenant
owns. The values land in the LXC's Incus config; on the next container
start (or `RefreshSecrets` call) they become environment variables of
the container's init process (`PID 1`) and inherit into every child
process via `execve(2)`.

The app code reads them as `os.Getenv("OPENAI_API_KEY")` or whatever's
idiomatic in its language — convenient, language-agnostic, no SDK.

## What "in env" means in practice

Once a value is in the container's environment, every process that can
escalate to the same UID — and many that can't — can read it:

| Reader                            | Has access?                                  |
| --------------------------------- | -------------------------------------------- |
| Any process running as the app UID | Yes (`/proc/self/environ`)                  |
| Root inside the container         | Yes (`/proc/<any-pid>/environ`)              |
| `ps eww` from a peer process      | Yes if same UID, no otherwise                |
| Container init's child after fork | Yes (inherited)                              |
| New `exec` inside the container   | Yes                                          |
| Docker / podman-in-LXC sub-container | Only if the operator explicitly forwards it |
| Operator on the daemon host       | Yes (`incus config show`)                    |
| Another tenant's container        | No (separate LXC, separate kernel namespaces) |

The interesting columns for tenants are the first three. If an
attacker gets RCE inside the container, even as a non-root user, they
can read every secret the app process can read. The env vars are also
visible in `/proc/<pid>/environ` to root — so a privileged daemon
inside the same container (logging agent, supervisor) sees them too.

That's a wider surface than many operators assume. It does NOT cross
tenant boundaries (one container can't read another's env), but it
does NOT confine secrets within a single container either.

## Threat model — what this DOES and DOES NOT protect

What's already protected (today):
- **Cross-tenant exposure**: secrets are scoped per `username` in the
  `secrets` table, encrypted with AES-256-GCM at rest, and stamped
  into exactly one LXC. Another tenant's container can't read them.
- **Operator audit trail**: every `set_secret` / `get_secret` is
  audit-logged.
- **At-rest encryption**: the master key lives at
  `/etc/containarium/secrets.key` mode 0400, off the wire and not in
  any backup unless the operator explicitly arranges it.

What's NOT protected (audit C-MED-4):
- **Same-container introspection**: any process inside the container
  that can read `/proc/<pid>/environ` sees every secret. That's the
  Linux env-var contract.
- **Docker-in-LXC sub-containers**: the LXC has the env, but docker
  run / docker compose require explicit `-e` passthrough. Operators
  who forget the passthrough get a "missing env var" runtime error —
  visible failure mode, not silent.

## Mitigations available today

For an operator who needs to harden this further without waiting for
the tmpfs alternative:

1. **Don't put high-risk secrets in env vars.** Use the secret-manager
   pattern: store a short-lived bootstrap token in env, have the app
   fetch the real secret from a vault on startup. The bootstrap token
   stays in env; the real secret never does.
2. **Drop privileges inside the container.** A non-root app user with
   `setuid` semantics can read its own `/proc/self/environ` but not
   that of root daemons. (The reverse is also true — root can read
   everyone.)
3. **Audit `incus config show`** access. Operators who can run that
   command see every container's secrets. Limit who has the
   incus-admin group on the daemon host.
4. **Rotate aggressively.** The combination of Phase 1.2 (jti +
   revocation), Phase 1.6 (short-lived access + refresh rotation), and
   `containarium secret set` (which versions in place) means an
   exposed secret has a bounded blast radius.

## Future: tmpfs-mount alternative (planned, not yet implemented)

The cleanest mitigation is to stop putting secrets in env entirely:

- Mount a `tmpfs` into the container at e.g. `/run/secrets/`.
- Write each decrypted secret to its own file, mode `0400`,
  owned by the app user (not root).
- App reads from the file instead of `os.Getenv`.

Properties:
- **Per-process access control**: file permissions, not the env-var
  free-for-all. The app user can read; root can read; nobody else.
- **No execve inheritance**: values aren't passed to child processes
  unless the app explicitly hands them off.
- **No `incus config show` leak**: tmpfs contents aren't in the
  Incus config — only the mount point is.
- **Crash-safe disposal**: `tmpfs` exists in kernel memory, evicted
  when the container stops. No risk of secrets persisting in
  container snapshots.

Costs:
- App-side change: read files instead of env. Most apps that already
  support `<SECRET>_FILE` env-var conventions (Postgres password,
  Vault sidecars, Docker Compose secrets) work with no code change —
  set `PGPASSWORD_FILE=/run/secrets/PGPASSWORD` instead of
  `PGPASSWORD=…`.
- Operator UX: a second toggle on `containarium secret set`
  (`--delivery=env|file`, opt-in to file mode).
- One more code path on the daemon (mount management, file rotation
  on `RefreshSecrets`).

The plan is to offer this as **opt-in alongside** the env-var path,
not as a replacement. Operators choose per-tenant or per-secret. The
default stays env-stamping for backwards compatibility; new
deployments are encouraged to use file mode for high-risk values.

## References

- Audit finding **C-MED-4** in
  [`ZERO-TRUST-AUDIT.md`](ZERO-TRUST-AUDIT.md).
- Implementation in `internal/server/secrets_server.go`.
- Related: PR #248 (jti + revocation), PRs #254 / #255 (refresh
  rotation) — both shrink the blast radius of any exposed credential
  derived from an env-var leak.
