# Compose Autostart — Design Note

> Status: **Exploration / not yet approved.** Filed in response
> to a real production incident on `containarium.footprint-ai.com`
> (2026-05-24): the `cloud-daemon-container` LXC restarted after
> a host reboot, but its `podman-compose` workload (postgres +
> nginx + cloud-daemon) was left in `Created` state because
> nothing inside the LXC owned its restart lifecycle. The tenant
> had to be told to `cd ~/deploy && podman-compose up -d` by
> hand. Every Containarium tenant running compose has this gap.

## Where we are today

Containarium sets `boot.autostart=true` on every LXC at create
time, so the LXC itself comes back after a host reboot. But the
**workload inside the LXC** is whatever the tenant launched
last. If they ran `docker compose up -d` interactively, nothing
remembers that on the next boot.

Tenants discover this the hard way: their site goes down after
a host reboot, they SSH in, they see `podman ps -a` showing
containers in `Created` state, and they re-run `up -d`. Every
tenant. Every time.

This is not a platform.

## Threats / failure modes the design has to handle

| Failure mode | Mitigated? |
| --- | --- |
| Tenant's compose stack stops on host reboot | This design's whole point |
| Tenant ran compose for a one-shot job and doesn't want it auto-restarted | Opt-in: never enabled unless asked |
| Tenant is using docker (not podman); design must work for both | Both supported (auto-detected per-tenant) |
| Tenant has multiple compose stacks (`frontend/` + `backend/`) | Multi-instance: one systemd unit template, instance per directory |
| Agent inside the box needs to know "is my compose autostart-protected?" | Discovery primitive callable from agent-box (in-box MCP) |
| Operator (or external agent via platform MCP) needs to enable for a tenant | Mirrored via daemon RPC + platform MCP |
| Compose dir moves / disappears | Unit fails on next boot (Restart=on-failure with backoff); operator sees `systemctl --user status` |

## Goal

Tenants (and agents acting on their behalf) can:

1. **Discover** which compose stacks exist in their box and
   which are autostart-protected.
2. **Opt-in** any compose stack to autostart with a single
   command, from either inside the box (agent-box) or outside
   (operator CLI / MCP).
3. **Survive a host reboot** without intervention once they've
   opted in.
4. **Work with whichever compose runtime they have installed**:
   `podman-compose`, `docker compose`, or `podman compose`
   (4.x+ builtin) — auto-detected at unit-install time.

## Architecture

### Inside the LXC

A user-systemd template unit, installed once per tenant under
`~/.config/systemd/user/`:

```ini
# containarium-compose@.service
[Unit]
Description=Containarium compose autostart: %i
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=%h/%i
# COMPOSE_BIN is resolved at install time:
#   podman-compose | docker compose | podman compose
Environment=COMPOSE_BIN=/usr/local/lib/containarium/compose-bin
ExecStart=/bin/sh -c '"$COMPOSE_BIN" up -d'
ExecStop=/bin/sh -c '"$COMPOSE_BIN" down'
Restart=on-failure
RestartSec=10

[Install]
WantedBy=default.target
```

Plus a small wrapper at `/usr/local/lib/containarium/compose-bin`
that resolves the actual binary at runtime (so an upgrade of
the tenant's compose tooling doesn't require re-installing the
unit).

`loginctl enable-linger $TENANT` ensures user-systemd starts
at host boot regardless of whether the tenant is logged in.

### Discovery

Pure-local-filesystem walk inside the LXC: look for
`docker-compose.{yml,yaml}` or `compose.{yml,yaml}` files
under `$HOME` (depth-limited; skip `node_modules`,
`.git`, `vendor`, etc.). For each found stack, report:

- absolute path to the compose file
- absolute path to the compose directory
- whether it's currently running (`<compose-bin> ps` exit + output)
- whether it's autostart-protected (does a
  `containarium-compose@<slug>.service` exist + is it enabled?)
- last-modified time of the compose file vs. last-modified time
  of the unit (so agents can flag "compose has changed since
  autostart was set up")

Same logic, called from both surfaces:
- `agent-box compose discover` (in-box MCP)
- `containarium compose discover <user>` (operator CLI via
  daemon RPC)

### Surfaces

| Surface | Who calls it | Audience |
| --- | --- | --- |
| `agent-box compose {discover,enable,disable,status}` | Agent inside the LXC, talks to local filesystem + systemd-user | Self-managing agents |
| `containarium compose {discover,enable,disable,status} <user>` | Operator, daemon RPC into the LXC | Humans + operator workflows |
| `mcp__containarium-*__compose_*` tools | External agents via platform MCP | Off-box agents |
| `containarium create <user> --auto-restart-compose=DIR` | Operator at provision time | Tenants set up once |

### Self-discovery flow (the agent path)

An agent setting up its workload, end-to-end:

```
agent inside LXC:
  → agent-box compose discover
    ← {"stacks": [
         {"path":"~/deploy/docker-compose.yml",
          "running": true, "autostart": false, "compose_bin": "podman-compose"},
         {"path":"~/playground/test/compose.yml",
          "running": false, "autostart": false, "compose_bin": "podman-compose"}
       ]}

agent decides: production stack at ~/deploy should survive reboots
  → agent-box compose enable --dir ~/deploy
    ← installed containarium-compose@deploy.service; enabled; linger ON

agent leaves ~/playground/test/ unprotected (it's a scratchpad)
```

Discovery is **read-only**. Enable is **opt-in** per stack.

### Proto contract

```proto
service ComposeAutostartService {
  rpc Discover(DiscoverRequest) returns (DiscoverResponse);
  rpc Enable(EnableRequest)     returns (EnableResponse);
  rpc Disable(DisableRequest)   returns (DisableResponse);
  rpc Status(StatusRequest)     returns (StatusResponse);
}

message ComposeStack {
  string username = 1;
  string compose_dir = 2;      // absolute path inside the LXC
  string compose_file = 3;     // absolute path to the compose.yml
  string compose_bin = 4;      // "podman-compose" | "docker compose" | "podman compose"
  bool running = 5;
  bool autostart_enabled = 6;
  string unit_name = 7;        // containarium-compose@<slug>.service when enabled
  google.protobuf.Timestamp compose_modified_at = 8;
  google.protobuf.Timestamp unit_modified_at = 9;
}
```

Same shape for `agent-box compose discover` JSON output —
the in-box tool isn't a gRPC client, but the schema matches
so an agent can write one parser for both.

## Phased rollout

| Phase | Scope | Bound |
| --- | --- | --- |
| **A — design + helpers** | This doc + the `/usr/local/lib/containarium/compose-bin` wrapper baked into stack scripts | 2 days |
| **B — agent-box subcommand** | `agent-box compose {discover,enable,disable,status}` against local filesystem + systemd-user. No daemon involvement. | 3 days |
| **C — daemon proto + RPC** | `ComposeAutostartService` end-to-end (proto → server → CLI → platform MCP wrapper). Daemon execs into the LXC via existing `container.Manager.Exec` | 1 week |
| **D — `containarium create --auto-restart-compose`** | Provision-time integration. Tenants opt in at create. | 2 days |
| **E — operator runbook + migration** | Doc section + the retroactive `containarium compose enable --all` for fixing existing prod containers (like cloud-daemon-container today) | 2 days |

Total: **2-3 weeks bounded**, Phase B independently shippable as
the highest-value primitive (agents can self-protect immediately
without daemon-side work).

## Open questions

- **Compose-file discovery depth.** A naive walk of `$HOME`
  finds compose files under `node_modules/` or `vendor/`
  (vendored examples). Skip-list pattern: `node_modules`,
  `.git`, `vendor`, `target`, `dist`. Configurable but with a
  sane default.
- **What counts as "running"?** `<compose-bin> ps -q` returning
  non-empty? Some compose tools also surface "Created" vs
  "Up." Probably surface both: `running_count` + `total_count`.
- **Multiple compose files per directory** (`compose.yml` +
  `compose.override.yml`). The unit invokes the compose tool
  in the directory, which handles overrides itself — no
  special logic on our side.
- **Unit conflict with hand-installed user units.** If the
  tenant already has `~/.config/systemd/user/myapp.service`
  doing the same thing, ours coexists peacefully (different
  unit name). Discovery should report both.
- **GPU passthrough.** Containers stamped with NVIDIA devices
  need `--gpus all` in their `compose.yml`. Out of scope for
  this design — tenants who use GPU compose are already
  handling that themselves.

## Decision log

- **Opt-in, not opt-out, even on `create`.** Tenants who run
  compose for one-shot jobs (CI, batch jobs, manual testing)
  shouldn't have their workloads auto-restarted by surprise.
  `--auto-restart-compose` is an explicit flag.
- **Both podman-compose AND docker compose.** Detection at
  install time picks the right binary; the wrapper isolates
  the runtime choice from the unit file.
- **agent-box surface lands BEFORE daemon RPC (Phase B before
  Phase C).** Agent self-protection is the highest-value
  primitive; landing it first means tenants and agents get
  the win without waiting for proto work.
- **Linger enabled on every install.** Without `loginctl
  enable-linger`, the user-systemd doesn't start at host boot
  and the whole design fails silently.
- **Reuse `container.Manager.Exec` for daemon-side install.**
  Existing infrastructure for stamping secrets already runs
  commands inside the LXC; the install command is "one more
  consumer of that pattern."

## What this is NOT

- Not a replacement for podman quadlets. Quadlets are the
  Red-Hat-blessed long-term answer (declarative `.container` /
  `.pod` / `.kube` files); they require tenants to migrate
  their compose stack. This design works on the compose files
  tenants already have.
- Not a systemd-unit-management product. We install exactly
  one templated unit per tenant; everything else is the
  tenant's domain.
- Not a compose-validity check. If the tenant's
  `compose.yml` is broken, our unit fails on next boot and
  surfaces the error via `journalctl --user -u
  containarium-compose@<slug>`. Same debugging story as
  doing it by hand.

## Related

- The 2026-05-24 cloud-daemon-container incident — concrete
  motivating example. After a host reboot, three podman
  containers were left in `Created` state; the tenant had to
  manually `podman-compose up -d`.
- [`docs/security/OPERATOR-SECURITY-RUNBOOK.md`](security/OPERATOR-SECURITY-RUNBOOK.md)
  — operator-facing security runbook; will get a sibling
  section on compose-autostart when this lands.
- [Containarium `--stack` flag](../README.md) — the existing
  provision-time stack installer. `compose-bin` wrapper
  shipping in Phase A goes through the same install path.
