# SSH Connect Broker — Design Note

> Status: **Exploration / not yet approved.** Filed in response
> to a real user-experience problem on the cloud product: tenants
> want to run `containarium connect <box>` from any laptop and be
> dropped into a shell, without per-machine SSH key management
> and without a long-lived private key on the client. This is the
> "zero-laptop-key" path. A separate design (`SSH-CA-DESIGN`,
> sketched in §"Alternate architecture") covers the cert-based
> path that complements this for self-host OSS deployments.

## Where we are today

The CLI already authenticates against the cloud:

- `containarium login` runs an OAuth-style device flow and
  stores a bearer token in `~/.containarium/credentials.json`
  (`internal/cmd/login.go:76`).
- `containarium ssh setup` generates or finds a local SSH key,
  uploads the **public** half to the cloud, registers it under
  a friendly name (`internal/cmd/ssh.go:85`).
- `containarium ssh propagate` pushes the registered key-set to
  every box the user owns (`internal/cmd/ssh.go:152`).
- `containarium ssh-config sync` writes a self-contained
  `~/.containarium/ssh_config` so `ssh <box-name>` Just Works
  after one `Include` line in `~/.ssh/config`
  (`internal/cmd/ssh_config.go`).

So the user's flow today is: **login → register a key on this
laptop → propagate → ssh-config sync → stock `ssh <box>`**. The
private key lives at a known path (`~/.ssh/id_ed25519` or
`~/.ssh/containarium_ed25519`) on every laptop the user wants to
SSH from.

Tenants on the cloud product keep asking for two things this
flow doesn't give them:

1. **Use any machine.** "I'm on a coworker's laptop / Chromebook
   / mobile terminal — can I get into my box without setting up
   a key first?"
2. **Don't store anything I have to rotate.** "If my laptop is
   stolen, the only thing I want to revoke is my Containarium
   login, not run around rotating SSH keys across N boxes."

## Threats / failure modes the design has to handle

| Failure mode | Mitigated? |
| --- | --- |
| Laptop theft → adversary has long-lived SSH keys for tenant's boxes | This design's whole point: no private key on the laptop |
| Adversary intercepts the user's bearer token from `~/.containarium/credentials.json` | Token-bound session: every connect call validates JWT signature + revocation list (`jti`); leak-response runbook already exists, this rides it |
| Compromised cloud broker reads tenant shell traffic | Detection (audit log + per-session checksums); short-term acceptance (broker is a trusted plane); long-term: end-to-end via SSH CA path (§Alternate architecture) |
| Broker → backend connection key is leaked | Sentinel-backend mTLS already rotates; this design reuses the same trust anchor |
| User wants SCP / port forwarding / agent forwarding | First class for the SSH subset of operations: SCP yes, local port forwarding yes; agent forwarding **out of scope for v1** (security smell — see Decision log) |
| User loses login token | Re-run `containarium login`; old `jti` revoked on next refresh attempt |
| Broker outage = nobody can reach their boxes | Direct SSH path (`ssh <box>` via `ssh-config sync`) remains supported as a fallback — broker is *additive*, never the only way in |
| Operator wants per-session-recordable shell for compliance | Audit log captures connect events; full session recording is a follow-up tied to the broker (out of scope for v1, but the seam is here) |

## Goals

1. `containarium connect <box>` is **one command** that drops the
   user into a shell, with **no private key on the laptop**.
2. The transport is JWT-authenticated; the same scope catalog
   that gates the REST API gates this surface.
3. Standard SSH semantics work where the protocol allows:
   interactive shell, `scp`, local port forwarding. (Agent
   forwarding and X11 forwarding are explicitly excluded — see
   Decision log.)
4. The broker is **stateless except for the live session table** —
   no key material persisted across restarts.
5. Direct SSH stays as a fallback. The broker is additive; the
   day it's down, `ssh <box>` still works.

## Architecture

### Components

```
        Laptop                  Cloud broker            Backend box
        ──────                  ────────────            ───────────

  containarium connect
        │
        │   HTTP/2 CONNECT     /v1/ssh/connect/{box}
        │   Authorization: Bearer <login token>
        ├──────────────────────►
        │                       │
        │                       │   Validate JWT (sig, exp, jti,
        │                       │   scope=ssh:connect)
        │                       │   Authorize (owner / collaborator)
        │                       │   Mint per-session ephemeral key
        │                       │
        │                       │     SSH (over sentinel mTLS hop)
        │                       ├─────────────────────────────────►
        │                       │
        │   <── bidirectional stream ───┘
        ↕                       ↕                                ↕
     stdin/stdout/stderr     bytes copy                    sshd on box

  Audit event appended at:
   - connect open  (broker)
   - connect close (broker)
   - first-byte    (sentinel, for liveness)
```

Three pieces:

- **Broker endpoint** lives on the API server (`internal/server/`).
  New RPC `SSHConnect` over gRPC, exposed as
  `POST /v1/ssh/connect/{box}` via grpc-gateway with the
  `(google.api.http)` annotation upgraded to support HTTP/2
  CONNECT (or WebSocket — see Open questions). It returns a
  bidirectional byte stream.
- **Sentinel SSH leg.** The broker dials sshpiper on the sentinel
  using a per-session ephemeral key pair generated in-memory.
  The ephemeral pub key is added to the target box's
  `authorized_keys` immediately before the connect, removed
  immediately after — bounded by a TTL fallback if cleanup
  fails. This is similar in shape to how
  `internal/sentinel/keysync.go` already manages sentinel-side
  key fan-out.
- **CLI**. `containarium connect <box>` opens the HTTP/2 CONNECT
  to the broker with the stored bearer token, sets the terminal
  to raw mode, copies stdio in/out of the stream. No SSH client
  binary involved on the client side.

### Wire protocol

The broker exposes one streaming RPC; the gateway tunnels it as
HTTP/2 CONNECT. The streamed bytes ARE the SSH protocol exchanged
between the broker's SSH client (on the cloud side) and the
target box's sshd. The CLI never speaks SSH — it speaks raw
bytes to the broker, which in turn speaks SSH to the box.

```proto
service SSHConnectService {
  rpc Connect(stream ConnectClientMessage)
      returns (stream ConnectServerMessage);
}

message ConnectClientMessage {
  oneof payload {
    OpenSession open  = 1;  // first message only
    bytes       stdin = 2;  // user input bytes
    Resize      resize = 3; // PTY window changes
    Signal      signal = 4; // CTRL-C etc.
  }
}

message ConnectServerMessage {
  oneof payload {
    OpenSessionAck ack    = 1;
    bytes          stdout = 2;
    bytes          stderr = 3;
    ExitStatus     exit   = 4;
  }
}

message OpenSession {
  string box = 1;
  string user = 2;          // optional; default = box owner
  PTY    pty = 3;
  string command = 4;       // optional; empty = interactive shell
  repeated PortForward forwards = 5; // local-to-remote port forwards
}
```

REST mapping: `POST /v1/ssh/connect/{box}` with HTTP/2 CONNECT,
streaming protobuf or — under discussion — a thin
length-prefixed framing for browser-WebSocket compatibility (see
Open questions).

### Authentication & authorization

- **AuthN.** Same bearer token as the rest of the API. The
  token's `jti` is checked against the revocation list on every
  connect (not just at issue). Scope required: **`ssh:connect`**
  (new; minted by `containarium token generate --scopes=
  ssh:connect,...`). Existing `ssh:write` covers
  authorized_keys mutation; we keep them distinct so a token
  that can open shells doesn't necessarily get to rewrite the
  authorized_keys file across the fleet.
- **AuthZ.** The broker resolves the target box via the
  container service, checks that the principal is the owner or
  a registered collaborator (existing collaborator model — see
  `internal/cmd/collaborator.go` and `internal/cmd/collaborator_add.go`),
  applies any per-box deny-list (out of scope for v1; the hook
  is there).
- **Ephemeral key lifecycle.** Per-session key generated in-RAM
  on the broker; never written to disk. Added to the box's
  `authorized_keys` via a single-use `command="…"`,
  `restrict`-prefixed entry; entry is removed in the broker's
  `defer` block when the stream closes. TTL-based janitor runs
  every 60s to clean any orphans from broker crashes.

### Audit

Every Connect emits two events into the existing hash-chained
audit log (`audit verify` already validates the chain):

- `ssh.connect.open` — principal, box, source IP, jti, ephemeral
  key fingerprint, session-id (random 128-bit).
- `ssh.connect.close` — session-id, duration, byte counts in/out,
  exit reason (clean, signal, broker-crashed, idle-timeout).

Session-id is the join key for any later session-recording
follow-up.

### Surfaces

| Surface | Who calls it | Audience |
| --- | --- | --- |
| `containarium connect <box>` | The user, from CLI | Humans + agents wrapping the CLI |
| `mcp__containarium-*__ssh_connect` | Off-box agent via platform MCP | AI agents |
| `POST /v1/ssh/connect/{box}` | Direct REST consumers | Web UI shell tab, third-party clients |
| Sentinel-side gRPC into the broker | Internal | Audit + observability |

Per CLAUDE.md: this lands as `containarium connect` in cobra
first; the MCP tool wraps the same Go function.

## CLI surface

```
containarium connect <box>
  [--user <linux-user>]          # default: owner
  [--command "<cmd>"]            # default: interactive shell
  [-L local:remote]              # local port forward (repeatable)
  [--server <host:port>]         # override cloud broker
  [--no-pty]                     # for non-interactive piping
```

Behaviour notes:

- If the user is not logged in: prompt them to `containarium
  login` first. Don't auto-launch a browser — surprise side
  effects from a connect command are anti-pattern.
- If the box is stopped: error with the exact `containarium
  wake <box>` invocation to start it.
- If the token is missing `ssh:connect` scope: error with
  the exact `containarium token generate` command they need to
  mint a new one.

## Phased rollout

| Phase | Scope | Bound |
| --- | --- | --- |
| **A — proto + auth** | `SSHConnect` RPC + REST shim + JWT/scope gate (Connect returns "not implemented" but the auth path is real and tested) | 1 week |
| **B — broker** | Real broker implementation: ephemeral key mint + sentinel SSH leg + bidirectional byte copy. Interactive shell only (no port forward yet). | 2 weeks |
| **C — CLI** | `containarium connect` with PTY raw mode, signals, resize. Audit events firing. | 1 week |
| **D — extras** | `-L` local port forwards, `--command` non-interactive mode, `--no-pty` for scripts. | 1 week |
| **E — MCP wrapper + web-UI shell tab** | Platform MCP tool; embed in the web UI dashboard so tenants can shell into a box from the browser. | 1 week |

Total: **5–6 weeks bounded**. Phase A is independently shippable
as the auth-gating foundation any later phase can rely on.

## Open questions

- **HTTP/2 CONNECT vs WebSocket.** CONNECT is cleaner protocol-wise
  but some corporate proxies block it. WebSocket gets through
  more environments at the cost of one framing layer. Defer to
  Phase A — start with CONNECT, add WebSocket fallback if
  reports come in.
- **Per-org broker placement.** For multi-tenant cloud, do we run
  one broker per region or one global broker? Latency to the
  backend matters for shell feel; same-region broker is
  preferred. Probably one-per-pool, reusing the existing pool
  abstraction (`internal/sentinel/pool.go`).
- **Idle session timeout.** Default 15 min idle = disconnect?
  Configurable per token? Currently I'd say yes, 15 min, hard
  override via `--keep-alive`.
- **Session recording.** Not in v1 scope, but the byte stream
  passes through the broker — we *could* tee it to object
  storage for compliance customers. Comes back as a follow-up
  RFC if anyone asks; the seam is in place.

## Decision log

- **Broker, not SSH CA, for v1.** SSH CA (option B in the
  conversation that produced this doc) still has a private key
  on the client — ephemeral, but it exists. The cloud product's
  pitch is "you bring only an agent." Broker delivers that
  literally. SSH CA remains valid for OSS self-host and ships
  as a sibling design (`SSH-CA-DESIGN`, not yet written) so
  operators who don't want to centralize shell traffic have
  the other option.
- **JWT-bound, not separate session tokens.** Reusing the
  existing token machinery (issuance, revocation, audit,
  scopes) means one revocation surface — `containarium token
  revoke <jti>` kills login + connect at once. Inventing a
  second token type would double the leak-response surface.
- **No agent forwarding in v1.** Forwarding an SSH agent
  through the broker is precisely the "private key
  centralization" anti-pattern this design is trying to avoid.
  Tenants who need it can fall back to direct SSH; we won't
  pretend the broker supports it.
- **No X11 forwarding ever.** It's a security smell and almost
  nobody in this user base needs it. Not a v1 vs v2 question;
  just no.
- **Ephemeral keys via single-use authorized_keys entry, not
  signed certs.** Signed certs would require sshd CA
  configuration on every backend; authorized_keys with
  `command=`/`restrict` prefixes works on stock sshd with no
  per-box configuration change. Trades one-off janitor risk
  (orphan entries) against fleet-wide config simplicity.
- **Direct SSH is not deprecated.** The broker is additive. If
  it's down or unreachable, `ssh <box>` via `ssh-config sync`
  still works. We never remove the escape hatch.

## What this is NOT

- **Not a session-recording / compliance product.** That's a
  follow-up; this design only makes it implementable.
- **Not a Teleport replacement.** No PAM integration, no SAML
  IdP, no cluster-wide role taxonomy. Just JWT scopes + box
  ownership.
- **Not a kubectl-exec or container-shell tool.** This shells
  into the LXC, not into a Docker container inside the LXC.
  For the latter, the agent uses `shell_exec` via `agent-box`
  inside the LXC after connecting.
- **Not an admin-only feature.** Tenants use this on their own
  boxes; the existing ownership / collaborator model gates who
  can shell into what.

## Alternate architecture (option B — SSH CA)

For self-host OSS deployments where operators don't want shell
traffic going through a centralized broker, the same problem can
be solved with an SSH certificate authority:

- `containarium connect <box>` calls a "mint cert" REST
  endpoint, receives a 5-minute SSH user certificate signed by
  a per-host CA whose private key lives in the existing KMS
  envelope (Vault Transit / GCP KMS).
- An in-memory keypair is generated on the laptop, the cert
  binds to it, stock `ssh` is exec'd with `-o
  CertificateFile=...`, cert expires.
- Boxes' sshd is configured to trust the CA via
  `TrustedUserCAKeys`.

Tradeoffs vs the broker:

- **+** Traffic never traverses the cloud — end-to-end SSH
  between laptop and box.
- **+** Standard SSH semantics work everywhere (scp, port
  forwarding, agent forwarding if you want it).
- **−** An ephemeral private key briefly exists on the laptop.
  "Zero key on disk" becomes "key valid for 5 minutes,
  best-effort cleanup."
- **−** Every backend's sshd config must be updated to trust
  the CA. The broker design needs no backend config change.

The two designs share the same auth layer (login token,
`ssh:connect` scope, audit log entries). Only the transport
differs. A future operator can pick per-pool which is enabled.
This document covers the **broker** path; the SSH-CA path is a
sibling design when there's demand.

## Related

- The CLI ↔ MCP symmetry rule in [`CLAUDE.md`](../CLAUDE.md):
  `containarium connect` lands as the cobra subcommand first;
  MCP wraps it.
- The proto-first contract rule in [`CLAUDE.md`](../CLAUDE.md):
  `SSHConnectService` is defined in
  `proto/containarium/v1/ssh_connect.proto` (to be added);
  `pkg/pb/`, the REST gateway, and the OpenAPI doc regenerate
  from it.
- [`docs/SENTINEL-DESIGN.md`](SENTINEL-DESIGN.md) — sshpiper +
  Caddy + PROXY-protocol on the sentinel. The broker leans on
  the existing sentinel-backend trust chain.
- [`docs/security/OPERATOR-SECURITY-RUNBOOK.md`](security/OPERATOR-SECURITY-RUNBOOK.md)
  — JWT scope catalog, token leak response. Gets a new section
  on `ssh:connect` semantics + how to revoke a live session
  when this lands.
- [`internal/sentinel/keysync.go`](../internal/sentinel/keysync.go)
  — existing single-source-of-truth for sentinel-side
  authorized_keys management; the broker's per-session
  ephemeral-key add/remove rides this rather than reinventing.
- The 2026-05-27 user conversation (in
  `experimental/insforge-pr-draft/`'s sibling conversation
  thread) — concrete motivating ask: "we run `./cli connect`
  it send to cloud and forward to the destination container.
  so the private key is never saved into local."
