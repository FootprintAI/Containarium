# SSH Live Authorization — Design Note

> Status: **Exploration / not yet approved.** Filed in response to
> an offboarding gap: a user who registered an SSH public key keeps
> access to every box that key was installed on after they leave the
> organization, and nothing on the platform notices. This note
> proposes checking the offered key against the cloud control plane
> on every connection, with an optional device-approval step on top.
> It complements [SSH-CONNECT-BROKER-DESIGN.md](SSH-CONNECT-BROKER-DESIGN.md)
> (zero-laptop-key path) and the SSH CA certificate path; it does not
> replace either.

## The problem

An SSH public key is a possession credential. Once installed in an
`authorized_keys` file it works until someone edits that file. In an
enterprise, access has to end on the day a person leaves, from one
place, and an operator has to be able to see that it ended. The
platform does not give that today.

### Where we are today

SSH access is gated by static `authorized_keys` files, not by a live
identity check.

- The sentinel's `sshpiperd` is the only hop that verifies a client's
  key. It reads per-login `authorized_keys` files that the sentinel
  copies from each backend's `/authorized-keys` endpoint on a 2-minute
  timer (`internal/sentinel/keysync.go`, `internal/sentinel/manager.go`).
  There is no `AuthorizedKeysCommand` and no per-connection call to
  the control plane.
- Boxes trust only the sentinel's upstream key for the second hop
  (`internal/gateway/keys_handler.go`).
- Registered keys have no expiry. `AddSSHKeyRequest` carries only a
  username and a public key (`proto/containarium/v1/container.proto`).
- `containarium ssh remove` deletes the key from the user's cloud
  record and tells the user to run `containarium ssh propagate`. The
  cloud-side `PropagateSSHKeysToBoxes` RPC is not implemented; the CLI
  prints a warning and exits 0 (`internal/cmd/ssh.go`). Existing boxes
  keep the key.
- `containarium token revoke` revokes a JWT. It does not touch SSH.
  The two credential systems are independent.
- The SSH CA path exists but is additive: `trusted_user_ca_keys` is
  written next to `authorized_keys`, raw keys stay enabled, and the
  K8s runtime has no CA trust at all. The certificate revocation list
  (`krl_spec`) is delivered in the trust bundle but nothing reads it.
- Session audit records carry a key fingerprint and the target box
  login, not a person (`internal/sentinel/sshsession/record.go`).
  There is no fingerprint-to-user mapping and no alert.

So after offboarding, a departed user's key still opens every box it
was installed on, and a login would appear in the audit store only as
an unlabelled fingerprint that an operator would have to match by
hand.

## Threats / failure modes the design has to handle

| Failure mode | Mitigated? |
| --- | --- |
| User leaves the org; their registered key still opens existing boxes | **This design's whole point.** Every connection is authorized against the cloud's current record, so one deactivation ends SSH access everywhere on the next attempt |
| Key copied or kept offline by someone whose cloud login is still valid (stolen laptop, shared key) | Optional device approval (§Design, step 2): the first connection from a new device must be confirmed in the cloud UI |
| Cloud control plane unreachable from the sentinel | Fail closed after a short cached grace window. Never fall back to the last-known static key set |
| Boxes reachable by SSH without going through the sentinel (LAN, overlay network) | Out of band of this design; must be confirmed per deployment, or the same live check runs as an `AuthorizedKeysCommand` on the host (§Open questions) |
| Session opened before revocation keeps running | Deactivation also fans out a session kill, reusing the collaborator-removal path (`pkg/core/container/collaborator.go`) |
| Per-connection approval breaks scp, git, agents, CI | Approval is per device session with a TTL, not per connection. Certificate holders skip it |
| Raw key kept for years with no rotation | Key age is enforced by the live check; `containarium ssh rotate` regenerates locally with an overlap window (§Design, step 4) |
| Extra round trip on every SSH connection | One HTTPS call at the sentinel; positive answers cached for seconds, negative answers never cached longer than the grace window |
| Compromised sentinel asks the cloud nothing and lets everyone in | Unchanged from today: the sentinel is already the trust boundary. The cloud-side audit of authorization checks makes a silent sentinel visible |

## Goals

1. **One revocation surface.** Deactivating a user on the cloud, or
   removing them from an org or a box, ends their SSH access on the
   next connection attempt, on every backend, with no per-box work.
2. **Identity in the audit trail.** Every session record names the
   user the key belonged to at the time of the login, and a login by
   a deactivated or unknown key is flagged.
3. **No new friction for the common path.** Plain `ssh <box>` with a
   registered key keeps working. The CLI and agents using
   certificates see no change.
4. **Optional second factor.** A tenant policy can require that a
   new device be approved in the cloud UI before its key is accepted.

### Non-goals

- Replacing the static `authorized_keys` sync. It stays as the
  routing table; this design changes only whether a key is
  *accepted*, not where it is *routed*.
- Session content recording.
- Removing raw-key auth. That is the CA migration's job.

## Design

### 1. Live authorization at the sentinel (the guarantee)

The sentinel already runs a first-position `sshpiperd` plugin that
sees the offered credential on every connection and stashes its
fingerprint before deferring to the routing plugin
(`internal/sentinel/sshsession/plugin.go`). A new plugin, or an
extension of that one, makes the accept decision instead of
deferring blindly:

```
ssh client ──► sshpiperd ──► authz plugin ──► cloud: POST /v1/ssh/authorize
                                 │                    { fingerprint, login, sentinel_id, client_addr }
                                 │              ◄──── { allow, user_id, reason, ttl, approval_required }
                                 ▼
                         routing plugin (yaml) ──► box
```

The cloud answers from its current record:

- Does this fingerprint belong to a user? Is that user active?
- Does that user still have access to the box behind `login`
  (owner, collaborator, org member)?
- Does the tenant's policy require device approval, and has this
  device been approved?

A `deny` short-circuits the chain; sshpiperd never consults the
static file for that key. An `allow` defers to the routing plugin as
today. The static files therefore stop being an authorization source
and become a routing table.

**Caching.** Positive answers are cached in memory for `ttl` seconds
(default 30). Negative answers are not cached. If the cloud is
unreachable, a cached positive answer is honoured until a grace
window expires (default 5 minutes), then the sentinel denies. This
is the opposite of today's keysync behaviour, which keeps last-known
keys indefinitely on backend failure, and that difference is
deliberate.

**Certificates.** A connection that offers a CA certificate skips the
live call. Issuance already required a live JWT seconds earlier, and
the certificate's validity window bounds its lifetime. The plugin
still records the certificate identity as today.

**Revocation of live sessions.** When the cloud deactivates a user,
it fans out to every backend hosting a box that user could reach,
and each backend terminates that user's in-container sessions and
jump-account sessions using the existing collaborator-removal
primitives. The sentinel does not tear down pipes itself.

### 2. Device approval (the optional second factor)

A tenant policy flag, `ssh_device_approval: required`, adds one
step for raw-key logins from a device the cloud has not seen:

1. The cloud answers `allow: false, approval_required: true` and
   creates a pending approval keyed by `(user, fingerprint,
   client_addr)` with a short code.
2. The plugin uses the sshpiperd banner callback to print the code
   and the approval URL, then polls the cloud for up to 60 seconds.
   The anonymous-box plugin already drives the banner and
   keyboard-interactive callbacks this way
   (`internal/sentinel/anondoor/plugin.go`).
3. The user confirms in the cloud UI, which requires their normal
   login and whatever second factor that login already has.
4. On approval the cloud records the device with a TTL (default 12
   hours, tenant-configurable). Later connections from the same
   `(user, fingerprint, client_addr)` are answered `allow` without
   a prompt until the TTL lapses.

This is a per-device-session approval, not a per-connection one, so
scp, git over SSH, and scripted use keep working inside the window.
Certificate holders are never asked.

### 3. Identity in the audit trail

The authorization response carries `user_id`. The session plugin
writes it into the open record alongside the fingerprint, so
`ssh_session_open` rows in the backend audit store name a person. A
`deny` also produces a row, `ssh_session_denied`, with the reason
(`user_inactive`, `no_access`, `unknown_key`, `key_expired`,
`approval_pending`, `cloud_unreachable`). A denied row with reason `user_inactive` is the
signal an operator alert should key on; the alerting surface itself
is a follow-up.

### 4. Rotating the key the user holds

A private key never leaves the device it was generated on, so the
platform cannot push a new one. Rotation means the device generates
a fresh keypair, registers the new public half, and the old one is
retired. This section makes that automatic and makes the live check
refuse keys past their age.

**Which keys need it.**

| Key type | Rotation |
| --- | --- |
| Certificate path (CLI, agents) | None. The keypair is generated per session and discarded (`internal/mcp/sshcert.go`) |
| FIDO2 hardware key (`sk-ssh-ed25519`) | Only on loss of the token, which is a revocation, not a rotation |
| Raw key registered with `containarium ssh setup` | This section |
| Managed long-lived fallback key used by the connect tool when certificates are unavailable | Same as a raw key; it goes through the same workflow |

**Workflow.**

1. **One key per device.** `containarium ssh setup --name` already
   registers a key under a per-device name. A key is never shared
   across devices, or rotating one locks out the others.
2. **Age is policy, enforced by the live check.** The cloud stores
   `created_at` and an optional `expires_at` on each key. The
   authorization call in §1 denies a key older than the tenant's
   maximum age (default 90 days) with reason `key_expired`, and the
   banner tells the user what to run.
3. **`containarium ssh rotate` does it in one command.** It generates
   a new keypair locally, signs a cloud-issued challenge with it so
   the cloud knows the caller holds the private half, registers the
   public key under the same device name, and rewrites
   `~/.containarium/ssh_config`. Registration rides the user's live
   JWT, which carries whatever second factor their login has.
4. **Nudge, then automate.** `containarium login` warns when a key is
   within seven days of expiry. A tenant policy can let the CLI
   rotate silently on the next login instead.
5. **Overlap window.** Both keys are valid for a grace period
   (default 7 days) after rotation, then the old one is retired
   without further action. This avoids lockouts from an open
   terminal or a stale config on another shell.
6. **Loss or compromise.** The user or an operator revokes the key in
   the cloud. The live check denies it on the next connection. This
   is the same path as offboarding.

**Rules.**

- Never generate a key on the server for the user to download. The
  private half would cross the wire and land in a log or a browser
  cache.
- Never accept a public key at registration without proof of
  possession. Otherwise a found public key can be registered and
  parked until it is approved.
- The sentinel's upstream key is operator infrastructure with its
  own runbook and does not use this mechanism.

### 5. Changes by component

| Component | Change |
| --- | --- |
| Cloud control plane (separate repo) | `POST /v1/ssh/authorize`; device-approval records and UI; deactivation fan-out to backends; `created_at` / `expires_at` on key records; challenge endpoint for proof of possession |
| `internal/sentinel/sshsession` or a sibling package | Authorization plugin: call cloud, cache, fail-closed timer, banner polling |
| `internal/sentinel/manager.go` | Plugin chain order and config (cloud endpoint, grace window, cache TTL) |
| `proto/containarium/v1` | `ssh_session_denied` audit row shape; a `TerminateUserSessions` RPC for the fan-out, landed as a `containarium` subcommand first per CLAUDE.md |
| `internal/server` | Handler for the fan-out, reusing `pkg/core/container/collaborator.go` session-kill logic |
| `internal/cmd/ssh.go` | `containarium ssh rotate`; expiry warning on `containarium login` |
| `docs/SENTINEL-SSH-SESSION-AUDIT.md` | New row type and the `user_id` field |
| `docs/ISO27001-COMPLIANCE.md` | A.6.5 moves from N/A to implemented, with this mechanism as the evidence |

### 6. Rollout

1. **Observe.** Ship the plugin in audit-only mode: call the cloud,
   log what it would have decided, always defer to the static file.
   Compare against actual accepts for one release.
2. **Enforce.** Flip to enforcing per sentinel. Static files remain
   as routing.
3. **Rotation.** Ship `containarium ssh rotate` and the login nudge
   before turning on the age policy, so no key expires without a
   path to replace it.
4. **Approval.** Expose the tenant policy flag once enforcement has
   run clean.
5. **Later.** The CA migration can then disable raw keys for tenants
   that opt in, at which point step 1 only ever sees certificates.

## Open questions

1. **Direct reachability of boxes.** The guarantee holds only if
   every SSH path goes through the sentinel. For deployments where
   a box's SSH port is reachable on a LAN or overlay network, either
   that path is closed or the host runs the same check as an
   `AuthorizedKeysCommand`. Which deployments have such a path?
2. **Grace window default.** 5 minutes is a guess. Too short and a
   cloud blip locks every operator out of every box; too long and a
   departed user has that much runway. The cloud's own availability
   target should set it.
3. **Client address in the approval key.** NAT and mobile networks
   change addresses within a session's TTL. Dropping the address
   from the key weakens it to `(user, fingerprint)`, which is still
   a device check in practice. Decide which.
4. **Where the fingerprint-to-user record lives for self-host.** The
   OSS daemon has no user directory; the cloud does. A self-host
   deployment without the cloud needs an equivalent lookup, most
   simply the key registry that `containarium ssh setup` already
   writes, served by the daemon.

## Decision log

- **Live check first, approval second.** The revocation guarantee
  comes from consulting the cloud on every connection. The approval
  step defends a different threat (copied keys) and costs user
  friction, so it is a policy flag, not the default.
- **Per-device-session approval, not per-connection.** Per-connection
  approval breaks every non-interactive SSH use. The TTL window is
  the trade-off.
- **Fail closed.** Availability of SSH during a cloud outage is
  bounded by the grace window. Choosing fail-open would reintroduce
  the exact gap this design closes.
- **Static files stay.** Rewriting routing is out of scope and the
  yaml plugin already does it well. Only the accept decision moves.
