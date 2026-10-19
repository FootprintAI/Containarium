# Sentinel SSH live authorization

The tenant SSH listener runs this chain:

```
ssh-authz-plugin → ssh-session-plugin → yaml → failtoban
```

`ssh-authz-plugin` checks raw public keys against the backend routed by
`KeyStore.BackendForLogin`. Certificates, malformed credentials and unknown
logins defer to the existing routing plugin. What happens to a decision
depends on the mode. There is no interactive approval flow yet, so
`DENY APPROVAL_PENDING` is handled like any other denial.

## Modes

| Mode | Flag | `ALLOW` | `DENY` (any reason) |
| --- | --- | --- | --- |
| Audit-only (default) | none | defers to yaml | logged and recorded on the `open` row, then defers to yaml; the static `authorized_keys` still decides |
| Enforce | `--ssh-authz-enforce` | defers to yaml | the key is refused (`Permission denied (publickey)` for OpenSSH); yaml is never consulted for that key, and a `denied` record is written |

In enforce mode the denial is returned as an error from the plugin's
`PublicKeyCallback`. sshpiperd keeps the connection on this plugin, so the
next key the client offers is checked too. Each refusal appends a `denied`
JSONL record (`enforced=true`, `user_id` when the daemon knows it,
`deny_reason`, key fingerprint) to `--records-file`. The shipper delivers
it as an `ssh_session_denied` audit row. The backend keeps one row per
session and phase, so a connection that is refused several times (a client
retrying the key, or offering several denied keys) yields one
`ssh_session_denied` row: the first.
Records of allowed sessions carry `enforced=true` as well.

**Revocation latency.** A cached `ALLOW` is reused without asking the
daemon until its `cache_ttl` expires (30 seconds from the self-host
decider). A key revoked within that window still logs in until the entry
expires. A login that loses its last key drops out of the sentinel's routing
table on the next key sync. The plugin then treats it as an unknown login
and defers: yaml refuses the key, and no `denied` record is written.

**Fail closed.** Enforcement covers `UPSTREAM_UNAVAILABLE`. If the routed
backend's daemon is unreachable or returns 5xx, a key with a cached `ALLOW`
still logs in while that entry is fresh (younger than its `cache_ttl`, which
is served without asking the daemon) or younger than `--ssh-authz-grace`.
After both have passed, and for a key with no cached `ALLOW`, the login is
refused until the daemon answers again. With the self-host decider
(`cache_ttl` 30 seconds) and the default 5 minute grace, the grace window is
the bound. A `cache_ttl` longer than the grace is capped at the grace, so no
daemon can extend it.
A failure of the local bridge (the sentinel manager's socket) gets no grace.
The login cannot be resolved to a backend, the cache is keyed by backend, and
so every raw-key login is refused until the manager is back. A daemon
outage that outlasts both therefore locks every raw-key login routed to that
backend. Certificate
logins are not checked by this plugin and are unaffected.

**Scope.** Enforcement holds only for SSH that goes through the sentinel.
A box reachable directly on a LAN or overlay network bypasses it; the LXC
jump host has its own check via `AuthorizedKeysCommand` (#2527).

**Known gap: several credentials on one connection.** sshpiperd v1.6.1
moves its plugin chain only forward within a connection. Once this plugin
defers one offer, every later offer on that connection goes straight to
yaml. A client that first offers a credential this plugin defers can then
log in with a denied key that is still in the static `authorized_keys`.
That first credential can be any certificate, even one from an untrusted CA:
`TestIntegrationEnforceMultiOfferGap` reproduces this against a real
sshpiperd. By the same chain rule, a key the daemon allows should open the
gap too; no test covers that case. Until it is closed, a key is fully revoked
only once it is also removed from the static file. The daemon's
`RemoveSSHKey` RPC does both: it revokes the key in the registry, removes it
from `authorized_keys`, and notifies the sentinel to resync. Denials with no
static-file change behind them, such as an inactive user or lost access,
rely on enforcement alone. Enforcement prevents a denied key that is
offered alone from logging in, which is how a standard client uses a single
configured identity. It does not stop a client that has been crafted to get
around it.

The manager and sshpiperd plugins are separate processes. The manager serves
the current keystore through `/run/containarium/ssh-authz.sock` (mode `0600`,
directory created with `0700`). The plugin resolves the login there; on a
cache miss, the manager rechecks that route and forwards the generated
`AuthorizeSSHRequest` to `POST /v1/ssh/authorize` on that backend. It uses the
same HMAC/ed25519 `SignRequest` as keysync. Signing secrets stay in the manager
process. No bridge handler is mounted on a TCP listener.

The sentinel command accepts `--ssh-authz-socket` (empty disables the bridge).
The plugin accepts the same socket path and:

| Flag | Default | Meaning |
| --- | --- | --- |
| `--ssh-authz-grace` | `5m` | Maximum age of a positive reused during an outage, and the cap on its fresh `cache_ttl`; `0` disables reuse |
| `--ssh-authz-timeout` | `3s` | Total deadline for login resolution and authorization |
| `--ssh-authz-enforce` | `false` | Refuse denied keys (see Modes) |
| `--records-file` | `/var/log/containarium/ssh-sessions.jsonl` | Where enforced denials are appended; same file as `ssh-session-plugin`. Opened only with `--ssh-authz-enforce`; empty disables denied records |

Both plugins append whole JSON lines to the records file with `O_APPEND`.
The plugins reopen it on SIGHUP. The module's logrotate stanza signals
`ssh-session-plugin` and only an `ssh-authz-plugin` running with
`--ssh-authz-enforce`, the one that holds the file. An audit-only or
pre-enforce plugin is never signalled, so a binary older than the startup
script is not stopped by rotation. With the Terraform module, set `ssh_authz_enforce = true`. It
adds `--ssh-authz-enforce` and `--records-file` to the tenant listener's
unit. The anonymous-box listener is not affected.

The plugin's private socket request carries its remaining deadline, so the
manager's backend call is also bounded and respects a timeout override.

## Cache and audit behavior

Positive entries are keyed by `(backend, login, SHA256 fingerprint)`. Their
fresh lifetime is the response's `cache_ttl`, capped at `--ssh-authz-grace`;
an absent or zero TTL permits no fresh reuse. Expired positives remain available until the outage grace
expires. Transport failures, HTTP 5xx, and a daemon's typed
`DENY UPSTREAM_UNAVAILABLE` may reuse them. HTTP 4xx, malformed responses,
and authoritative denials invalidate old positives. Grace reads never
refresh the success timestamp. The cache is concurrency-safe, prunes expired
entries, and evicts the oldest positive at its 10,000-entry limit.

The session plugin emits `user_id`, `authz_decision` and `deny_reason` (the
`SSHAuthzDecision` / `SSHDenyReason` proto enums) in its JSONL; `enforced` is
true in enforce mode and omitted when false. The shipper's proto conversion
and backend audit ingestion preserve these fields in `ssh_session_open`
and `ssh_session_close` rows. Skipped checks have no authorization decision;
bridge failures have `DENY UPSTREAM_UNAVAILABLE`. A grace acceptance is
recorded as `ALLOW` with the last successful response's `user_id`.

sshpiperd v1.6.1 advances its plugin chain only forward within a connection.
As with the existing session observer, a later key offer can bypass observers
after the first offer has advanced to yaml. Use one offered identity when
verifying the audit attribution. Fixing multiple-offer observation requires
an upstream chain change; in enforce mode this is the known gap above.

The protobuf messages, service declaration and audit fields needed by this
plugin are included here using #2516's proposed contract. The daemon's
signature-verified gateway mount, decider, cloud mirror and remaining contract
work are separate dependencies (#2516 / #2517). Until the endpoint is deployed,
the plugin records `UPSTREAM_UNAVAILABLE`. In audit-only mode SSH continues
through yaml. In enforce mode raw-key logins routed to that backend are
refused as described under Fail closed (at once for a key with no cached
`ALLOW`), so deploy the endpoint before turning enforcement on.

## Verification

Unit tests cover certificates, unknown logins, every denial reason, response
TTL, backend/login/key isolation, eviction, stale positives, grace boundaries,
deadline expiry, signatures, redirect rejection and metadata round trips.

The integration test uses a real sshpiperd, the production CLI plugins, the
real yaml plugin, a signed stub daemon and a local SSH upstream. It checks that
allow, deny, outage inside grace and outage after grace all reach a shell, and
that their session JSONL has the expected attribution. In enforce mode it
checks that the denied key is refused (including the stock OpenSSH
`Permission denied (publickey)` message) and recorded as `denied` with
`enforced=true`, that the allowed key still logs in, that an outage inside
grace logs in and one after grace is refused, and it pins the
multiple-credential gap:

```sh
go build -o /tmp/containariumd ./cmd/containariumd
SSH_AUTHZ_SSHPIPERD=/path/to/sshpiperd \
SSH_AUTHZ_YAML=/path/to/plugins/yaml \
SSH_AUTHZ_CONTAINARIUM=/tmp/containariumd \
  go test -tags integration ./internal/sentinel/sshauthz -run Integration -v
```

`sshpiperd` must be built from the v1.6.1 tag's nested `cmd/sshpiperd`
module and the yaml plugin from `plugin/yaml` with `-tags full`.

For deployed verification, first deploy the daemon's signed authorization
endpoint, then deploy the sentinel binary and the updated tenant sshpiper
unit. The anonymous-box listener uses its own authorization flow and keeps its
existing plugin chain. Ensure the sentinel manager and sshpiperd run as the
same user (root in the supplied units) so the private socket is accessible.

1. Connect with one registered raw key. Check the backend audit row for
   `user_id`, `authz_decision=ALLOW`, and `enforced=false`.
2. Connect with a key absent from the registry but still present in the
   routed login's `authorized_keys`. Login must succeed and the audit row
   must carry `DENY UNKNOWN_KEY` and `enforced=false`.
3. With a previously allowed key, wait for its response TTL to expire, make
   the daemon unavailable and reconnect within five minutes of that allow.
   Check `ALLOW` with the cached person. Reconnect after that age exceeds five
   minutes: SSH still succeeds, with `DENY UPSTREAM_UNAVAILABLE` in the row.

In enforce mode, on one backend behind the sentinel:

4. Register two keys on the login and connect with the first: the
   `ssh_session_open` row carries `user_id` and `enforced=true`.
5. Remove the first key (`RemoveSSHKey`). The second key keeps the login
   routable. Wait out the cache TTL (30 seconds), then connect offering only
   the removed key. The login is refused, and an `ssh_session_denied` row
   carries `UNKNOWN_KEY` and `enforced=true`.
6. Stop the backend daemon for longer than the grace window: a new login
   is refused and the sentinel log shows `reason=UPSTREAM_UNAVAILABLE
   enforced=true`. Restart the daemon: login resumes.

The live checks above require the daemon dependency and a configured
`audit:ingest` shipper token; passing the stub integration test does not prove
deployment of those components.
