# Sentinel SSH live authorization

The tenant SSH listener runs this chain:

```
ssh-authz-plugin → ssh-session-plugin → yaml → failtoban
```

`ssh-authz-plugin` checks raw public keys against the backend routed by
`KeyStore.BackendForLogin`. Certificates and malformed credentials are not
checked against the daemon; neither is an unknown login (one no synced
backend lists), which audit-only mode defers and enforce mode refuses. The
plugin offers publickey only and refuses password, keyboard-interactive and
none itself, in both modes, so no other method can move sshpiperd's chain
cursor past it. The one exception is device approval in enforce mode (see
Device approval below). What happens to a decision depends on the mode.

## Modes

| Mode | Flag | `ALLOW`, and offers not checked | `DENY` (any reason) |
| --- | --- | --- | --- |
| Audit-only (default) | none | defers to yaml | logged and recorded on the `open` row, then defers to yaml; the static `authorized_keys` still decides |
| Enforce | `--ssh-authz-enforce` | an `ALLOW`, a certificate or a malformed offer is routed by this plugin from `--sshpiper-config`, exactly as yaml would route it, and never deferred; an unknown login is refused as `DENY UPSTREAM_UNAVAILABLE` (see Fail closed) | the key is refused (`Permission denied (publickey)` for OpenSSH); yaml is never consulted for that key, and a `denied` record is written |

In enforce mode the denial is returned as an error from the plugin's
`PublicKeyCallback`. sshpiperd keeps the connection on this plugin, so the
next key the client offers is checked too. Every other offer is routed by
the plugin itself: it runs the yaml plugin's own checker (`libplugin/skel`:
certificate validity and CA match, `authorized_keys` match) over the
`config.yaml` keysync writes, and returns the upstream. An offer that does
not verify is refused, as yaml would refuse it. The plugin refuses every
login if that file holds a field it does not model. The plugin never defers,
so sshpiperd's chain never moves past it (see "Several credentials on one
connection" below).

Because the plugin returns the upstream, sshpiperd copies none of its
metadata onto the connection. In enforce mode the plugin therefore writes
the session's `open` and `close` records itself, including the
`proxy_shutdown` close when the proxy stops. They carry the same fields
`ssh-session-plugin` writes in audit-only mode: credential identity, routed
target, `user_id`, `authz_decision`, `deny_reason` and `enforced`.
`ssh-session-plugin` never sees these connections' credentials and writes
nothing for them, so each session is recorded once. The `target` on both
records is the upstream the plugin routed to when it accepted the offer, not
a fresh read of `config.yaml`, so a file keysync re-renders during the
session cannot put the `open` row on one backend and the `close` row on
another. The one exception is a session whose pending decision was evicted
from the plugin's bounded stash (see
[SENTINEL-SSH-SESSION-AUDIT.md](./SENTINEL-SSH-SESSION-AUDIT.md)): it has no
recorded route, so its `target` comes from a fresh read of the config. Each
refusal appends a `denied` JSONL record (`enforced=true`, `user_id` when the daemon knows it,
`deny_reason`, key fingerprint) to `--records-file`. The shipper delivers
it as an `ssh_session_denied` audit row. The backend keeps one row per
session and phase, so a connection that is refused several times (a client
retrying the key, or offering several denied keys) yields one
`ssh_session_denied` row: the first.
Every record the plugin writes in enforce mode carries `enforced=true`,
including the `open` and `close` records of a session it routed without a
daemon decision (a certificate); `authz_decision` says whether the daemon was
asked. The plugin keeps each routed connection's decision until its pipe
starts (at most 10,000 connections, 10 minutes). If that stash evicted a
session's decision first, the session is still recorded, without credential
or decision, and the sentinel log names the connection.

**Revocation latency.** A cached `ALLOW` is reused without asking the
daemon until its `cache_ttl` expires (30 seconds from the self-host
decider), and never longer than `--ssh-authz-grace`. A key revoked within
that window still logs in until the entry expires. A login that loses its
last key drops out of the sentinel's routing table on the next key sync. The
plugin then treats it as an unknown login and refuses it, with a `denied`
record carrying `UPSTREAM_UNAVAILABLE` (see Fail closed).

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

An unknown login, one no synced backend lists, is treated like a bridge
failure: refused with `DENY UPSTREAM_UNAVAILABLE`, no grace, and a `denied`
record. Without a backend there is no daemon decision, and the static
`config.yaml` on disk must never be the sole judge; that file persists across
a sentinel manager restart while the in-memory keystore starts empty, so for
the window until every backend has synced, every login is unknown. The plugin
asks the manager whether routing is ready (the signal the session shipper
uses: every healthy backend has synced at least once) and logs the refusal as
`routing not ready, keystore not yet synced` or `no synced backend lists the
login`, so the sentinel log tells a restart apart from a revoked login. The
record is the same in both cases.

**Scope.** Enforcement holds only for SSH that goes through the sentinel.
A box reachable directly on a LAN or overlay network bypasses it; the LXC
jump host has its own check via `AuthorizedKeysCommand` (#2527).

**Several credentials on one connection.** sshpiperd v1.6.1 moves its
plugin chain only forward within a connection: once a plugin defers one
offer, every later offer on that connection goes to the next plugin. Before
#2629 was fixed, the enforcing plugin deferred certificates and allowed
keys, so a client could offer one of those first and then log in with a
denied key that was still in the static `authorized_keys`. In enforce mode
the plugin now routes every offer itself and never defers, so each offer on
a connection is checked here. A denied key is refused whatever was offered
before it. Trying another method first does not move the cursor either, and
never did: sshpiperd v1.6.1 only advertises the methods the current plugin
implements, and this plugin offers publickey only. Its refusals of password,
keyboard-interactive and none are defence in depth (pinned by the unit test
`TestPublicKeyIsTheOnlyMethod`), not a fix for a past bypass. Three tests
check the outcomes against a real sshpiperd:
`TestIntegrationEnforceMultiOfferGap` (a certificate from an untrusted CA,
then the denied key), `TestIntegrationEnforceAllowThenDeny` (an allowed
key, of which the client holds only the public half, then the denied key)
and `TestIntegrationEnforcePasswordFirst` (`PreferredAuthentications=
password,publickey`, then the denied key).
Audit-only mode still defers, so there the static file decides as before.

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
| `--records-file` | `/var/log/containarium/ssh-sessions.jsonl` | Where enforced denials and enforce-mode `open`/`close` records are appended; same file as `ssh-session-plugin`. Opened only with `--ssh-authz-enforce`; empty disables these records |
| `--sshpiper-config` | `/etc/sshpiper/config.yaml` | The routing config enforce mode routes from; the same file yaml reads. Unused without `--ssh-authz-enforce` |

Both plugins append whole JSON lines to the records file with `O_APPEND`.
The plugins reopen it on SIGHUP. The module's logrotate stanza signals
`ssh-session-plugin` and only an `ssh-authz-plugin` running with
`--ssh-authz-enforce`, the one that holds the file. An audit-only or
pre-enforce plugin is never signalled, so a binary older than the startup
script is not stopped by rotation. With the Terraform module, set `ssh_authz_enforce = true`. It
adds `--ssh-authz-enforce` and `--records-file` to the tenant listener's
unit and leaves `--sshpiper-config` at its default, the same
`/etc/sshpiper/config.yaml` yaml reads, so the rendered unit never names a
flag an older sentinel binary would reject (with `Restart=always`, that would
take port 22 down for every tenant). Still upgrade the sentinel binary to
#2741 or later before enabling enforcement: an older one enforces without
routing itself and keeps the gap described below. The anonymous-box listener
is not affected.

The plugin's private socket request carries its remaining deadline, so the
manager's backend call is also bounded and respects a timeout override.

## Device approval

When the daemon answers `DENY APPROVAL_PENDING` with an `SSHDeviceApproval`,
enforce mode asks the user to approve the device on the same connection
(design component 3, #2526):

1. The plugin returns a retry of itself, so sshpiperd's chain cursor stays
   here. sshpiperd turns that into publickey partial success, and only once
   the client's signature has been verified.
2. keyboard-interactive is then the only method offered. The client shows
   `Approve this device at <url>, code <code>` and one prompt,
   `press Enter once approved: `.
3. After Enter the plugin polls `Authorize` with `approval_id`, every
   `poll_after` (default 2 s, at least 250 ms). `ALLOW` routes the session
   as any `ALLOW` does. `APPROVAL_DENIED`, any other denial, a transport
   error or an invalid response ends the login. Reaching `expires_at` or the
   60-second cap also ends it. The cap counts from the first `PENDING`. A
   refused login writes a `denied` record (`APPROVAL_PENDING` when the
   deadline passed). Nothing waits past the deadline, and no grace applies.

Fail closed:

- An approval is shown only when it has an id, an `https` URL and a code of
  visible ASCII, and an `expires_at` still in the future. Otherwise the key is
  refused as `APPROVAL_PENDING`. The URL and code reach the user's terminal,
  so no control characters get through.
- The approval is kept in the plugin by connection, not in sshpiperd
  metadata. sshpiperd stores a retry's metadata even for an unsigned key
  query, so metadata alone would let a client that queried someone else's
  public key reach the prompt after signing with a different key. Every new
  publickey offer clears the connection's approval. A keyboard-interactive
  attempt is answered only for the key that signed last, and only once.
- Non-interactive clients (`BatchMode=yes`, scripts, CI) cannot answer the
  prompt and are refused. There is no banner-only fallback: approve the
  device from an interactive client first. The approval is keyed on
  `(user, fingerprint)` by the decision source, so later logins with that
  key are not asked again. The client address is sent for audit only.
- Certificates never enter this path, and neither does audit-only mode: it
  logs `reason=APPROVAL_PENDING` and defers like any other decision.
- Neither the approval id nor the code is logged.

sshpiperd closes any connection whose pipe is not established within
`--login-grace-time`, by default 30 seconds, shorter than the cap. The
supplied tenant units pass `--login-grace-time 90s` (#3074). It is a
listener-wide setting: it applies to every unauthenticated connection on
that listener, not only those waiting on an approval, so a client that
stalls before authenticating also holds its connection for up to 90 seconds.
The anonymous-box listener keeps the default. (The grace-timer
behaviour was read from the sshpiperd v1.5.3 source; v1.6.1 was not
re-read. The flag itself is passed to the v1.6.1 daemon by the
approval spike test.) A custom unit that enables
enforcement with device approval must raise it too.

The managed daemon forwards the request, `approval_id` included, to the
cloud unchanged (#2525). A self-host daemon never answers `APPROVAL_PENDING`.

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

In audit-only mode sshpiperd v1.6.1 advances its plugin chain past the
observers after the first offer, so a later key offer bypasses them. Use one
offered identity when verifying the audit attribution there. In enforce mode
every offer reaches this plugin, and its session records name the
credential that authenticated.

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
`TestDeviceApproval` and `TestDeviceApprovalBoundaries` cover the device
approval path: `ALLOW` on the first or a later poll, `APPROVAL_DENIED`,
`expires_at`, the 60-second cap, poll errors, unusable approvals, another
key offered after `PENDING`, certificates and audit-only mode.

The integration test uses a real sshpiperd, the production CLI plugins, the
real yaml plugin, a signed stub daemon and a local SSH upstream. It checks that
allow, deny, outage inside grace and outage after grace all reach a shell, and
that their session JSONL has the expected attribution. In enforce mode it
checks that the denied key is refused (including the stock OpenSSH
`Permission denied (publickey)` message) and recorded as `denied` with
`enforced=true`, that the allowed key still logs in, that an outage inside
grace logs in and one after grace is refused, that a denied key is refused
after a certificate, an allowed key or a password attempt on the same
connection, and that each session gets exactly one `open` and one `close`
record with the full field set. `TestIntegrationEnforceDeviceApproval` has
the stub daemon answer `APPROVAL_PENDING`, then `PENDING` again on the first
poll and `ALLOW` on the second. A stock OpenSSH client, answering through
`SSH_ASKPASS_REQUIRE=force`, gets partial success, the instruction, one
prompt and a session. A `BatchMode=yes` client is refused. The refusals are
pinned on the same chain: `TestIntegrationEnforceDeviceApprovalDenied`
(`APPROVAL_DENIED` stops polling), `...Expires` (polling ends at
`expires_at`), `...SignedNeverAnswered` (an unanswered prompt never polls and
ends in a `denied` record) and `...FakeAgentCannotBorrow` (an agent that lists
a victim's key but refuses to sign gets no prompt once another key is
denied). The unit tests add the full approval store, `userinfo` in the
approval URL and the cache write on a polled `ALLOW`.
`TestIntegrationEnforceAllowThenDeny`, `TestIntegrationEnforcePasswordFirst`,
`TestIntegrationEnforceDeviceApproval` and the four `TestIntegrationEnforceDeviceApproval*`
tests above drive the stock OpenSSH client and skip without it (the CI lane fails on a skip):

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
7. Restart the sentinel manager and connect before its first key sync
   completes: the login is refused, the `ssh_session_denied` row carries
   `UPSTREAM_UNAVAILABLE`, and the sentinel log shows `unknown login refused
   in enforce mode: routing not ready, keystore not yet synced`. Once the
   sync completes, login resumes.
8. Device approval (needs the cloud approval page): ssh from an interactive
   client with a registered key the tenant policy has not yet approved on
   this device. The client shows `Approve this device at <url>, code <code>`.
   Approve it in the browser within 60 seconds, then press Enter: the session
   opens and the `ssh_session_open` row carries `ALLOW` and `enforced=true`.
   Deny it in the browser instead, or wait past 60 seconds: the login is
   refused and an `ssh_session_denied` row carries `APPROVAL_DENIED` or
   `APPROVAL_PENDING`.

The live checks above require the daemon dependency and a configured
`audit:ingest` shipper token; passing the stub integration test does not prove
deployment of those components.
