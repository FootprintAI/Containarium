# Sentinel SSH authorization audit

The tenant SSH listener runs this chain:

```
ssh-authz-plugin → ssh-session-plugin → yaml → failtoban
```

`ssh-authz-plugin` checks raw public keys against the backend routed by
`KeyStore.BackendForLogin`. Certificates, malformed credentials and unknown
logins defer to the existing routing plugin. Every decision also defers:
this release is **audit-only**, with no enforcement flag or interactive
approval flow. `DENY APPROVAL_PENDING` is logged like any other denial.

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
| `--ssh-authz-grace` | `5m` | Maximum age of a positive reused during an outage; `0` disables stale reuse |
| `--ssh-authz-timeout` | `3s` | Total deadline for login resolution and authorization |

The plugin's private socket request carries its remaining deadline, so the
manager's backend call is also bounded and respects a timeout override.

## Cache and audit behavior

Positive entries are keyed by `(backend, login, SHA256 fingerprint)`. Their
fresh lifetime is the response's `cache_ttl`; an absent or zero TTL permits
no fresh reuse. Expired positives remain available until the outage grace
expires. Transport failures, HTTP 5xx, and a daemon's typed
`DENY UPSTREAM_UNAVAILABLE` may reuse them. HTTP 4xx, malformed responses,
and authoritative denials invalidate old positives. Grace reads never
refresh the success timestamp. The cache is concurrency-safe, prunes expired
entries, and evicts the oldest positive at its 10,000-entry limit.

The session plugin emits `user_id`, `authz_decision` and `deny_reason` (the
`SSHAuthzDecision` / `SSHDenyReason` proto enums) in its JSONL; `enforced` is
false in this release and omitted when false. The shipper's proto conversion
and backend audit ingestion preserve these fields in `ssh_session_open`
and `ssh_session_close` rows. Skipped checks have no authorization decision;
bridge failures have `DENY UPSTREAM_UNAVAILABLE`. A grace acceptance is
recorded as `ALLOW` with the last successful response's `user_id`.

sshpiperd v1.6.1 advances its plugin chain only forward within a connection.
As with the existing session observer, a later key offer can bypass observers
after the first offer has advanced to yaml. Use one offered identity when
verifying the audit attribution. Fixing multiple-offer observation requires
an upstream chain change; this plugin never claims to enforce authorization.

The protobuf messages, service declaration and audit fields needed by this
plugin are included here using #2516's proposed contract. The daemon's
signature-verified gateway mount, decider, cloud mirror and remaining contract
work are separate dependencies (#2516 / #2517). Until the endpoint is deployed,
the plugin records `UPSTREAM_UNAVAILABLE` and SSH continues through yaml.

## Verification

Unit tests cover certificates, unknown logins, every denial reason, response
TTL, backend/login/key isolation, eviction, stale positives, grace boundaries,
deadline expiry, signatures, redirect rejection and metadata round trips.

The integration test uses a real sshpiperd, the production CLI plugins, the
real yaml plugin, a signed stub daemon and a local SSH upstream. It checks that
allow, deny, outage inside grace and outage after grace all reach a shell, and
that their session JSONL has the expected attribution:

```sh
go build -o /tmp/containariumd ./cmd/containariumd
SSH_AUTHZ_SSHPIPERD=/path/to/sshpiperd \
SSH_AUTHZ_YAML=/path/to/plugins/yaml \
SSH_AUTHZ_CONTAINARIUM=/tmp/containariumd \
  go test -tags integration ./internal/sentinel/sshauthz -run Integration -v
```

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

The live checks above require the daemon dependency and a configured
`audit:ingest` shipper token; passing the stub integration test does not prove
deployment of those components.
