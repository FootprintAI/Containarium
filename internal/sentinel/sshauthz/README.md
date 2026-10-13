# Audit-only SSH authorization (#2518)

The tenant sshpiperd chain is `ssh-authz-plugin` → `ssh-session-plugin` →
`yaml` → `failtoban`. Authorization always defers, including DENY,
APPROVAL_PENDING, protocol failures and upstream outages. This issue adds no
enforcement flag or interactive device-approval flow.

`Authorizer` uses the generated `SSHAuthzService` contract from #2516.
`HTTPAuthorizer` sends a sentinel-signed `POST /v1/ssh/authorize` with a
three-second default timeout. The command uses the same configured credentials
as keysync, but signs a domain-separated method/path/timestamp/body SHA-256
message. The authorization gateway rejects legacy method/path-only signatures
and restores the verified body for protobuf decoding. Other sentinel routes
keep their existing signing format.
Certificates and unknown logins skip authorization. Successful responses are
cached by backend ID, login and key fingerprint for the response TTL (30s if
absent). Live denials invalidate old positives.

The original `Cache`, `PositiveCache` and `BackendResolver` foundations and
tests are preserved. The cache is bounded and concurrent, with an injectable
clock. Grace ends strictly five minutes (by default) after the last successful
authorization, including time spent fresh. Reads never refresh either window.
Grace is only consulted on transport errors or HTTP 5xx. HTTP 4xx, invalid
responses and configuration errors are logged as denied outcomes without grace.

The plugin is a separate process. `KeyStore.Apply` publishes the selected routes
to `/etc/sshpiper/authz-backends.json` atomically; the manager configures this
snapshot path. `FileBackendResolver` reloads it on each lookup, preserving the
same sorted-backend first-match precedence as `KeyStore.BackendForLogin`.
The snapshot contains backend IDs and explicit HTTP URLs, never credentials;
SSH target ports are not used as daemon HTTP ports. Removing the last login
publishes an empty snapshot even when Apply returns its existing no-users error.
A missing/unreadable snapshot
resolves no logins, so the audit-only plugin defers to routing as usual.

The command accepts `--ssh-authz-routes`, `--ssh-authz-grace` (5m),
`--ssh-authz-timeout` (3s) and an informational `--sentinel-id`. Session records
preserve user ID, typed protobuf decision and reason, and `enforced=false` on
open, close and shutdown; the shipper carries those fields into audit ingest.
JSONL represents the protobuf enums by their numeric values; operational logs
include their enum names.

The #2516 daemon stub intentionally returns Unimplemented after signature
verification. The real local/cloud decider belongs to #2517. Running against
the stub therefore logs UPSTREAM_UNAVAILABLE, while SSH still follows routing.
The known sshpiperd chain limitation remains: later offered keys on the same
connection can bypass the early plugins after the first key advances the chain,
as already documented for sshsession.Plugin.

Validation (use umask 0022 for existing permission-sensitive repository tests):

```sh
go test -race ./internal/sentinel/sshauthz ./internal/sentinel/sshsession ./internal/server/sshauthz
```

The integration test follows the existing anonymous-door harness's real
sshpiperd stdio-chain pattern, with a fake HTTP daemon and an in-process SSH
upstream. It verifies a functional SSH command and authorization metadata in
JSONL for allow, deny and expired-TTL transport-error grace:

```sh
SSHAUTHZ_SSHPIPERD=/path/to/sshpiperd \
SSHAUTHZ_CONTAINARIUM=/path/to/containariumd \
go test -race -tags integration ./internal/sentinel/sshauthz -run TestIntegration
```

`SSHAUTHZ_YAML_PLUGIN` optionally supplies the YAML plugin binary; otherwise it
is `plugins/yaml` beside sshpiperd. No root, Docker or model credentials are
needed. Without the binaries this integration test reports a skip.

The tenant sshpiper units load the optional root-only sentinel secrets file.
Startup atomically reconciles that file and restarts sshpiper when credentials
change or are removed; unchanged credentials do not interrupt live sessions.
