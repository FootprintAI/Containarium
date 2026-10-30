# SSH upstream retry characterization (#1138)

Date: 2026-10-15. Initial base: `7f979bae7237a0e663df87dc7b3871045f166644` (the merge of #2556). The worktree was subsequently fast-forwarded to `78186195b9aa9618d950922be506657f2aa9742c` during fork synchronization. The original tests characterize unchanged behavior. The opt-in transport-hook increment below adds an experimental command; deployed listener templates still use their existing routing invocation.

## Opt-in transport-hook increment

The `sentinel ssh-upstream-plugin` command wraps an explicitly chosen routing child using its existing generated plugin contract. It attaches a one-use capability to each selected TCP endpoint and intercepts the actual connection-creation callback. It delegates authentication and preserves credentials, metadata, chain transitions and environment fields. Unsupported callbacks, child-owned transport callbacks and remote-signing routes fail closed; the adapter does not forward the separate remote-signing service.

The initial real-binary test failed on the baseline daemon (the command did not exist). After implementation, a single-key outage causes **one** actual backend dial rather than seven. The real anon-door child also passes through the hook and retains its Ensure endpoint and proxy key. A baseline-versus-adapter host-key test then found an actual incompatibility: ConnOverGrpc's synthetic RemoteAddr is a URI, breaking knownhosts' host:port parser. The existing typed VerifyHostKey callback now restores the attempt-bound endpoint and actual backend address; it preserves a child verifier's precedence or runs the existing knownhosts checker on the child's bytes. Correct pins pass, wrong and revoked keys fail.

Coverage in this increment:

| Test | Behavior proved |
|---|---|
| `TestIntegrationSSHUpstreamRoutingTransportHook` | One actual outage dial; restored-backend login; unauthorized client cannot dial backend |
| `TestIntegrationSSHUpstreamAnonymousTransportHook` | Actual anon-door routing child uses the hook for outage and recovery |
| `TestIntegrationSSHUpstreamPinnedHostKey` | Original YAML and adapter both accept the correct pin and reject a changed host key |
| `TestIntegrationSSHUpstreamCertificateAuthorization` | Real YAML accepts a trusted user certificate and rejects a wrong principal before dialing |
| `TestIntegrationSSHUpstreamPasswordRetry` | A wrong password followed by a corrected password succeeds on the same downstream socket, with two actual backend dials. The initial adapter failed this test; releasing setup state on the typed upstream-auth-failure notice makes it pass. |
| `TestIntegrationSSHUpstreamProxyCredentialFailure` | A reachable backend rejecting the configured proxy key still produces seven dials with both original YAML and the unguarded adapter. This failure class needs the follow-up gate; an accidentally retained setup must not substitute for admission policy. |
| `TestIntegration_PublicKeyApprovalThroughTransportAdapter` | Existing OpenSSH signature/partial-success/keyboard-interactive proof remains intact; no-private-key and no-publickey cases still reject |
| Seven `TestAdapter*` unit tests | Attempt identity, one-use replay rejection, metadata/credential preservation, revoked keys, child verifier forwarding, unsupported-contract rejection and session-deadline promotion |
| `TestSSHUpstreamPluginStopsWhenRoutingChildExits` | A real child serves its generated bootstrap contract then exits; the adapter exits and reaps it so service supervision can recover. Demonstrated red before adding the exit watcher, then green in 0.256s. |
| `TestIntegrationSSHUpstreamHookRetainsFailurePolicy` | Existing #933 accounting still counts three outage connections and bans that source; this increment does not pretend to fix attribution |

The actual TCP dial is bounded to 2 seconds and pre-session sockets to 30 seconds. An attempt-correlated PipeStart clears the setup deadline so established sessions retain their original lifetime. Pending capabilities expire and are count-bounded. A typed upstream-auth-failure notice releases that attempt so a legitimate corrected password or later key can select another one. This is **not aggregate exponential backoff**: different clients can each dial, and upstream credential rejection can retry on the same connection. The measured seven-to-one reduction applies to the TCP-unavailable fixture. No shared backend gate or backend-jail prevention is claimed. The proposed follow-up requires both-listener aggregate budgeting and typed failure accounting; its recovery behavior awaits the strict-jail-budget decision described in the architecture doc.

CI's existing SSH enforcement lane now installs strace explicitly, runs the original tests plus these scenarios with the race detector, and uploads connect traces and logs without fixture key files. The [first published transport-spike artifacts at commit 06a0dd69](https://github.com/FootprintAI/Containarium/actions/runs/38710280439/artifacts/11959814485) cover the earlier transport/pin/certificate/approval scenarios; the added password/proxy-credential cases run on subsequent heads of [PR #2578](https://github.com/FootprintAI/Containarium/pull/2578). The full normal test/lint/typecheck workflows remain enabled. Local output does not substitute for a passing PR run.

To reproduce this increment, set the binary variables from the reproduction section below, set `ANONDOOR_SSHPIPERD=$SSH_BAN_SSHPIPERD`, and run:

```sh
go test ./internal/sentinel/sshupstream -count=1 -v
go test -tags integration ./internal/sentinel/sshban -count=1 -timeout 90s -v
go test -tags integration ./internal/sentinel/anondoor -count=1 -timeout 90s -v \
  -run '^TestIntegration_PublicKeyApprovalThroughTransportAdapter$'
```

## Latest-main recheck

On `78186195`, rebuilt containariumd and reran the complete `internal/sentinel/sshban` package with integration tests. It passed in **15.771 seconds**. All eight characterization scenarios retained their original results: single-key Go/OpenSSH and bundled-failtoban comparison each dialed seven times; twelve clients dialed 84 times; three keys on one connection dialed nine times; healthy handshakes did not spend failure budget; outage-induced source bans persisted until unban after the backend returned. Existing real SSH enforcement/parity tests also passed. The separate two-minute idle observation below was performed on the original `7f979bae` base and was not repeated on latest main.

Latest-main daemon SHA256: `69f6a93e3caf34375e5232a04e6a34e6970898c9f57b5bfdbccbc20096df52f4`. Latest-main test output (local-only path: `/tmp/containarium-1138-latest-evidence/latest-main-package.log`). Initial-run identities and evidence below remain historical records of the first characterization run. Unmerged authorization/rotation PRs were inspected, not merged into this tested checkout.

## Findings

An unavailable upstream produces multiple backend TCP attempts within one downstream SSH connection. Both Go's SSH client and OpenSSH reproduce this with a single authorized identity. This disproves the issue comment's blanket claim that one incoming connection results in only one upstream dial.

The observed exchange is authentication-driven: OpenSSH logs six `partial success` responses, reoffers the same key seven times, and strace records seven backend `connect(2)` calls. After that client disconnects, a separate two-minute observation found no further dials. This fixture demonstrates rapid retry amplification during an SSH handshake, not an indefinitely running background reconnect loop.

Swapping the first-party ban plugin for the pinned bundled failtoban plugin produces the same seven dials. The amplification therefore exists with both policies under SSHPiper v1.6.1; replacing the ban plugin in #2556 did not introduce it. This comparison does not recreate a historical VM running the older v1.5.3 pin mentioned in the issue.

Source corroboration: the pinned daemon's [routing callback creates the actual upstream connection](https://github.com/tg123/sshpiper/blob/v1.6.1/cmd/sshpiperd/internal/plugin/grpc.go). Its [SSH fork maps routing/authentication errors through updateAuthMethods and PartialSuccessError](https://github.com/tg123/sshpiper.crypto/blob/v0.54.0-sshpiper-20260726/ssh/sshpiper.go). The exact observed counts depend on the pinned versions and client authentication exchange; seven is not asserted as a universal connection limit.

## Measurements

The eight scenarios passed in each of five consecutive runs (40 subtest passes), taking 36.456 seconds in total. The extended idle observation passed in 120.327 seconds. Passing here means the current behavior was characterized; it does not mean #1138 is fixed.

The complete related package, including the existing real SSHPiper enforcement/parity tests, also passed with `go test -tags integration ./internal/sentinel/sshban -count=1 -timeout 90s` in 16.068 seconds. A final process check found no active fixture sshpiperd, containariumd or tracer processes. Formatting and whitespace checks passed.

| Scenario | Downstream activity | Measured backend activity |
|---|---|---|
| One Go SSH client | One TCP connection, one authorized key | 7 connect calls |
| OpenSSH | ConnectionAttempts=1, IdentitiesOnly=yes, one key, no agent | 7 connect calls; 7 key offers; 6 partial-success responses |
| Bundled failtoban comparison | One TCP connection, one authorized key | 7 connect calls |
| Sequential reconnects | 12 client connections | 84 connect calls |
| Concurrent independent sources | 12 connections from 12 loopback source IPs | 84 connect calls, completed in about 0.48–0.59 seconds under tracing |
| Multiple candidate keys | One TCP connection, 3 authorized identities | 9 connect calls |
| Healthy backend burst | 12 successful handshakes | 12 connect calls; 12 accepted connections; zero source-policy failures |
| Backend outage and recovery | Test threshold 3; 3 failed client connections | 21 connect calls before the source was banned; the restored backend remained inaccessible from that source, worked from another source, and became accessible after targeted unban |

Separately, after the single-client failure, the backend stayed unavailable for two minutes with **zero additional connect calls**. The normal fast version uses a 500ms observation interval.

Most scenarios retain the production default of 100 failures/5 minutes. The outage/ban scenario deliberately lowers only the test policy threshold to 3 while preserving the same callbacks and fixed-window behavior. Its control-state polling waits for asynchronous pipe-create notices rather than assuming the final client error means every callback has completed.

Connection calls are counted from strace across the full sshpiperd/plugin process family and filtered by the exact backend IPv4 address and ephemeral port. For the healthy fixture, the real backend independently counts accepted connections and checks the configured upstream key. Rates measured under tracing are diagnostic observations, not production throughput benchmarks.

## Reproduction

Prerequisites: Linux with localhost binding and ptrace permitted, Go 1.26.9, OpenSSH client, strace, the SSHPiper v1.6.1 daemon/YAML/failtoban release binaries, and a daemon built from this checkout. Missing prerequisites fail the test instead of skipping it.

```sh
go build -o /tmp/containarium-1138-tools/containariumd ./cmd/containariumd

export SSH_BAN_SSHPIPERD=/tmp/containarium-933-tools/sshpiperd
export SSH_BAN_YAML=/tmp/containarium-933-tools/plugins/yaml
export SSH_BAN_UPSTREAM_GUARD=/tmp/containarium-933-tools/plugins/failtoban
export SSH_BAN_DAEMON=/tmp/containarium-1138-tools/containariumd
export SSH_UPSTREAM_STRACE=/tmp/containarium-1138-tools/strace-root/usr/bin/strace
export SSH_UPSTREAM_EVIDENCE_DIR=/tmp/containarium-1138-recheck

go test -tags integration ./internal/sentinel/sshban \
  -run '^TestIntegrationSSHPiperUpstreamRetryCharacterization$' \
  -count=5 -timeout 90s -v

SSH_UPSTREAM_IDLE_OBSERVE=2m go test -tags integration ./internal/sentinel/sshban \
  -run '^TestIntegrationSSHPiperUpstreamRetryCharacterization$/^one_client_then_idle$' \
  -count=1 -timeout 150s -v
```

The absolute paths above describe this local run; point them at the same pinned binaries on another runner. SSH_UPSTREAM_STRACE may be omitted when strace is on PATH. The CI lanes install strace explicitly.

Test source: [upstream_retry_integration_test.go](../../internal/sentinel/sshban/upstream_retry_integration_test.go). The fixture uses ephemeral ports, fresh synthetic keys, bounded client/server deadlines, readiness polling, and process-group teardown. Evidence copies contain only traces and logs; private-key files remain in automatically cleaned temporary fixture directories.

Local evidence:

- Eight scenarios repeated five times (local-only path: `/tmp/containarium-1138-evidence/eight-cases-five-runs.log`)
- Two-minute idle observation (local-only path: `/tmp/containarium-1138-evidence/two-minute-idle.log`)
- OpenSSH verbose exchange (local-only path: `/tmp/containarium-1138-evidence/TestIntegrationSSHPiperUpstreamRetryCharacterization-openssh_one_key_one_connection-2682588497/openssh.log`)
- Matching process-family syscall trace (local-only path: `/tmp/containarium-1138-evidence/TestIntegrationSSHPiperUpstreamRetryCharacterization-openssh_one_key_one_connection-2682588497/connect.trace`)

Binary identities:

| Binary | Version / SHA256 |
|---|---|
| sshpiperd | v1.6.1, ac2658090; d2360e2071719d612dabce866d4a6b55f3d3cad7f5e87ac910f2c15fc52b1565 |
| YAML plugin | ea5fc49041bbe34126f35bbf3f7c71fe005863a3c6a151ec051df914c853cfb9 |
| Bundled failtoban | 62f315f568cefdc9a33f559431034ce9ab47575271fe8e9c85237a8c388560c4 |
| Local containariumd | b74593f9bd703c006d00f7b375e360934d99333e026cb84c4ba22601ca7b05d9 |
| OpenSSH client | 9.6p1 Ubuntu-3ubuntu13.19 |
| strace | 6.8 |

## Limits and consequence for the fix

Docker/Podman, OpenSSH server and fail2ban are absent locally. This run uses the real pinned proxy binaries and a real Go SSH server for restoration/healthy cases. It **does not prove that a backend sshd jail bans the sentinel**, or that a proposed fix prevents such a ban. No backend jail was simulated and presented as equivalent. The tests cover the main listener locally, not a deployed fleet or the two listeners' combined load. No CI run, merge or deployment is claimed.

The result supports controlling actual per-backend dial attempts, including repeated authentication attempts on an already accepted client connection. Limiting only new downstream TCP connections misses the measured 7-to-1 amplification. Separately, any outage gate must account for the existing source-IP policy's pipe-create failure counting, so that its own cooldown rejections do not silently create new client bans. A real OpenSSH/fail2ban fixture with recorded effective jail settings remains necessary to prove #1138's backend-ban claim.
