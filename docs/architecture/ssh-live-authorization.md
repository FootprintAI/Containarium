# SSH live authorization — verified device approval decision

**Date:** 2026-10-13

**Issue:** [#2524](https://github.com/FootprintAI/Containarium/issues/2524)

**Result:** verified with sshpiperd/libplugin v1.6.1 and stock OpenSSH.

This document records the verified component 3 decision required by #2524. The broader [SSH live authorization architecture (#2514)](https://github.com/FootprintAI/Containarium/pull/2514) remains proposed; its other components are outside this spike. Component 3 was also updated in [#2530](https://github.com/FootprintAI/Containarium/pull/2530), which was merged into the design branch. When that proposal lands, retain this verified decision and evidence in its component 3.

## Component 3 — device approval, sentinel side

**Use keyboard-interactive on the same connection.** The client sees publickey partial success, an approval instruction and one prompt, then opens an authenticated upstream session after Enter. A banner-only flow requiring a reconnect is not needed for clients that support keyboard-interactive. Noninteractive clients cannot answer this prompt.

The plugin uses these libplugin calls:

1. `NextAuthMethodsCallback` initially returns `[]string{"publickey"}`.
2. `PublicKeyCallback` returns `&libplugin.Upstream{Auth: libplugin.CreateRetryCurrentPluginAuth(meta)}`, with a pending-approval stage in the per-connection metadata.
3. `NextAuthMethodsCallback` reads that stage and returns only `[]string{"keyboard-interactive"}`.
4. `KeyboardInteractiveCallback` invokes `challenge(conn.User(), instruction, "press Enter once approved: ", false)` and, after the answer, returns an upstream authenticated with `libplugin.CreatePrivateKeyAuth(key)`.

The retry API is not itself an `ssh.PartialSuccessError`. sshpiperd stores the metadata and returns `client retry requested`; its SSH fork updates the auth methods and verifies the client's signature before applying wire-level partial success. Receiving a public-key offer alone must not be treated as proof of possession.

## Evidence

`TestIntegration_PublicKeyPartialSuccessKeyboardInteractive` in `internal/sentinel/anondoor/approval_integration_test.go` reuses the real-sshpiperd harness helpers. It launches a throwaway stdio plugin from the test binary, stock OpenSSH, and a loopback SSH upstream that authenticates the proxy's key and serves a real session channel.

| Case | Required result |
| --- | --- |
| Signed publickey, then keyboard-interactive | Partial success, visible instruction, exactly one prompt, `approval-ok` session output and exit status 0 |
| Public key without its private key, agent disabled | No approval prompt and no session |
| Keyboard-interactive without publickey | No approval prompt and no session |

The original spike passed with OpenSSH 9.6p1 on Linux in [CI](https://github.com/FootprintAI/Containarium/actions/runs/38346189715) and OpenSSH 10.3p1 on macOS. Removing the instruction makes the success test fail; restoring it passes. `.github/workflows/ssh-approval-spike.yml` builds the pinned daemon, runs with `-race`, fails on skips, and preserves the transcript.

## Reproduce

Build sshpiperd from the v1.6.1 source tag in its nested `cmd/sshpiperd` module, preserving its specified SSH crypto fork. With `ssh` and `ssh-keygen` on `PATH`, run:

```sh
ANONDOOR_SSHPIPERD=/path/to/sshpiperd go test -race -tags integration -count=1 -v \
  ./internal/sentinel/anondoor -run '^TestIntegration_PublicKeyPartialSuccessKeyboardInteractive$'
```

The harness generates temporary keys and starts the proxy with:

```sh
sshpiperd -l 127.0.0.1 -i <host-key> -p <port> \
  --drop-hostkeys-message --login-grace-time 90s <plugin>
```

No extra daemon keyboard-interactive flag is required. The test client uses `PreferredAuthentications=publickey,keyboard-interactive`, enables keyboard-interactive, and disables its agent. `SSH_ASKPASS_REQUIRE=force` and a generated askpass helper record the single prompt and supply Enter in headless CI; these are test automation settings.

## Production follow-up

This spike does not implement browser approval, cloud calls, polling, or the routing/session-plugin handoff; those remain [#2526](https://github.com/FootprintAI/Containarium/issues/2526). The upstream is a Go SSH fixture, not a complete OpenSSH sshd or production box.

The production callback should re-call `Authorize` with `approval_id`: `ALLOW` completes auth; `APPROVAL_PENDING` continues polling every `poll_after`; a terminal denial, `expires_at`, or the 60-second cap stops polling and denies auth. The daemon's default login grace is 30 seconds, so it must be raised above that cap; 90 seconds leaves handshake/upstream headroom.
