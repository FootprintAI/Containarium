# SSH authorization cache (#2518)

This package implements the contract-independent positive cache and backend resolver seam for
FootprintAI/Containarium#2518. The prerequisite FootprintAI/Containarium#2516
was still open when inspected; neither the fork nor upstream main at
`2ec361eaa1f642fae12a18bf13d9d89e835b21a7` contained `ssh_authz.proto`,
the generated authorization messages/enums, or the requested session audit
fields. The design was read from PR #2514 at
`fdec56583b4d1af9bc48fa6d55b7cc821cfc84d3`.

`BackendResolver` is implemented by `KeyStore.BackendForLogin`, matching the sorted-backend first-match precedence of `KeyStore.Apply`. A subprocess adapter and endpoint lookup remain dependent wiring.

`Cache` is the injectable positive-cache seam. `PositiveCache` is bounded and
thread-safe, with an injectable clock. Fresh hits use the supplied server TTL.
Grace hits expire strictly five minutes (by default) after the last successful
authorization, including time spent fresh. Reads never refresh either window.
Entries remain available until both windows expire, unless explicitly
invalidated or evicted in order of oldest successful insertion. A nonpositive
TTL prevents fresh hits; a nonpositive grace prevents outage fallback.

The eventual plugin must only call `Put` for ALLOW, invalidate on a live DENY
(including APPROVAL_PENDING), and consult `Grace` only after transport errors
or HTTP 5xx. It must ALWAYS defer to the following plugin, even for deny and
UPSTREAM_UNAVAILABLE outcomes. This issue adds no enforcement flag.

After #2516 lands, use its generated types for the Authorizer interface, HTTP
adapter and connection/session metadata conversion. Do not introduce substitute
proto definitions or hand-written wire payloads. Complete the three-second
sentinel-signed request, audit-only callbacks, command entry point, plugin-chain
wiring and real-sshpiperd integration tests together against that contract.

The existing anonymous-door integration harness lives in
`internal/sentinel/anondoor/integration_test.go` (integration build tag), and
starts real sshpiperd with an environment-supplied daemon binary and upstream
sshd. Session metadata is read by `sshsession.Plugin.buildRecord`. Note that
plugins run in separate processes: an in-memory KeyStore on the sentinel is
not directly accessible to the plugin. Backend resolution must preserve the
same deterministic route selection as KeyStore.Apply, and supply a daemon HTTP
endpoint rather than assuming that the SSH target port is an HTTP port.

Validate the independent cache with:

```sh
go test -race ./internal/sentinel/sshauthz
go vet ./internal/sentinel/sshauthz
go build ./internal/sentinel/sshauthz
```
