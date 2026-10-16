# Design: connect shared SSH admission (#1138)

**Status:** accepted for implementation; ban avoidance takes priority over
seconds-level recovery after verified jail-risk exhaustion (user decision).
**Stack:** existing host-managed Go sentinel/plugins, protobuf/gRPC over a private
Unix socket; no new language, container or public API in the production path.

## Components and flow

The existing sentinel Manager owns one `sshcontrol.Controller` and private socket
for both listeners. Its resolver reads authoritative KeyStore backend records,
not the best-effort audit TargetResolver. The selected routing adapter delegates
all authorization to its existing child, then asks the controller for one
attempt-bound lease before opening the backend. It enforces the lease's actual
socket deadline with a close timer. A timely PipeStart proves authenticated SSH
and removes that deadline before the bounded completion RPC. A control transport
failure retains uncertain risk but preserves that authenticated session; an
explicit stale-route rejection closes it. The source-ban plugin queries a typed disposition before
counting a failure. All components are Go, type-checked with `go build`/`go vet`.

The real anonymous child registers the endpoint and stable box name returned by
its signed Ensure call. That private registration is bound to the existing
anonymous connection; it is not an anonymous/public route-registration API.
Controller identity aliases keep one stable budget when main and anonymous refer
to an authoritative backend. Anonymous-only jail identity follows the physical
endpoint; box names authorize live Ensure routes and never permanently union
DHCP lifetimes. Endpoint risk survives reuse. Idle entries and aliases are
removed only after pending setups, cooldown and jail history have drained and
the identity has been unused for max(window, max delay) plus setup timeout.
Every admission decision, including cooldown denial, refreshes that activity;
active outages must never lose their exponential backoff during cleanup.
Legacy box aliases are dropped on restore while endpoint history is preserved.
Adding an alias does not advance the group's route epoch: simultaneous main/anon
aliases must not make each other's in-flight failures stale. Per-connection route
tokens isolate authorization retries; the core incident epoch isolates recovery.
Ready acknowledgements recheck authoritative endpoint identity. A new Ensure
endpoint for the same anonymous box invalidates its old route at ready validation;
it does not invalidate unrelated sessions using the same physical backend.
Manager backend unhealthy-to-healthy transitions publish a hint, never an
unconditional admission. HTTP health is a hint; SSH-ready completion is the proof.

The pinned [chain implementation](https://github.com/tg123/sshpiper/blob/v1.6.1/cmd/sshpiperd/internal/plugin/chain.go)
invokes observers synchronously in plugin order. Both current units put the
routing child before the ban observer. Preserve that order and verify it with
the real binary. Open/register connection identities before authorization;
reset the disposition at every child authorization call. Record confirmed dial
failure, deliberate gate denial, configured-proxy credential rejection or host
verification failure before the trailing ban callback. Unknown errors and actual
client credential/signature denials keep default source accounting. Never match
error text or exempt every PipeCreateError. Password rejection is a tenant
credential failure: retain jail risk without declaring a healthy backend down.

## Contracts and persistence

`proto/containarium/v1/ssh_upstream.proto` defines generated private clients,
connection/route tokens, weighted admission, absolute lease deadline, setup
outcomes, source-failure disposition, anonymous route registration and recovery
hints and an admission-reason enum. Unix directory 0700/socket 0600 is the local operator trust boundary. A
controller generation binds each connection; restart/stale replies cannot grant
or suppress events on a new connection. Fail closed when control is unavailable;
do not convert that service outage into new client bans.

Controller policy is strict protobuf JSON. Production defaults target the
repository's tested 3/600s jail with one measured matching failure per admitted
setup: reserve at most two units, window 600s, setup timeout 30s, backoff 1s to 30s
with nonnegative jitter. Operators must supply a conservative cost/window for
different filters; no guarantee is made for arbitrary third-party jails. Existing
CIDR exemptions remain unchanged. Tenant-visible authentication and approval
semantics remain delegated to the existing child.

Persist bounded canonical identity aliases and conservative gate checkpoints
atomically in a private directory before acknowledging admission. A checkpoint
records pending risk through its setup deadline plus the entire jail window.
Restore without live leases: do not reopen while an old process could still have
a pending setup. Corrupt, unsafe or incompatible state fails closed. With no
state, hold new admission for one verified jail window to avoid assuming the
backend has no earlier failures. This does not clear an already-existing ban.
An exclusive advisory file lock permits only one checkpoint owner. Closing an
owner denies subsequent ready acknowledgements before releasing that lock.

## Availability revision after maintainer review (2026-10-16)

Implementation retains the user's ban-avoidance choice; production rollout and
the fail-closed/initial-hold tradeoff still require maintainer acceptance. The Go
Manager supervises only the guard on a five-second retry interval. Startup errors
set `sentinel_ssh_upstream_faulted=1` and never exit `Manager.Run`. Existing
HTTP/HTTPS forwarding, health and sync services continue. Corrupt/incompatible
state requires operator repair, not risk deletion. A storage fault can recover by
atomically syncing the same conservative in-memory snapshot under the same live
lock. Closed or replaced ownership cannot be revived by this path.

Both listener units use After/BindsTo/PartOf on the sentinel. Its drop-in starts
the listeners asynchronously after every daemon start; missing optional anonymous
units cannot fail the daemon. Policy-only reconciliation never restarts it, and
both GCE and module installers stage changed policy. A controller RPC outage
refuses new guarded setups but does not interrupt established SSH.

Pure Dial failures, including TCP timeouts, refund risk and keep backoff. Dial's
deadline is at most five seconds and half the remaining setup lease, allowing a
bounded outcome report before lease expiry. Post-dial timeouts stay uncertain and
retain risk. Metadata is additionally limited per normalized source IP across
listeners to min(64, one quarter of global capacity), at least one slot.

The pinned sshpiperd can dial/authenticate upstream during an unsigned public-key
probe, before asking the downstream client to sign. Two aborted probes can thus
exhaust two risk units. `TestIntegrationGuardedSSHAbandonedClientRisk` confirms
this with the real binary; this is an unresolved availability limitation, not a
claim that aborts are free. The plugin contract supplies no typed backend-ready
event before PipeStart. Refunding a generic PipeCreateError or matching its error
text would weaken ban protection. A future safe refund needs a trusted typed
backend outcome; this revision does not fork sshpiperd or add an auth bypass.

New regression tests pin startup degradation/retry, durable fault recovery,
anonymous address reuse and inventory expiry, normalized-source capacity,
typed reasons, GCE reboot staging and existing-drop-in upgrades. CI adds a real
125-second DROP outage to the existing refusal/strict 600-second jail proof.

## Test strategy

- Core checkpoint/tenant-outcome tests: red/green, fake clock, bounded state,
  history retention, restart with pending lease, invalid-state rejection.
- Generated private-socket contract tests: two listeners share the budget;
  stale/forged connection, route and lease tokens reject; invalid route does not
  dial; persistence failure denies; exhausted budget/hints cannot over-admit.
- Adapter/ban tests: real ordered callbacks, refused backend and cooldown do not
  consume source budget; invalid key/signature/password still do; later client
  denial cannot inherit an earlier backend exception; control outage fails closed.
- Real integration: pinned sshpiperd, YAML and anonymous child, actual sshd and
  fail2ban, multi-minute outage, many clients/two listeners, observed backend
  attempts, jail state, established-session/healthy-backend isolation and timed
  recovery. CI uses an isolated network namespace for real firewall blocking;
  local unprivileged tests retain recording actions and never claim packet proof.
- Real Terraform templates and startup reconciliation prove the production
  invocation passes the same socket/policy and preserves approval/host pins.

No new deployable replaces systemd SSH. Tests may use containers/namespaces for
firewall isolation. PRs #2578/#2581/#2582 are assembled locally as prerequisites;
the final integration PR must carry working end-to-end behavior and CI evidence.
