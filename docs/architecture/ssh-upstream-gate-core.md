# Shared SSH admission core (#1138)

This increment implements the backend-state component of the proposed
`sentinel-ssh-upstream-backoff` design in PR #2578. It is independent of that
unmerged adapter: no production listener or RPC changes yet. PR #2581's real
sshd/fail2ban characterization disproves a universal one-dial/one-jail-failure
assumption. The user explicitly chose ban avoidance over unconditional seconds
recovery when a verified failure budget is exhausted.

Use one Go `sshgate.Gate` in the future sentinel manager for both listeners.
Trusted inventory registers a stable backend/egress key plus route generation;
clients cannot create keys. Route generations do not create separate budgets.
Bound registered keys, pending setups, probe leases and weighted risk records.
Removal cannot erase live reservations, cooldown or retained failure history.

The caller must supply policy (initial/capped exponential delay, additive jitter,
lease deadline, risk limit/window and capacities) and a conservative per-setup
risk cost for the effective jail profile. There are no production defaults or
hardcoded three-dial budget. Pending setups reserve that cost atomically, so
parallel clients cannot over-admit before failures arrive. Unknown/expired
setups retain the risk until the failure window expires. A verified TCP refusal
releases its reservation but starts transport backoff; a successful SSH setup
releases only its own reservation, retaining all earlier failure records.

Reject promptly during cooldown; no sleeping client goroutines or background
retry loop. At the deadline, admit one probe across listeners and keep its lease
until SSH setup completes or expires. TCP connect alone is not success. A failed
probe doubles the base delay up to the cap, with bounded nonnegative jitter. A
successful probe restores admission. Old normal-setup success and stale route/
incident outcomes cannot reopen a newer outage; their risk accounting still
settles. Trusted recovery hints may advance a probe deadline but never bypass
pending reservations or the rolling budget. Established sessions leave the gate
at SSH success and are never closed by this component.

Use injected clock/randomness for deterministic tests and a mutex for atomic
admission/completion. Expired leases conservatively charge at their setup
deadline; future wiring must actually close the socket at that deadline. This
library neither authenticates callers nor creates/closes network connections.
Typed in-process leases/outcomes are internal Go contracts. New inter-process
messages will be defined in `.proto` before private-socket integration; no RPC
is introduced by this milestone.

State is in memory. Before guarded listeners can use a replacement controller,
integration must preserve prior risk history or wait out a verified jail window;
a process restart must not silently renew its retry budget. Lease-owner binding
rejects foreign completions but does not itself provide restart continuity.

Tests must cover exponential/capped/jittered delays, shared admission, weighted
budget/window edges, healthy-success history retention, one SSH-ready probe,
expiry, stale/tampered/duplicate outcomes, route updates, recovery hints, backend
isolation, capacity and concurrent callers. CI runs this package with the race
detector. This is not #1138 completion: trusted routing, actual socket deadlines,
typed client-ban attribution and live firewall/outage/recovery proof remain.
