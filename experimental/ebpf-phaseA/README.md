# Phase A — Per-Veth Network-Policy Validation

> On-backend validator for the **eBPF network isolation** work, Phase A
> (design: [`docs/security/NETWORK-ISOLATION-DESIGN.md`](../../docs/security/NETWORK-ISOLATION-DESIGN.md), #315).
>
> Phase 0 proved the attach point (per-container host veth, `TC_INGRESS`).
> Phase A productionizes it: a real policy program + the Go loader the daemon
> will use. This kit exercises that program end-to-end against a live
> container veth **before** it is wired into the daemon.

## What this validates

`netpolicy.bpf.c` is the Phase A program: attached to a container's host veth in
`TC_INGRESS` (the sender side of every flow), it evaluates each IPv4 flow against
the sender tenant's policy and, for flows that **would be denied**, bumps a
counter and emits a perf event. **Observation only** — it always returns
`TC_ACT_OK`; nothing is dropped. (Phase B flips would-deny to `TC_ACT_SHOT` when
the per-veth mode is `ENFORCE`.)

The Go loader (`internal/netbpf`) loads the object, populates the policy maps
(per-veth config, egress allow-list LPM trie, IP→tenant map), and attaches via
TCX. `cmd/ebpf-phaseA` drives all of it and watches the result.

Success criteria, run on a real backend:

1. **Loads + attaches cleanly** on the target kernel (≥ 6.6 for TCX) without
   disrupting the container's existing networking.
2. **`seen` counter increments** as the target container sends traffic.
3. **`would_deny` + a `WOULD-DENY` event** appear for a flow *outside* the
   configured allow-list, and **do not** appear for a flow *inside* it.
4. **`allow-intra` semantics**: with `--allow-intra` + the peer registered via
   `--peer-ip`, same-tenant peer traffic is allowed (no deny event); without it,
   it is would-denied.

## Build the BPF object (on the backend)

```sh
clang -O2 -g -target bpf -I/usr/include/$(uname -m)-linux-gnu \
    -c netpolicy.bpf.c -o netpolicy.bpf.o
```

(The multiarch `-I` lets clang's bpf target find `<asm/types.h>`, same as
Phase 0.)

## Run

Resolve the target container's host veth first (the daemon will do this via
`netbpf.HostVethFromConfig`):

```sh
# host veth name for a container's eth0:
incus config get <container> volatile.eth0.host_name
```

Then attach and watch (as root):

```sh
sudo ./ebpf-phaseA \
    --obj ./netpolicy.bpf.o \
    --veth <vethXXXXXXXX> \
    --tenant 1 \
    --allow-cidr 8.8.8.8/32 \
    --allow-intra \
    --peer-ip 10.0.3.42 --peer-tenant 1
```

Generate traffic from inside the target container and observe:

```sh
incus exec <container> -- ping -c3 8.8.8.8   # allowed → no deny event
incus exec <container> -- ping -c3 1.1.1.1   # not allowed → WOULD-DENY events
```

`^C` detaches and exits (the TCX link is closed on exit).

## Status

`netpolicy.bpf.c`, the loader, and this validator are **hardware-pending**: they
compile in CI, the pure-Go map translation (`internal/netbpf`) is unit-tested,
but the BPF program + TCX attach have **not** yet been run on a backend. Do not
wire the loader into the daemon (the denied-flow→audit consumer + container
lifecycle integration) until this validator passes on a Linux backend — the same
discipline that made Phase 0 catch a wrong attach point before it shipped.
