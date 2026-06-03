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

**Validated on a Linux backend** (kernel 6.8, Incus 6.23, TCX attach). The run,
against a throwaway Ubuntu 24.04 container with `--allow-cidr 8.8.8.8/32`:

- program loaded (verifier passed) and attached to the container's host veth in
  `TC_INGRESS` via TCX; existing container networking undisturbed;
- `seen` incremented by exactly the container's outbound packets;
- ICMP to `8.8.8.8` (allow-listed) produced **no** would-deny — the tenant-scoped
  `egress_cidr` LPM trie matched and passed it;
- ICMP to `1.1.1.1` (not listed) produced `would_deny` counts + `WOULD-DENY` perf
  events carrying the correct `src`/`dst`/`proto`/`tenant`/`ifindex` (C↔Go struct
  layout and byte order confirmed);
- log_only dropped nothing — all pings succeeded.

This validates the load-bearing eBPF path. The remaining Phase A work — the
denied-flow→audit consumer + container-lifecycle integration in the daemon
(attach on create/start, detach on stop/delete, populate maps from stored
policies + container IPs) — builds on the now-proven loader.
