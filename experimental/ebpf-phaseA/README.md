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

This validates the load-bearing eBPF path. The daemon-side integration (enforcer
+ denied-flow→audit consumer + reconcile loop) now consumes this proven loader.

## Enabling the enforcer in the daemon

The daemon wires all of this up but keeps it **OFF by default**. To turn it on,
build the object on the backend (above) and point the daemon at it:

```sh
export CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT=/path/to/netpolicy.bpf.o
# restart the daemon
```

When set, the daemon loads the program, reconciles every tenant's stored policy
(`containarium network-policy set ...`) and live containers into the BPF maps on
a periodic loop (and on container events), attaches to each container's veth, and
writes a `network_policy.deny_logged` audit row per would-deny flow. Unset → the
daemon behaves exactly as before.

## Phase B — enforcement (dropping)

By default the enforcer is observation-only even for `--mode enforce` policies.
To actually drop, the operator arms a **second** opt-in:

```sh
export CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT=/path/to/netpolicy.bpf.o
export CONTAINARIUM_NETWORK_POLICY_ENFORCE=1   # arm drops
# restart the daemon
```

Then a tenant's `--mode enforce` policy drops denied flows (`TC_ACT_SHOT`),
audited as `network_policy.deny_dropped`. Safety properties:

- **Two opt-ins.** The object path enables observation; the enforce env enables
  drops. Soak in log_only first, watch the deny logs, complete the allow-list
  (including DNS / the bridge gateway — an enforce policy that omits its
  resolver will cut the container off), *then* arm enforce.
- **No-policy containers are never dropped** — they stay log_only regardless, so
  the blast radius is exactly the tenants with an explicit enforce policy.
- **The egress allow-list converges** — a CIDR removed from a policy is deleted
  from the kernel map on the next reconcile, so tightening a policy actually
  takes effect.

Validated on a Linux backend: with enforce armed and `--allow-cidr 8.8.8.8/32`,
`ping 8.8.8.8` succeeds and `ping 1.1.1.1` sees 100% packet loss (dropped), while
a policy-less neighbour container is unaffected.

## Phase C — egress by domain

A policy's `egress_domains` (`containarium network-policy set <tenant>
--egress-domain api.github.com`) are resolved to IPv4 and folded into the same
egress allow-list as /32 entries, refreshed on a loop (default 60s). The
reconcile's `diffEgress` prunes IPs a domain stops resolving to; a failed lookup
keeps the prior IPs so a DNS blip doesn't thrash the allow-list (or, under
enforce, blackhole the domain). Resolve the DNS resolver / gateway too — name
resolution itself must be allowed.

Validated on a Linux backend: with enforce armed and only `--allow-domain
one.one.one.one` (no CIDRs), `ping 1.1.1.1` (the resolved IP) succeeds and
`ping 8.8.8.8` sees 100% packet loss.

> TTL: a fixed refresh interval for now; per-record DNS-TTL refresh (raw DNS) is
> a follow-up.

## Phase D — cloud metadata default-deny

The cloud metadata service (`169.254.169.254`) hands out instance credentials, so
it is denied by default — checked *before* the egress allow-list, so even a broad
`--egress-cidr 0.0.0.0/0` can't expose it. A tenant that genuinely needs metadata
opts in explicitly:

```sh
containarium network-policy set <tenant> --allow-metadata ...
```

Validated on a Linux backend: under enforce with `--allow-cidr 0.0.0.0/0`, traffic
to `8.8.8.8` passes but `169.254.169.254` is dropped (`deny … dst=169.254.169.254
… DROPPED`); adding `--allow-metadata` lets it through.

## Per-flow accounting → traffic view (#627)

The program also keeps a `flows` map (`BPF_MAP_TYPE_LRU_HASH`, 5-tuple →
`{packets, bytes, first_ns, last_ns}`) updated for **every** observed flow
(allowed and would-deny). The daemon enforcer polls it (`Loader.Flows()`,
default 15s), attributes each flow to a container by veth ifindex, and feeds the
traffic collector — so the traffic view shows real src/dst IP + byte counts
sourced straight from eBPF, independent of conntrack accounting and the IP→name
cache (both of which come up empty in the common docker-in-LXC topology). EGRESS
only (the veth ingress hook sees the container's outbound side); reply bytes
stay 0.

Rebuilding `netpolicy.bpf.o` with the new map is required to enable it — an
older object still loads and enforces, the daemon just logs that flow accounting
is off. To validate on a backend (after rebuild + `export
CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT=...`, with a tenant container running):

```sh
incus exec <container> -- curl -s https://1.1.1.1 >/dev/null   # generate egress
# then query the daemon's traffic API (or open the webui traffic view):
curl -s -H "Authorization: Bearer $JWT" \
  "$DAEMON/v1/containers/<tenant>-container/connections" | jq .
```

Expect non-empty rows carrying the container's source IP, the destination
IP/port, and non-zero `bytes_sent` — with **no** dependency on
`nf_conntrack_acct` or the conntrack collector matching. Counters are cumulative
per flow; the LRU map self-evicts idle flows.
