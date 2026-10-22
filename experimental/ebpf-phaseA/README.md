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

## Build the BPF object

```sh
clang -O2 -g -target bpfel -I/usr/include/$(uname -m)-linux-gnu \
    -c netpolicy.bpf.c -o netpolicy.bpf.o
```

(The multiarch `-I` lets clang's bpf target find `<asm/types.h>`, same as
Phase 0. `-target bpfel` emits a little-endian object — one object serves every
little-endian backend, amd64 and arm64.)

For the daemon, `make build-bpf` runs exactly this and stages the object at
`internal/netbpf/netpolicy.bpf.o` for embedding; the release pipeline does it
automatically (see "Enabling the enforcer" below). The standalone command here
is for the validator kit / iterating by path.

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

The daemon wires all of this up but keeps it **OFF by default**. The
`CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT` env var both enables it and selects
where the object comes from:

```sh
# Option 1 — use the object compiled into the release binary (no backend clang).
export CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT=embedded

# Option 2 — point at a custom / locally-built object by path.
export CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT=/path/to/netpolicy.bpf.o

# restart the daemon
```

**`embedded`** loads the object baked into the binary at build time. The release
pipeline runs `make build-bpf` (clang) and builds with `-tags embed_bpf`, so
official binaries carry it — operators no longer need a compiler on the backend.
A binary built without the object (a plain `make build`) reports the embedded
object is absent and the enforcer stays off; use a **path** instead, or build
your own with:

```sh
make build-bpf        # compiles internal/netbpf/netpolicy.bpf.o (needs clang)
make build            # re-run: the Makefile auto-adds -tags embed_bpf
```

A **path** value is loaded from that file as before — useful for iterating on the
program without a full rebuild. Either way, the verifier still runs at load time
on the target kernel.

When enabled, the daemon loads the program, reconciles every tenant's stored
policy (`containarium network-policy set ...`) and live containers into the BPF
maps on a periodic loop (and on container events), attaches to each container's
veth, writes a `network_policy.deny_logged` audit row per would-deny flow, and
(with the `flows` map) feeds the traffic view (#627). Unset → the daemon behaves
exactly as before.

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

### Known limitation: replies to inbound connections (#2618)

The ingress program runs on the container veth's ingress (traffic *leaving*
the container) and judges each packet by its **destination address alone**
(plus the metadata and virtual-patch rules). It has no connection-state
handling, so a *reply* to a connection opened toward the container (a reverse
proxy fetching from a service in the box, host management over SSH, a health
probe from the bridge gateway) is evaluated exactly like a new outbound flow
to the proxy / gateway / host address. This follows from reading the program;
it has not been confirmed on a live host, so treat it as expected rather than
measured.

What that means in practice:

- **In `log_only`** such replies show up as would-denies, typically as many
  different high ports (the client's ephemeral ports) toward the proxy or the
  bridge gateway. They inflate the deny counts you are asked to review before
  arming enforcement, and (before #2612) the deny-burst finding.
- **Before arming enforce for a tenant**, a service reached through the proxy
  may lose its replies. The only workaround with the current key is to put the
  proxy / gateway address in the tenant's allow-list, which allows **every
  port** on that address to the tenant, not just replies. Treat that as a
  deliberate widening and prefer a host you control.
- To tell whether a would-deny is a reply: it is toward an address that
  *contacted* the box (the proxy, the gateway, an operator host) and the
  destination port is a high ephemeral port.

To confirm on a canary in `log_only`: open an inbound connection to a service
in the box from the proxy or host, then check the daemon log for a
`log_only (not dropped)` deny whose destination is that client.

A real fix needs per-flow state (a map of inbound-initiated flows recorded by
the egress hook, consulted by the ingress hook). Passing every TCP segment
that lacks a bare SYN is **not** an acceptable shortcut: it would let any
non-SYN segment out to any destination, defeating default-deny for a
cooperating remote endpoint. That change belongs in the BPF program and needs
a live backend to verify.

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
cache (both of which come up empty in the common docker-in-LXC topology). Both
directions are captured (#631): the ingress hook tallies the container's egress
(bytes_sent), and a second program on the veth TC_EGRESS hook tallies the reply
direction (bytes_received) onto the same flow entry.

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

The full on-backend acceptance procedure (verifier acceptance of the egress
program, `bytes_received` check, history persistence, no-regression, rollback)
is in [`VALIDATION-traffic-flows.md`](VALIDATION-traffic-flows.md).

## Exec telemetry — `execwatch.bpf.c` (#2637)

A **second object** next to `netpolicy.bpf.o`, for the process guardrail
(design: [`docs/architecture/process-exec-guardrail.md`](../../docs/architecture/process-exec-guardrail.md),
component 1). One program on the `sched/sched_process_exec` tracepoint walks
the exec'ing task's cgroup ancestors (levels 1..12) against the
`watched_cgroups` hash map (cgroup id → container index, filled by the daemon
from each running container's init PID → `/proc/<pid>/cgroup` →
`/sys/fs/cgroup/<path>` inode) and, on a hit, emits one fixed-layout record
`{host_pid, ppid, uid, cgroup_id, comm[16], filename[256], argv[512],
argv_truncated}` to the 1 MiB `exec_events` ring buffer. A miss at every level
(host or core-infra process) emits nothing. `argv` is read from
`mm->arg_start..arg_end` with CO-RE and capped at 512 bytes; the environment
block is never read. Ring overflow is counted in `exec_stats[1]`, never
blocks the exec.

Why a separate object: the exec program is host-global, needs kernel ≥ 5.8
(ringbuf; 5.6 for `bpf_get_current_ancestor_cgroup_id`) plus kernel BTF for
the CO-RE reads, and a verifier rejection or missing BTF must not take flow
enforcement down with it. The network object keeps its 5.4 floor.

Build — `make build-bpf` does all of this: it generates `vmlinux.h` from the
build host's kernel BTF (`bpftool btf dump file /sys/kernel/btf/vmlinux format c`,
gitignored, never checked in) and compiles both objects. By hand:

```sh
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -O2 -g -target bpfel -I. -c execwatch.bpf.c -o execwatch.bpf.o
```

Overhead (lane measurement, `TestExecWatch_OverheadMeasurement`, ubuntu-latest
8-core runner): 983 execs/s sustained for 60 s, 0 events lost, kernel-side
1.21 % + ring consumer 1.74 % = 2.95 % of one core = **0.37 % of the host's
CPU**. The bar is "< 1 % of host CPU at 1,000 execs/s" (decided 2026-10-19);
bringing the Go consumer under 1 % of a core is a follow-up. A burst the
consumer cannot drain is counted in `exec_stats[lost]` (10,000 undrained
execs: 1,272 kept, 8,729 counted), never blocks the exec.

The Go side is `internal/netbpf/execwatch.go` (`LoadExecWatch`, `Attach`,
`WatchCgroup`/`UnwatchCgroup`, `ConsumeExecEvents`, `ParseExecEvent`); the
wire layout is pinned by `TestExecEventWireLayout`, and the real-kernel
proof (loads, one event per watched exec, none for host execs, a 10k burst
counts rather than panics, the measured per-exec overhead) is
`internal/netbpf/execwatch_load_test.go` in the `ebpf-load.yml` lane. The
daemon resolves the object from the same `CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT`
value: `embedded` uses the embedded copy, a path loads the sibling
`execwatch.bpf.o` next to `netpolicy.bpf.o`.
