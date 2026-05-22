# Phase 0 — Bridge-Attach Validation

> Throwaway lab kit for the **eBPF network isolation** work
> (design: [`docs/security/NETWORK-ISOLATION-DESIGN.md`](../../docs/security/NETWORK-ISOLATION-DESIGN.md)).
>
> Goal: confirm the design's load-bearing assumption — that a
> tc-bpf program attached to the Incus bridge sees every
> container-to-container packet — before any user-facing work
> (Phase A onward) begins.

## What this validates

The design proposes attaching small BPF programs to `incusbr0` in
both `tc ingress` and `tc egress`, with policy maps populated by
the daemon. If the **bridge attach point doesn't work cleanly
with Incus** — Incus owns the bridge, fights us for ownership,
loses our filters on `incus stop` / restart, or simply doesn't
route container traffic through the path we expect — the design
collapses.

Phase 0 runs **two validators** that both have to pass:

1. **Shell path** (`tc filter add` + `bpftool map dump`) — confirms
   the kernel + Incus + tc-bpf cooperate at all. Lowest-common-
   denominator; no Go dependency required.
2. **Go path** (`cmd/ebpf-phase0` via `github.com/cilium/ebpf`) —
   confirms the production Go library Phase A will use can drive
   the same path end-to-end. Catches "tc works but cilium/ebpf
   has a rough edge on our kernel" before Phase A commits to it.

Both validators assert:

1. The program can attach to the bridge alongside Incus.
2. Container-to-container traffic on the same bridge actually hits
   the program (in both directions).
3. Detaching is clean — no Incus side-effects.

If both pass on a real Containarium backend, Phase A
productionalizes. If either fails, the design returns to the
drawing board (or the design's "kernel ≥ 5.4" floor is tightened
to ≥ 6.6, depending on which path failed).

## What this is NOT

- Production code. Throwaway.
- A policy engine. The program literally just `__sync_fetch_and_add(counter, 1)`.
- Any kind of drop / filter. `return TC_ACT_OK` always — observation only.

## Files

| File | Purpose |
| --- | --- |
| `counter.bpf.c` | The BPF program — two `__u64` counters, one per direction. |
| `validate.sh` | All-in-one: builds counter.bpf.o, runs shell path AND Go path, asserts both saw the cross-container traffic, cleans up. |
| `../../cmd/ebpf-phase0/` | Go validator using `github.com/cilium/ebpf` + `link.AttachTCX`. Same attach point cilium/ebpf would use in Phase A production code. |
| `README.md` | This file. |

## Running

**Where:** any Containarium backend VM (or any Ubuntu 24.04+ host
with Incus installed) with a kernel ≥ 6.6 (for `link.AttachTCX`).
Ubuntu 24.04 ships 6.8 — fine out of the box. macOS dev
environments cannot run this; BPF + tc need a live Linux kernel.

```bash
# On the backend, as root. Repo must be cloned; the script needs
# both experimental/ebpf-phase0/ and cmd/ebpf-phase0/.
sudo apt install -y clang llvm libbpf-dev linux-tools-$(uname -r) bpftool golang-go
cd /path/to/Containarium/experimental/ebpf-phase0
sudo ./validate.sh
```

Expected output on success:

```
==> 1/5: building BPF object
    OK: counter.bpf.o (1432 bytes)
==> 2/5: attaching to incusbr0
    OK: tc filters installed
==> 3/5: spawning two throwaway containers
    OK: phase0-validate-a=10.0.3.42  phase0-validate-b=10.0.3.43
==> 4/5: snapshotting counters, pinging, re-reading
    before: ingress=0 egress=0
    after:  ingress=14 egress=14
==> 5/5: assertions
    ✓ shell path validated (kernel + Incus + tc-bpf cooperate)
==> 6/7: detaching shell-path filters; preparing for Go-path test
==> 7/7: running Go-side validator (cmd/ebpf-phase0 via cilium/ebpf)
    built /tmp/.../ebpf-phase0
    Go path: ingress before=0 after=14
    ✓ Go path validated (cilium/ebpf drives TCX attach + map read)

────────────────────────────────────────────────────────────────
  ✓ PHASE 0 VALIDATED
────────────────────────────────────────────────────────────────
  • tc-bpf attaches cleanly to incusbr0
  • container-to-container packets traverse the bridge in both
    directions and hit our program
  • shell-path counter deltas: ingress=14 egress=14
  • Go path (cilium/ebpf via TCX): ingress delta 14

  Next step: Phase A (BPF programs in log_only mode, policy
  data model). See docs/security/NETWORK-ISOLATION-DESIGN.md.
────────────────────────────────────────────────────────────────
```

Exit code 0 on validation, non-zero on any failed assertion. If
`go` isn't installed the Go path is **skipped, not failed** — the
shell path can still validate the kernel side.

## Failure modes worth recording

If `validate.sh` fails, the kind of failure tells us what the
design needs:

| Symptom | Diagnosis | Design impact |
| --- | --- | --- |
| `tc qdisc add` errors with "Operation not permitted" | Missing `CAP_NET_ADMIN` / not root | Operator issue, not design |
| `tc filter add` errors with "Error: Specified qdisc not found." | Kernel lacks CLS_BPF | Document minimum kernel ≥ 5.4 — Phase A floor |
| `tc filter add` errors with "Cannot allocate memory" | BPF JIT not enabled | `sysctl net.core.bpf_jit_enable=1` — runbook item |
| Counters stay zero after ping | Bridge isn't on the traffic path | **Design collapses.** Investigate which veth / interface to attach to instead. |
| `incus delete` hangs | Our tc filters block Incus's own management traffic | **Design needs rework.** Maybe per-veth attach instead of bridge attach. |
| Counters increment but Incus throws errors elsewhere | Something we did interferes with Incus's tc usage | **Design needs rework.** Coexistence story with Incus must be designed. |

Record the symptom + diagnosis in the PR comments if Phase 0
fails — that's the deliverable. Don't try to fix Phase 0; the
fix is whatever Phase A needs to do differently, not whatever
makes this throwaway script pass.

## After validation

When this validates on a real backend, the next PR opens Phase A
per the design doc:

1. Add `github.com/cilium/ebpf` to `go.mod`.
2. Land the proto definition for `NetworkPolicy`.
3. Land a Go loader equivalent to the `tc filter add` lines above,
   keyed off the policy data model.
4. Default mode: `log_only` — every "would-deny" event logs but
   no packets are actually dropped.

Phase 0's `counter.bpf.c` is then deleted; the production C
source lives under `internal/network/ebpf/`.

## Cleanup

`validate.sh` cleans up by default. To leave the program attached
for manual poking:

```bash
sudo ./validate.sh --keep
# poke at it
sudo tc filter show dev incusbr0 ingress
sudo bpftool map dump name pkt_counter
# when done:
sudo tc qdisc del dev incusbr0 clsact
sudo incus delete --force phase0-validate-a phase0-validate-b
```
