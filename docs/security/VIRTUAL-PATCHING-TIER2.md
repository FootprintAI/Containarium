# eBPF Virtual Patching — Tier 2 (cleartext signature scanning)

> Status: **PR-A + PR-B implemented.** PR-A = kernel scan + loader + built-in
> signature set, enforce-gated, verifier-validated on a 6.8 backend. PR-B =
> operator signature CRUD (API + CLI + persistence). Part of the virtual-patching
> epic (#659); #661. Builds on Tier 1
> ([`VIRTUAL-PATCHING-DESIGN.md`](./VIRTUAL-PATCHING-DESIGN.md)).

## What this adds

Tier 1 blocks a vulnerable destination at L3/L4 (deny a CIDR/port). Tier 2 looks
*inside* the packet: it scans the **inbound** payload of a container's TCP
connections for a small set of curated **cleartext exploit signatures** and
drops the packet before it reaches the (vulnerable) service — the WAF/IPS form
of virtual patching, e.g. dropping a `${jndi:` Log4Shell request to a Java app
that hasn't been patched yet.

This is a **best-effort pre-filter, not a WAF.** The honest constraints are
structural and must stay visible to operators (see below); the WAF-grade answer
is Tier 3 (#662).

## Direction: inbound (container-receive)

The scan runs on the container veth's **TC_EGRESS** hook — the host→container
direction, i.e. packets arriving *at* the container's services. That is where an
exploit payload aimed at a vulnerable service in the container is seen. (Tier 1's
deny logic runs on TC_INGRESS, the container's send side; the two are
complementary.)

## Kernel design (the hard part)

Pure-kernel payload scanning is verifier-hostile. The shape that works (proven in
`experimental/ebpf-phaseA/sigscan-proto.bpf.c`, validated on kernel 6.8 — three
earlier shapes were rejected, documented in that file's header):

- **One `bpf_loop`** over the flattened `(signature × offset)` space. `bpf_loop`
  is verified once regardless of trip count, so there is no back-edge for the
  verifier to mistake for an infinite loop (naive nested loops *and* full
  unrolling were both rejected with "infinite loop detected").
- The payload window lives in a **per-CPU scratch map**, re-looked-up inside the
  callback — passing a stack pointer through the callback context loses its
  bound.
- Only the tiny **pattern-compare loop is unrolled** (fixed `SIG_MAX_LEN`).
- **Constant-size payload loads** via a tier of `bpf_skb_load_bytes(…, 256/128/
  64/32)` — a *variable* length gets re-derived by clang straight from the skb
  arithmetic past every guard and the verifier rejects the possibly-zero size.
- A global **`sig_config` gate**: the per-packet `bpf_loop` cost is only paid
  when the operator has enabled scanning (otherwise the egress hook stays
  pure accounting, as before).

Current limits (compile-time constants in `netpolicy.bpf.c`): `SCAN_WINDOW=256`,
`SIG_MAX_COUNT=32`, `SIG_MAX_LEN=32`. The full program verifies on 6.8 using a
small fraction of the 1M instruction budget, so there's headroom to widen later.

On a match the egress program emits a `deny_event` with `reason=SIGNATURE` and
the matched `sig_id`, and returns `TC_ACT_SHOT` **only** in enforce mode;
otherwise it observes + audits.

## Honest constraints (best-effort, not a WAF)

- **Single packet, no reassembly.** A signature split across two TCP segments
  is not matched — a trivial evasion. Tier 2 catches unsophisticated/scripted
  attempts, not a determined attacker.
- **Cleartext only.** TLS payloads are opaque to eBPF; an HTTPS exploit is
  invisible. Pairs with TLS-terminating ingress, or Tier 3.
- **First window only.** Only the first `SCAN_WINDOW` bytes of the payload are
  scanned, and (today) only packets carrying at least 32 payload bytes.
- The audit log records the best-effort nature: a Tier-2 *pass* means "no
  configured signature matched in the first window of single packets", **not**
  "clean".

## Control plane

- **Built-in signatures** (`internal/netpolicy/signatures.go`): a small,
  high-confidence curated set (Log4Shell `${jndi:`, Shellshock `() {`,
  Spring4Shell, path-traversal, `/etc/passwd`). Stable nonzero IDs (echoed in
  audit).
- **Operator signatures (PR-B)**: a daemon-global (fleet-wide, NOT tenant-scoped)
  set an operator manages via `containarium network-policy signature add/rm/list`
  (RPCs on NetworkPolicyService, `/v1/network-policy-signatures`, admin-only).
  Each is `{name (unique, the CVE id), pattern (1..32 bytes), enabled, note}`;
  the store assigns a stable id in a reserved high range (`OperatorIDBase=1000`+)
  so operator and built-in ids never collide and a match's audit id unambiguously
  names its source. Persisted in a `network_policy_signatures` table (Postgres) /
  in-memory on standalone. The enforcer merges built-ins + enabled operator
  signatures (built-ins first), capped to the 32-slot budget, and **picks up
  changes on the reconcile loop** (a fingerprint skips the map rewrite when
  nothing changed).
- **Loader** (`internal/netbpf/sigmap.go`): `SetSignature(slot, entry)` writes a
  slot of the `signatures` array map; `SetScanEnabled(bool)` flips the
  `sig_config` gate. Optional-map-safe: an object built before #661 just reports
  `HasSignatures()==false` and the daemon logs that a rebuild is needed.
- **Enforcer** (`network_policy_enforcer.go`): on Start, if opted in, it arms the
  gate and loads the merged set; each reconcile re-syncs the slots so an operator
  add/remove/toggle takes effect within one interval. `OnDenyEvent` labels a
  signature match `network_policy.signature_match` with the signature name.

## Enablement (three independent opt-ins)

1. `CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT` — load the BPF object at all (Tier 0).
2. `CONTAINARIUM_NETWORK_POLICY_SIGNATURES=1` — populate signatures + run the
   scan (this tier). Harmless without (3): matches are logged, nothing dropped.
3. `CONTAINARIUM_NETWORK_POLICY_ENFORCE=1` — actually `TC_ACT_SHOT` a match.

So an operator soaks with (1)+(2) watching `network_policy.signature_match`
audit rows for false positives, then adds (3) to start dropping.

## Validation

`experimental/ebpf-phaseA/sigscan-proto.bpf.c` proved verifier acceptance in
isolation. The integrated `netpolicy.bpf.c` (Tier 0/1/2) was compiled and
verifier-loaded on a Linux backend (kernel 6.8). The runtime match/drop path —
sending a `${jndi:` request to a container and confirming the
`network_policy.signature_match` audit row (and a drop under enforce) — runs on a
backend with the daemon built from this branch; it is not exercisable in CI or on
the dev mac (eBPF needs a Linux kernel). Pure-Go layers (signature set, map
serialization, event decode, `toSigEntry`) are unit-tested.
