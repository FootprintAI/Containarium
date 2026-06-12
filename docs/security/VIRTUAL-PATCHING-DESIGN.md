# eBPF Virtual Patching — Design Note

> Status: **Tier 1 implemented (this slice); Tiers 2–3 designed, not built.**
> Tracking: epic #659, Tier 1 #660, Tier 2 #661, Tier 3 #662.
> Builds directly on the network-isolation substrate (see
> [`NETWORK-ISOLATION-DESIGN.md`](./NETWORK-ISOLATION-DESIGN.md), #315).

## What virtual patching is

A **virtual patch** is a temporary, network-level rule that blocks a known
exploit *before it reaches the vulnerable software* — buying time until the
vendor's real patch ships, with zero downtime and no change to the running
application. The classic form is a WAF/IPS signature; the cheap, reliable form
is an L3/L4 block rule. It is a Band-Aid, not a cure: the underlying bug still
exists, so the virtual patch is meant to be removed once the real fix lands.

## What we already had (the substrate)

The eBPF network-isolation work (#315) gave us the enforcement machinery:

- A per-container-veth TC clsact program (`netpolicy.bpf.c`) that can
  `TC_ACT_SHOT` (drop) on the sender side of every flow.
- A per-tenant LPM-trie **allow**-list (`egress_cidr`), a reconcile loop that
  pushes rules into BPF maps with zero downtime, and a perf-event audit stream
  on every deny.
- Two opt-ins that gate the whole feature: it is off unless
  `CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT` is set, and drops are disarmed unless
  `CONTAINARIUM_NETWORK_POLICY_ENFORCE=1` (operators soak in log-only first).

What was missing was a **deny** primitive and any payload inspection. This note
adds the deny primitive (Tier 1) and sketches the inspection tiers.

## The honest split

"Virtual patching" names two very different things:

1. **L3/L4 block** — "a network-reachable service/upstream is vulnerable, block
   it." Pure eBPF, reliable, available today. **This is Tier 1.**
2. **L7 signature** — match an exploit string in the payload (Log4Shell
   `${jndi:`, Shellshock `() {`). Genuinely hard in pure-kernel eBPF: the
   program sees one packet at a time (no TCP reassembly → segment-split
   evasion) and cannot read TLS payloads. Tiers 2–3 address this with explicit
   caveats.

Because of (2), this is staged in tiers rather than shipped as one feature.

---

## Tier 1 — L3/L4 deny rules (implemented)

### Data model

`NetworkPolicy` gains `repeated NetworkPolicyDenyRule deny_rules` (field 8):

```proto
message NetworkPolicyDenyRule {
  string cidr = 1;        // destination CIDR or host IP (/32), IPv4
  uint32 port = 2;        // 0 = any
  string proto = 3;       // "tcp" | "udp" | "" (any)
  string note = 4;        // operator note — typically the CVE id
  string expires_at = 5;  // RFC3339; past → not installed (self-removing patch)
}
```

A deny rule is part of the tenant's policy, evaluated **before** the allow-list:
deny beats allow, the same way the cloud-metadata IP already overrides a broad
allow CIDR.

### Evaluation order (in `netpolicy_ingress`)

1. Unmanaged veth → pass.
2. **Virtual-patch deny rule match → would-deny** (NEW). Beats everything below.
3. Cloud-metadata deny-by-default (#315 Phase D).
4. Intra-tenant allow.
5. Egress allow-list.

A would-deny emits a perf event and returns `TC_ACT_SHOT` **only** when the
veth's mode is `ENFORCE` and the daemon is armed; otherwise it is observed and
audited (`TC_ACT_OK`). Same disarm-by-default safety as the rest of the policy.

### Kernel objects

- `deny_cidr` — an `LPM_TRIE` sharing the tenant-scoped `egress_key` shape
  (`prefixlen, tenant_id, addr`), with a richer value:

  ```c
  struct deny_val { __u16 port; __u8 proto; __u8 flags; };
  ```

  The LPM key is **CIDR-only** (port/proto live in the value). Consequence:
  at most one deny entry per `(tenant, CIDR)`. To block two distinct ports on
  the same host, deny the host outright (`port 0 = any`). Documented Tier-1
  limitation; lifting it (port in the key) is a follow-up if needed.
- `deny_event.reason` reuses the struct's former pad byte (wire size
  unchanged) to distinguish a virtual-patch drop from a routine allow-list
  miss, so the audit log can label them differently
  (`network_policy.virtual_patch` vs. `network_policy.deny_*`).

### Control plane

- `internal/netpolicy` parses/validates/dedupes/sorts deny rules into
  `CompiledPolicy.DenyRules` (time-pure: expiry is *parsed* but not *applied*
  here).
- The daemon (`compiledPolicies`) drops expired rules with
  `DenyRule.Expired(now)` before planning, so an expired patch self-removes on
  the next reconcile.
- `planReconcile` emits per-tenant `DenyEntry`s; `diffDeny` converges the map.
  Unlike egress, a deny entry's kernel key is narrower than the full entry (the
  value carries port/proto), so a rule whose *only* change is its port is an
  **upsert** of the same slot, never a delete-then-add of two slots.
- Backward-compatible: if the loaded BPF object predates the `deny_cidr` map
  (an older release binary), the daemon logs that deny rules are configured but
  unenforceable until `netpolicy.bpf.o` is rebuilt — it does not fail.

### CLI (CLI-first per `CLAUDE.md`)

```
containarium network-policy patch add <tenant> --cidr 1.2.3.4/32 \
    [--port 6379] [--proto tcp] [--note CVE-2024-XXXX] [--expires 2026-07-01T00:00:00Z]
containarium network-policy patch rm   <tenant> --cidr 1.2.3.4/32 [--port 6379] [--proto tcp]
containarium network-policy patch list <tenant>
```

`patch add/rm` read-modify-write only the `deny_rules` of the tenant's policy
(the allow-list is untouched). `network-policy set`, which has no deny flags,
fetches and **preserves** any existing deny rules rather than wiping them. The
platform MCP tool wraps the same endpoints.

### Product hook (scanner → virtual patch)

The intended end-to-end: a security-scan CVE finding emits a deny rule (with the
CVE as `note` and a conservative `expires_at`); reconcile pushes it; the scanner
clears it once it confirms the upstream patch landed. "Band-Aid until the real
fix ships, then auto-removed." The expiry field makes the auto-removal a
property of the data, not a cron job.

---

## Tier 2 — bounded cleartext signature matching (designed, #661)

Extend the program with `bpf_skb_load_bytes` over the first ~256 payload bytes
and a `bpf_loop`-bounded scan against a small, operator/scanner-managed
signature table. On match → the existing would-deny path.

**Caveats that must stay documented, not hidden:** single-packet only (no
reassembly → segment-split evasion), cleartext only (TLS is opaque),
verifier-bounded pattern count/length. A best-effort pre-filter, not a WAF.

## Tier 3 — userspace WAF behind eBPF steering (designed, #662)

eBPF steers flagged flows (sockmap/TC redirect) into a host-side WAF (Coraza /
ModSec CRS) that does reassembly, TLS termination, and full rule sets, then
forwards or blocks. The only WAF-grade tier; eBPF shrinks to a fast
classifier/redirector. Heavy (per-host proxy, cert lifecycle), so it is opt-in
per tenant and justified only where Tiers 1–2 fall short.

---

## Validation (Tier 1)

The BPF object only builds and runs on a Linux backend (it needs kernel UAPI
headers + a ≥6.6 kernel for TCX); it cannot be compiled on the dev mac. Steps,
run on a backend with the feature enabled:

1. `make build-bpf` and rebuild the daemon with `-tags embed_bpf` (or point
   `CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT` at the freshly built `.o`).
2. Pick a tenant container; confirm it can reach a test destination.
3. `network-policy patch add <tenant> --cidr <dest>/32 --note CVE-test`,
   reconcile, confirm the audit log shows `network_policy.virtual_patch` and —
   with `CONTAINARIUM_NETWORK_POLICY_ENFORCE=1` — the destination is now
   unreachable while unrelated egress still works.
4. `patch add` the same CIDR with `--port` set; confirm only that port is
   blocked.
5. Set `--expires` a minute out; confirm the rule disappears (reachability
   restored) on the reconcile after expiry.
6. `patch rm`; confirm reachability restored and the deny entry is gone from the
   map.

Pure-Go layers (compile, plan, diff, expiry) are covered by unit tests in
`internal/netpolicy`, `internal/netbpf`, and `internal/server`.
