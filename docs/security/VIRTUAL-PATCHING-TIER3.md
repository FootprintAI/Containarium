# eBPF Virtual Patching — Tier 3 (userspace WAF behind flow steering)

> Status: **Design — not yet approved or built.** This tier is a large,
> multi-PR effort with a new dependency (an embedded WAF + the OWASP CRS) and a
> new operational surface (a per-host transparent proxy). It should not start
> until the design is signed off. Part of the virtual-patching epic (#659);
> #662. Builds on Tiers 1–2
> ([`VIRTUAL-PATCHING-DESIGN.md`](./VIRTUAL-PATCHING-DESIGN.md),
> [`VIRTUAL-PATCHING-TIER2.md`](./VIRTUAL-PATCHING-TIER2.md)).

## Why a third tier

Tiers 1–2 are in-kernel and therefore structurally limited: Tier 1 blocks at
L3/L4 (CIDR/port), Tier 2 matches cleartext signatures in a single packet's
first window. Neither can handle the cases a real WAF is for:

- **TLS** — encrypted payloads are opaque to eBPF; Tier 2 sees nothing.
- **Multi-segment** — a signature split across TCP segments evades Tier 2 (no
  reassembly in the kernel).
- **Vendor rule sets** — the OWASP Core Rule Set and CVE-specific virtual-patch
  rules need a real HTTP parser and state, not a byte-substring scan.

Tier 3 closes these by steering *flagged* flows into a userspace WAF that does
reassembly, TLS termination, and full rule evaluation, then forwards or blocks.
eBPF's role shrinks to a fast classifier; the fast path (everything not flagged)
stays in-kernel and untouched.

## Architecture decision

### WAF engine: **Coraza, embedded in the daemon** (recommended)

[Coraza](https://github.com/corazawaf/coraza) is a Go-native, ModSecurity-
compatible WAF library that runs the OWASP CRS. Embedding it in the daemon (which
is Go) beats an external ModSecurity/Envoy process for this codebase:

| | Coraza embedded | External (ModSecurity/Envoy) |
|---|---|---|
| Process model | in the daemon — nothing else to deploy | a second per-host process to supervise |
| Cert/TLS | reuses the daemon's existing Caddy-managed certs | its own cert ritual |
| Config lifecycle | rules shipped + reconciled by the daemon | separate config + reload story |
| CLI-first fit | the daemon already owns the policy surface | an agent-only side-channel |
| Cost | a Go dependency (+ the CRS rule files) | a container/binary + IPC |

The cost of Coraza is a sizeable Go dependency and the embedded CRS rule files;
the saving is the entire operational surface of a separate proxy. For a single
Go daemon that already terminates TLS via Caddy and owns the network-policy
surface, embedded Coraza is the clear fit. ModSecurity/Envoy stays the escape
hatch if a customer needs a rule feature Coraza lacks.

### Steering: **TPROXY redirect + eBPF classification** (recommended)

Backend capability probe (kernel 6.8, the validation host) — **both** candidate
mechanisms are available:

- `nft_tproxy` loads; the daemon runs with `CAP_NET_ADMIN` (can bind
  `IP_TRANSPARENT` sockets and program nft). → **TPROXY path works.**
- `bpf_sk_assign` is present. → the pure-eBPF alternative is also possible.

Recommended split:

1. **eBPF classifies.** The existing per-veth TC program decides whether a flow
   is *steer-worthy* (per-tenant, per-port policy — e.g. "tenant T's container
   port 8080 is HTTP-facing and opted into WAF") and marks it (a socket/packet
   mark), OR simply the daemon derives the nft match from policy. eBPF's role
   stays small, as #662 wants.
2. **TPROXY redirects.** An nft `tproxy` rule (generated per-tenant/per-port from
   policy) steers matching inbound connections to a local port where the daemon
   listens with `IP_TRANSPARENT`. The listener recovers the original destination
   (`IP_RECVORIGDSTADDR`) so it can forward upstream after the WAF passes.
3. **Coraza evaluates.** The daemon's transparent proxy reads the connection,
   (optionally) terminates TLS, runs Coraza+CRS over the reassembled HTTP, and
   either forwards to the original container:port or returns a block (403) +
   emits `network_policy.waf_block` to the audit.

**Why TPROXY over a pure-eBPF `bpf_sk_assign` redirect:** TPROXY is a mature,
well-understood transparent-proxy mechanism; the redirect is not where the risk
or the value is (the WAF integration is). `bpf_sk_assign` keeps the redirect
"eBPF-native" but adds verifier/socket-lookup complexity for no functional gain
here. The design keeps `bpf_sk_assign` as a documented future swap if we want to
drop the nft dependency.

### TLS termination

Reuse the daemon's existing Caddy-managed cert store (the BYOD custom-domains
plumbing, cloud #228): where the daemon already holds a cert/key for the
container's hostname, the WAF proxy terminates TLS, inspects, and re-originates
(or passes through to a cleartext upstream). Where no cert is available, the WAF
sees only the TLS handshake and **must fail open** (forward without inspection) —
inspecting encrypted bytes is impossible. This limitation is documented and
surfaced in the audit (a "waf: passthrough, no cert" note), so an operator never
believes a TLS flow was inspected when it wasn't.

## Policy & control plane

- **Opt-in per tenant/port.** A new field on `NetworkPolicy` (or a sibling
  `waf_ports`) marks which of a tenant's container ports are WAF-steered. Off by
  default — only flagged flows pay the userspace round-trip; everything else
  keeps the in-kernel fast path. This is the "keeps the fast path fast"
  acceptance criterion.
- **Rule sources.** (a) the bundled OWASP CRS, (b) CVE-specific virtual-patch
  rules an operator adds (the natural evolution of Tier 2's signature CRUD into
  full ModSecurity rules), (c) the scanner→virtual-patch hook (a CVE finding
  emits a CRS rule with an expiry, mirroring Tier 1's deny-rule auto-expiry).
- **Audit.** `network_policy.waf_block` / `network_policy.waf_pass` with the
  matched rule id, naming the CRS/virtual-patch rule — consistent with Tier
  1/2's `virtual_patch` / `signature_match` actions.

## Phased PR breakdown (proposed)

1. **PR-1 — transparent proxy skeleton (DONE).** Daemon binds an
   `IP_TRANSPARENT` listener; an nft TPROXY rule (manually applied) steers one
   test port to it; the proxy forwards to the original dst (no WAF yet). Proves
   the steering + original-dst recovery + forward path end to end.
2. **PR-2 — inspection seam + reference inspector (DONE).** An `Inspector`
   interface is wired into the proxy: it reads + **reassembles** the request head
   across TCP segments, inspects, and — armed — returns a 403 instead of
   forwarding (observe-only otherwise; both audit `network_policy.waf_block`).
   The reference `BuiltinInspector` substring-matches the curated cleartext
   signatures over the reassembled head — already a win over Tier 2 (which can't
   reassemble), with **no new dependency**. The Coraza-backed inspector (full
   HTTP parse + OWASP CRS) is a drop-in behind the same `Inspector` interface,
   deliberately deferred so the supply-chain decision (Coraza + CRS into go.mod,
   likely behind a `waf` build tag) is made explicitly rather than smuggled in —
   see the open questions. Enabled via `CONTAINARIUM_WAF_INSPECT=1`; blocks only
   when `CONTAINARIUM_NETWORK_POLICY_ENFORCE=1` (same arm as the kernel tiers).
3. **PR-3 — policy-driven nft generation.** Per-tenant/per-port `waf_ports`
   reconciled into nft rules by the enforcer (no manual nft); eBPF classification
   wired.
4. **PR-4 — TLS termination** via the Caddy cert store; fail-open + audit when no
   cert.
5. **PR-5 — rule lifecycle**: operator virtual-patch rules + the scanner hook +
   expiry.

Each phase is independently shippable and off-by-default; only PR-3+ touches the
hot path's policy. PR-1 is the de-risk (analogous to Tier 2's verifier
prototype): if transparent steering + original-dst recovery doesn't work cleanly
on the target kernels, the whole tier's approach is revisited before any WAF
work.

## Open questions (for sign-off)

- **Dependency weight.** Coraza + the embedded CRS materially grow the binary and
  the dependency surface. Acceptable for OSS, or should Tier 3 be a build-tagged
  / Cloud-only feature? (Leaning: build-tag `waf` so OSS binaries don't carry it
  unless built in.)
- **Per-host proxy resource model.** One shared proxy listener for all steered
  tenants vs. per-tenant — shared is simpler and fine if Coraza transactions are
  per-connection; revisit if tenant rule isolation needs separate engines.
- **Failure mode.** If the WAF proxy is down, do steered flows fail **open**
  (reach the service unprotected) or **closed** (blocked)? Default open (avail-
  ability over a best-effort protection layer), operator-overridable.
- **Overlap with Caddy.** The daemon already fronts HTTP via Caddy for ingress;
  is the WAF better as a Caddy plugin (coraza-caddy) than a standalone TPROXY
  listener? **Evaluated** in
  [`TIER3-WAF-ENGINE-DECISION.md`](./TIER3-WAF-ENGINE-DECISION.md): they're
  complementary by traffic topology — recommendation is **coraza-caddy first**
  for north-south ingress (TLS + HTTP parsing free, zero daemon dependency), the
  standalone proxy (PR-1/PR-2) for east-west. Awaiting a go/no-go on the custom
  Caddy build + whether east-west coverage is in scope now.

## Acceptance (from #662)

- [ ] A flagged flow is transparently routed through the WAF; a CRS rule blocks a
      known exploit (multi-segment / TLS Log4Shell) that Tier 2 cannot.
- [ ] Non-flagged flows keep the in-kernel fast path (measured overhead).
- [ ] Off by default; opt-in per tenant.

## Recommendation

Build Tier 3 **only if** a concrete need lands that Tiers 1–2 can't meet (a TLS
or multi-segment exploit, or a compliance requirement for CRS-grade rules). It is
the highest-cost tier by far. When that need arrives, start with **PR-1** (the
steering de-risk) behind a `waf` build tag, and re-evaluate the Caddy-plugin
option before committing to the standalone TPROXY proxy.
