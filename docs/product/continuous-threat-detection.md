# PRD: Continuous threat detection (background security sentry)

**Date:** 2026-08-31
**Status:** accepted — P0 stories filed as #1639 #1640 #1641 #1642 #1643
**Owner:** devops@footprint-ai.com

## Problem

Nothing on the platform continuously watches for abuse or cross-tenant
attack attempts. Every incident to date was detected by someone else, by
luck, or not at all:

- **Cryptomining abuse (cloud#815, 2026-07-11).** An abusive signup
  created 12 containers in 19 minutes from a 2-minute-old account and ran
  miners at ~260% CPU with a persistent TLS connection to a known mining
  pool. **Google Cloud SCC detected it, not us** — the alert arrived
  after the mining window had already ended. Repeated events risk GCP
  **project suspension**, which would take down every tenant on that
  provider. On BYOC hosts there is no external detector at all: the same
  attack there is invisible.
- **Cross-org isolation breach (cloud#780, 2026-07-07).** Two containers
  in different orgs on the same backend could reach each other. The
  condition had existed in production indefinitely; it was found only
  when the one-shot CI isolation sentry was armed for the first time.
  Nothing verifies the tenant fence between CI runs, and nothing would
  notice a tenant *probing* it.
- **Signals already exist but terminate in a log nobody watches.** The
  eBPF network-policy layer emits per-flow records (5-tuple,
  bytes/packets, 15s poll → `TrafficService`) and typed deny events
  (policy / virtual-patch / signature-match). Deny events go to the
  audit log and stdout only — no alert, no event-bus fan-out, no
  thresholding (`internal/server/network_policy_enforcer.go:414`).
- **Cost of the gap:** incident response starts from an external abuse
  notification (reputational + suspension risk), the operator burns
  hours reconstructing timelines from raw logs, and the multi-tenant
  isolation story — the product's core promise — is verified only at CI
  time, not continuously.

**Why now:** the substrate shipped over the last two quarters (eBPF
Phase A #315, flow accounting #627, deny-event plumbing #660/#661,
webhook alert path, event bus). The remaining work is correlation and
delivery, not new data collection — and free-tier signup means
cloud#815-class abuse recurs until detected automatically.

## Target user

The **platform operator / on-call engineer** running a Containarium
fleet (our cloud, or an OSS self-hoster). Job-to-be-done: *know within
minutes — not from a third party — when a tenant is abusing the platform
or testing the tenant fence, with enough context to respond.*

Tenants benefit indirectly (their co-residents are watched) but are not
the MVP audience.

## Success metrics

| Metric | Baseline | Target |
|--------|----------|--------|
| Time-to-detect mining-class abuse (start of egress to known-bad destination → our own alert) | External-only: provider alert after the fact on GCP; **never** on BYOC | < 5 min, from our own alert, on every backend with eBPF enabled |
| Cross-tenant reachability / fence-probing detection | One-shot CI sentry only; probes between runs invisible | Continuous: cross-tenant flow or deny-burst alerts within 5 min |
| Alert precision (on-call trusts the channel) | Unknown — instrument first | After 4 weeks tuning: < 3 false-positive alerts/week fleet-wide |

## MVP scope — the core journey

> A tenant workload opens a connection to a known mining pool (or starts
> probing sibling containers). Within one detection cycle the daemon
> raises a **security finding**, records it in the tamper-evident audit
> log, emits it on the event bus, and delivers it to the operator's
> configured webhook. The operator runs
> `containarium security findings` to see what fired, on which backend,
> for which tenant, with the triggering flows attached — and responds
> using existing primitives.

Detection-only in the MVP: the sentry **observes and alerts, it does not
act**. (Automated response is P1 — precision must be measured before
anything is allowed to freeze or quarantine on its own.)

The engine lives in the OSS daemon (CLI-first; cloud wraps it), runs as
a background loop over signals already collected — eBPF flow records and
deny events — and evaluates a small, fixed, explainable rule set. No ML
in the MVP.

### P0 stories

**Story 1: Security finding as a first-class platform event** (#1639)**.**
As an operator, I want detections recorded as typed security findings so
that they are queryable, streamable, and tamper-evident — not log lines.
**Acceptance criteria:**
- [ ] A `SECURITY_FINDING` event type exists in `events.proto` with rule
      id, severity, tenant/container ref, backend, and evidence
      (triggering flow 5-tuples / deny counts); delivered via
      `EventService.SubscribeEvents`.
- [ ] Every finding also lands in the audit log inside the existing hash
      chain, and `VerifyChainSinceID` still passes over a window
      containing findings.
- [ ] Findings persist across daemon restart.
**Priority:** P0

**Story 2: Background detection loop in the daemon** (#1640)**.**
As an operator, I want a detection engine that continuously evaluates
rules over the eBPF flow and deny-event streams so that detection is not
tied to a scan schedule or a CI run.
**Acceptance criteria:**
- [ ] Engine subscribes to flow records and deny events in-process; end
      of a detection cycle ≤ 60s after the triggering flow is polled.
- [ ] Runs in observation mode: requires the eBPF object loaded but NOT
      `CONTAINARIUM_NETWORK_POLICY_ENFORCE` — detection works on a fleet
      that hasn't turned on enforcement yet.
- [ ] A rule firing repeatedly for the same tenant+rule dedupes into one
      open finding with an updated count, not an alert storm.
- [ ] Engine on/off state and per-rule status visible via
      `containarium security sentry status` (CLI verb; MCP tool wraps
      the same client function).
**Priority:** P0

**Story 3: Known-bad destination rule (catches cloud#815)** (#1641)**.**
As an operator, I want an alert when any tenant egresses to a known
mining pool or known-bad destination so that coin-mining abuse is
detected in minutes instead of via a provider abuse notice.
**Acceptance criteria:**
- [ ] Ships with a static, versioned bad-destination list (mining pools
      first) matched against flow destination IPs; list is
      operator-extendable via CLI without a daemon rebuild.
- [ ] A flow to a listed destination raises a HIGH finding naming the
      tenant container and destination within one detection cycle.
- [ ] Replaying the cloud#815 flow pattern in a test environment
      produces the finding.
**Priority:** P0

**Story 4: Fence-probe rules (catches cloud#780-class conditions)** (#1642)**.**
As an operator, I want an alert when cross-tenant east-west traffic
occurs, or when one tenant accumulates a burst of policy denies, so that
both a *breached* fence and a *probed* fence are visible.
**Acceptance criteria:**
- [ ] A flow whose source and destination resolve to containers in
      different tenants on the same backend raises a CRITICAL finding —
      the continuous version of the one-shot isolation sentry.
- [ ] ≥ N deny events (default 20) for one tenant within M minutes
      (default 5) raises a MEDIUM "fence probing" finding; N and M are
      operator-tunable.
- [ ] Both rules verified by an e2e test that creates two-org peers and
      probes across them (reusing `cmd/isolation-sentry` scaffolding).
**Priority:** P0

**Story 5: Delivery and triage surface** (#1643)**.**
As an on-call engineer, I want findings pushed to my webhook and
listable from the CLI so that I learn about an incident from my own
platform first and can triage without SSH-ing into backends.
**Acceptance criteria:**
- [ ] MEDIUM+ findings deliver to the existing webhook path with
      recorded delivery status; a dead webhook never blocks detection.
- [ ] `containarium security findings [--severity --tenant --since]`
      lists findings with evidence; works against a remote server.
- [ ] Cloud: findings from all connected backends are visible through
      the shim (aggregation UI is P1; pass-through visibility is P0).
**Priority:** P0

### Rollout prerequisite (not a story)

Detection requires the eBPF object loaded
(`CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT`), which is off by default and
not enabled fleet-wide today. MVP ships with a rollout note: enable
observation mode per backend, measure overhead (Phase A was
hardware-validated), then arm the sentry. Backends without eBPF report
"sentry unavailable" honestly rather than silently detecting nothing —
the cloud#780 lesson is that silent non-verification reads as safety.

## Later phases

- **P1 — Automated response ladder.** Org-freeze primitive
  (cloud#815 follow-up; reversible, unlike today's soft-delete) and
  auto-quarantine wiring for CRITICAL network findings, reusing the
  existing ClamAV→deny-rule hook template
  (`internal/server/auto_quarantine.go`). Gated on 4 weeks of measured
  precision.
- **P1 — Control-plane abuse rules (cloud repo).** Container-create
  velocity on young accounts (12 creates in 19 min from a 2-minute-old
  org was the cloud#815 tell) — CP-side signal the daemon can't see.
- **P1 — Cloud fleet aggregation view.** One pane across backends,
  including BYOC (findings ride the sentinel tunnel; BYOC hosts export
  no metrics by design, so the event path is the transport).
- **P2 — Anomaly scoring.** Reuse the model-gateway anomaly engine
  (EWMA windows, novelty sets, composite score) for "unusual for this
  tenant" detection beyond fixed rules.
- **P2 — Process-level signals.** CPU-pattern + known-miner-binary
  checks inside boxes; today's flow-level view can't see a miner using
  an unlisted pool.

## Out of scope

- **Full IDS integration (Falco/Tetragon/Suricata).** Heavy operational
  dependency per backend; the Tier-2 signature engine is already
  documented as evadable, and rule-based flow detection must prove
  signal quality first. Revisit at P2 with data.
- **Any auto-response in the MVP** — a false positive that freezes a
  paying tenant costs more than a late alert; precision is unmeasured.
- **Attacker source-IP traceability** — real gap, separately tracked as
  a cloud#815 follow-up; different plumbing (proxy-protocol/XFF), not
  this engine.
- **DDoS / volumetric protection** — different problem class and
  mitigations; nothing here should imply we detect or absorb it.
- **Tenant-facing security dashboard** — operator-first; exposing
  findings to tenants raises its own questions (what does a tenant get
  to see about a co-resident probing them?).

## Open questions & assumptions

1. **eBPF observation-mode fleet rollout** — assumed acceptable overhead
   (Phase A hardware-validated). Validate: enable on one low-stakes
   backend, compare host CPU before/after.
2. **BYOC coverage in MVP** — assumed P0 detects locally on any backend
   with eBPF, but cross-backend *visibility* through the cloud shim may
   lag for BYOC. Decide during design whether the tunnel event path is
   MVP or P1.
3. **Bad-destination list sourcing** — MVP assumes a static in-repo list
   is enough to catch commodity miners. Validate against the cloud#815
   IOCs; a refreshing threat feed is a later decision.
4. **Alert destination** — the webhook path exists but where it points
   (Slack? pager?) is operator config; no evidence yet on preferred
   channel.
5. **IPv6** — flow accounting is IPv4-only today; assumed acceptable for
   MVP (tenant egress is effectively v4 in current deployments). Confirm
   before GA claims.
6. **Precision baseline is unknown by definition** — the metric plan is
   instrument-first: run 4 weeks in observe-only, count would-have-paged
   alerts, then set thresholds.
