# PRD: Application-domain metrics in cloud-provider monitoring

**Date:** 2026-07-24
**Status:** draft
**Owner:** devops (platform operator)

## Problem

The v0.60.0 cloud-native export (#1069/#1070) put **host infra** series
(load/memory/disk/container-count) into GCP Cloud Monitoring, and #1071/#1072
extend that to per-container infra and a heartbeat. But an operator running
Containarium backends on GCP still cannot answer platform-level questions from
the provider's console:

- *"Are container creates succeeding right now?"* — requires SSH + journalctl
  or the host-local VictoriaMetrics dashboards.
- *"Is the API erroring? Are BYOC peers connected?"* — same; and the BYOC
  CONNECTED-while-dead incident class (#903-era) showed that in-band health
  reporting can lie precisely when it matters.
- Tenant workloads that emit OTLP app metrics land only in the host-local
  VictoriaMetrics LXC; an operator watching GCP sees none of it.

Today the operator context-switches between GCP Console (host infra), per-host
VictoriaMetrics/vmalert, the cloud dashboard, and SSH. Each surface covers a
slice; only the host-local stack sees everything — and it fate-shares with the
host it monitors. Evidence: the host-local stack was the blind spot in real
incidents (incus wedge stopping `incus list`-backed reporting; disk-full
feedback loops), and the out-of-band export exists because of exactly that
failure class.

**Who hurts:** the platform operator on every incident triage and every
routine "is the fleet OK?" check. **Cost:** minutes of context-switching per
check, and platform failures (provisioning broken, tunnel down) that are
invisible in the provider console where the operator's alerting already lives.

## Target user

Platform operator (devops) running one or more Containarium backends on GCP,
who already lives in GCP Cloud Monitoring for the rest of their estate.
Job-to-be-done: see Containarium platform health — not just VM health — in the
same console, and alert on it out-of-band.

## Success metrics

| Metric | Baseline | Target |
|--------|----------|--------|
| Platform failure classes alertable from GCP (create-failure, API 5xx burst, BYOC peer disconnect, export stall) | 0 of 4 (only host death via #1072 absence) | 4 of 4 |
| GCE backends with export enabled | 2 of 2 primaries (host group only) | all groups enabled on all GCP backends |
| "Fleet OK?" check answerable from the GCM dashboard alone (no SSH) | no — platform state invisible | yes for the P0 series set |
| Billed GCM samples per host per day | ~11.5k (8 series × 1440) | ≤ 3× current with platform group on (hard cap via allowlist review) |

## MVP scope — the core journey

> An operator opens the existing "Containarium Hosts" dashboard in GCP
> Cloud Monitoring and sees, per backend, alongside host infra: API
> error rate, container-create success/failure, and connected-peer
> count — and can build a GCM alert on any of them. No SSH, no
> host-local dashboard.

The MVP is **platform-domain metrics only** (Phase A). Tenant app metrics are
Phase B (below) — they have cardinality/privacy problems the platform group
doesn't, and the core journey doesn't need them.

**Story 1 — metric groups (foundation & cost control).**
As an operator, I want export organized into named groups (`host`,
`container`, `platform`; later `apps`) that I can enable independently, so the
billed sample surface stays a deliberate choice.
**Acceptance criteria:**
- [ ] `monitoring export enable --provider gcp --groups host,platform` (and
  the RPC equivalent) enables exactly those groups; omitting `--groups` keeps
  today's behavior (host).
- [ ] `monitoring export status` lists enabled groups.
- [ ] Groups are typed in proto (enum/repeated), not strings; persisted and
  restart-resumed like the existing toggle.
- [ ] Golden test pins the exact series set per group (the billed surface is
  reviewable in one file, same rule as #1070).
**Priority:** P0

**Story 2 — API health series.**
As an operator, I want `containarium.platform.api.requests` and
`.api.errors` (counters, labels: `backend_id`, plus coarse `code_class`
2xx/4xx/5xx), so an API error burst is visible and alertable in GCM.
**Acceptance criteria:**
- [ ] Series appear in GCM within 2 intervals of enabling the `platform` group.
- [ ] A forced 5xx on the daemon increments `.api.errors{code_class="5xx"}`.
- [ ] No per-route, per-user, or per-org labels (cardinality/allowlist test).
**Priority:** P0

**Story 3 — provisioning outcome series.**
As an operator, I want `containarium.platform.provision.attempts` /
`.failures` counters and a `.duration_seconds` histogram-or-gauge for
container create/delete, so "creates are silently failing" (the phantom-state
incident class) fires an alert instead of waiting for a user report.
**Acceptance criteria:**
- [ ] A successful create increments attempts; a failed create increments
  attempts + failures, visible in GCM.
- [ ] Labels: `backend_id`, `operation` (create|delete) only.
- [ ] GCM alert recipe documented: failures > 0 for 10 min.
**Priority:** P0

**Story 4 — connectivity series.**
As an operator, I want `containarium.platform.peers.connected` (gauge) and
`containarium.platform.tunnel.state` per registered peer (gauge 0/1, label
`peer_id`), so a BYOC peer drop is visible in GCM even though the peer itself
can't export (BYOC hosts have no GCP identity — #1078).
**Acceptance criteria:**
- [ ] Stopping a peer's tunnel flips its `tunnel.state` to 0 within 2
  intervals; reconnect flips it back.
- [ ] `peer_id` is the enrolled host name, never an org/tenant identifier.
**Priority:** P0

**Story 5 — dashboard + quickstart extension.**
As an operator, I want the platform group on the existing GCM dashboard and
in the #1073 quickstart, so the single pane of glass is the documented
default, not a hand-built artifact.
**Acceptance criteria:**
- [ ] Dashboard JSON (committed, reproducible) includes API errors,
  provision failures, peers connected.
- [ ] Quickstart shows enabling both groups and creating one platform alert.
**Priority:** P0

## Later phases

**Phase B (P1) — tenant app metrics (`apps` group).** Forward the OTLP app
metrics that monitoring-enabled containers already emit (container →
core-otelcollector → VictoriaMetrics) into GCM. Deliberately deferred because
it inverts every MVP property: cardinality is tenant-controlled (billing risk
in the operator's project), series names are arbitrary (no golden allowlist),
and tenant data lands in the operator's GCP project (privacy/positioning
question). Pre-requisites to promote to a sprint: a hard per-container series
cap + drop counter, label scrubbing reusing `DefaultOTelDropLabels` intent,
and per-container (not per-host) opt-in tied to the existing
`monitoring_enabled` flag.

**P1 — export self-health in-band.** `containarium.export.dropped_series`,
`.export.push_errors` as part of the platform group (distinct from #1072's
heartbeat) so cost caps and failures are observable.

**P2 — #1080 dependency.** Label identity for resumed collectors must be
fixed before platform alerts key on `backend_id`; until then the dashboard
excludes `backend_id="local"`.

## Out of scope

- **Export to a tenant-owned GCP project** — that's a tenant-facing product
  (auth, isolation, billing hand-off), not this operator tool. Needs its own
  PRD if wanted.
- **AWS sink** — provider enum reserves it; nothing here is GCP-coupled
  beyond the sink, but scoping AWS now doubles test surface for zero current
  users.
- **Logs and traces** — this is metrics-only; GCP log export is a different
  pipeline (Ops Agent / log router) with different cost mechanics.
- **Replacing the host-local VictoriaMetrics stack** — the in-band pipeline
  stays authoritative for the cloud dashboard and high-cardinality history;
  export remains an out-of-band allowlisted subset.

## Open questions & assumptions

- **Assumption:** the daemon already tracks (or can cheaply derive) API
  request/error counts and provisioning outcomes from existing code paths;
  if a counter has to be added at the handler layer, Story 2/3 estimates grow.
  Validate in `/architect:design`.
- **Assumption (evidence gap):** "single pane of glass" demand is the
  operator's own (this PRD's requester); no external-user evidence yet. The
  OSS quickstart (#1073) adoption will be the first external signal.
- **Open:** cost ceiling per host — is 3× current samples the right cap, and
  do we enforce it in code (interval floor + series count) or in review only?
- **Open:** should `container` group (#1071) and `platform` group ship in the
  same release to make the groups UX land once?
- **Open (Phase B):** per-container series cap number, and whether `apps`
  export requires org-admin consent in the cloud CP, not just the operator.
