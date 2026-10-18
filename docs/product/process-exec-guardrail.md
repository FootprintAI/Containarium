# PRD: Process guardrail — detect and contain cryptomining in tenant boxes

**Date:** 2026-10-18
**Status:** draft — P0 stories filed as #2634 #2635 #2636 #2637 #2638 #2639
**Owner:** @hsinatfootprintai

Follows [Continuous threat detection](continuous-threat-detection.md)
(#1645, shipped). That PRD's P1 "automated response ladder" and P2
"process-level signals" are this document.

## Problem

Tenants run cryptominers in their boxes, and the platform neither sees
the miner nor stops it. Two incidents on a hosted deployment of this
daemon had the same shape:

| | 2026-07-11 (cloud#815) | 2026-10-11 (cloud#2438) |
|---|---|---|
| Account age at first box | 2 min | 8 min |
| Boxes | 12 in 19 min | 2 × 8 vCPU in ~10 min |
| Miner | `xmrig`, persistent TLS to a pool | `xmrig`, uploaded over SSH after creation, TCP `:3333` to the same pool |
| Who detected it | the cloud provider, after the mining window | the cloud provider, ~50 min after start |
| Our sentry | did not exist | returned "unavailable on this backend"; the known-bad-destination rule never ran |
| Mining time | hours | ~1 h at ~100 % of 16 vCPU, then 6 h more surviving a failed org freeze (cloud#2451) |

What this costs:

- **Provider suspension risk.** Repeated abuse events on one project can
  take down every tenant on that provider. On BYOC hosts there is no
  provider detector at all; the same attack is invisible.
- **Stolen compute and co-tenant starvation.** A miner pegs every core it
  is given; CPU admission (#1029) assumes tenants are bursty.
- **Hours of human response.** Both incidents were handled by hand:
  find the box, kill the process, freeze, fix firewall rules. The second
  response found that the July egress rules were on the wrong network.

What exists today, and why it was not enough:

- The sentry (#1640) evaluates eBPF **flow** records: known-bad
  destination (#1641), cross-tenant flow and deny burst (#1642). It has
  **no process visibility**: the daemon cannot see what runs in a box.
- The shipped bad-destination list contains only RFC 5737 example ranges
  (`internal/threatdetect/rule_baddest_list.yaml`). Pools are hostnames
  whose IPs change; the stratum port is the durable signal.
- Findings notify and never act (MVP decision in #1645). The only
  auto-response in tree is ClamAV→egress quarantine
  (`internal/server/auto_quarantine.go`).
- cloud#830 researched provider detectors: GCP's is agentless memory
  scanning for miner signatures; AWS GuardDuty is network and DNS based.
  It also named the evasion a CPU threshold alone cannot catch: a miner
  that throttles itself (`xmrig --max-cpu-usage=50`).

**Why now.** The second incident happened with the sentry shipped and the
firewall rules "in place". The gap is not detection sophistication; it is
that nothing on the host sees the process and nothing acts within
minutes. Free signup makes recurrence a matter of weeks.

## Target user

The **platform operator / on-call engineer** running a Containarium
fleet (hosted or self-hosted). Job-to-be-done: *when a tenant starts a
miner, know within minutes from my own platform, have it contained
within minutes without a human, and be able to undo a wrong call.*

Tenants benefit indirectly (co-residents are protected, suspension risk
drops). A legitimate heavy-compute tenant is the main false-positive
risk and shapes the enforcement ladder below.

## Success metrics

| Metric | Baseline | Target |
|--------|----------|--------|
| Time from miner start to our own HIGH finding | Never from us; provider alert 50 min+ after start | < 5 min on every backend with the sentry armed (incl. BYOC) |
| Time from miner start to containment (CPU throttled or box frozen) | Hours, human-driven (1 h + 6 h in cloud#2438) | < 10 min, no human, when the policy is `throttle` or `freeze` |
| Wrong containment of a legitimate workload | Unknown, instrument first (4 weeks in `alert` mode) | < 1 per month fleet-wide; every action reversible with one command |
| Exec-telemetry overhead on a loaded host | n/a | < 1 % CPU at 1,000 execs/s, measured before the rule is armed |

## MVP scope: the core journey

> A tenant uploads a miner into a box and starts it. The host-side eBPF
> exec tracepoint reports the exec with its command line and container.
> Within one detection cycle the daemon raises a HIGH finding, either
> because the exec matched the miner-signature list or because the box
> has run at sustained high CPU with a persistent flow to a stratum port
> or listed pool. The backend's **process policy** decides what happens
> next: `alert` (default) notifies; `throttle` caps the box's CPU
> allowance; `freeze` pauses the box with its state intact. Every action
> is a finding update and an audit row, and
> `containarium security process-policy release <container>` undoes it.
> The operator sees all of it with `containarium security findings` and
> `containarium security exec-events`.

Design constraints the stories inherit:

- **Everything runs on the host.** Tenants have root in their box and
  can kill anything inside it. Telemetry comes from the host kernel
  (eBPF, cgroups); actions go through Incus and host signals.
- **Observe first, then act.** Each rule ships in `alert` mode. A policy
  stricter than `alert` is an explicit operator choice, per backend.
- **Reversible by design.** No action in the MVP destroys state. Throttle
  restores the previous CPU limit; freeze keeps memory and disk for
  forensics (the cloud#2438 response did exactly this by hand).
- **CLI-first.** Every verb is a `containarium security …` subcommand on
  the daemon's gRPC API; MCP and cloud wrap it. Proto first, generated
  stubs, enums not strings.
- **Honest when unavailable.** A backend where the exec tracepoint or the
  sentry cannot run says so in `sentry status` and raises a finding; it
  never reports "no miners" by silence. The second incident ran on a
  backend whose sentry was quietly unavailable.

### P0 stories

**Story 1: The sentry alerts when it is not running where it should be** (#2634)**.**
As an operator, I want an armed backend whose sentry is unavailable or
whose eBPF object is not loaded to raise a finding and show in
`sentry status`, so that an abuse on that host is not invisible by
accident.
**Acceptance criteria:**
- [ ] With `CONTAINARIUM_THREAT_SENTRY=1` and the engine unable to start
      (no eBPF object, load failure, or any rule in error), the daemon
      raises a MEDIUM `sentry-unavailable` finding within 60 s of startup
      and delivers it to the webhook like any other finding.
- [ ] The finding names the reason (the same reason strings
      `containarium security sentry status` prints) and resolves
      automatically when the engine becomes healthy.
- [ ] A backend without the env var set raises nothing (unarmed is a
      choice, not a fault).
**Priority:** P0 · **Size:** S

**Story 2: `mining-behavior` rule over signals the daemon already has** (#2635)**.**
As an operator, I want a HIGH finding when a box runs at sustained high
CPU while holding a persistent flow to a stratum port or a listed pool,
so that the two known incidents are caught with no new telemetry.
**Acceptance criteria:**
- [ ] Rule fires when, for one container, CPU usage ≥ `min_cores`
      (default 1.5 cores) averaged over `window` (default 5 min) **and**
      a flow to a destination port in the stratum set (default 3333,
      4444, 5555, 7777, 14444, 14433) or to a bad-destination entry has
      lasted ≥ `flow_min_age` (default 3 min) within the window.
- [ ] Thresholds and the port set are operator-tunable via
      `containarium security process-policy set --rule mining-behavior …`
      and persisted in the daemon config store; defaults are documented.
- [ ] Evidence on the finding: the CPU series summary, the flow 5-tuple,
      bytes, first/last seen, and the matched port or list entry.
- [ ] A test replays the 2026-10-11 pattern (synthetic CPU samples plus
      a 20-minute flow to `:3333`) and gets the finding within one
      detection cycle; a build job at 100 % CPU with only `:443` flows
      does not fire.
- [ ] Uses `container.cpu.usage_seconds` as already sampled by the
      metrics collector; the rule adds no new polling of Incus.
**Priority:** P0 · **Size:** M

**Story 3: Process policy and the response ladder** (#2636)**.**
As an operator, I want to choose, per backend, what a HIGH mining
finding does (`alert`, `throttle`, `freeze`), and to undo it with one
command, so that containment runs without me and a wrong call costs a
tenant minutes, not data.
**Acceptance criteria:**
- [ ] `ProcessPolicy` proto message with an `action` enum
      (`ALERT | THROTTLE | FREEZE`), a `throttle_allowance` (default
      `10%`), a `ttl` (default 24 h), and per-rule thresholds;
      `Get/SetProcessPolicy` RPCs with grpc-gateway annotations;
      `containarium security process-policy get|set|release`.
- [ ] Default action is `ALERT`. Nothing acts until an operator sets
      otherwise, mirroring the eBPF enforce rollout.
- [ ] `THROTTLE` records the box's current CPU limit and sets
      `limits.cpu.allowance` to `throttle_allowance` via the existing
      `SetCPULimit` path; `FREEZE` pauses the instance through Incus with
      memory and disk kept. Both write an audit row and update the
      finding with the action taken and the time.
- [ ] `release <container>` restores the recorded limit or unfreezes,
      and marks the finding resolved with `remediated=true`. After `ttl`
      with no operator decision the action is released automatically and
      a MEDIUM finding says so (same backstop as auto-quarantine).
- [ ] The same tenant+rule does not re-trigger a second action while the
      first is active (dedupe by open finding).
- [ ] An e2e test on a real Incus backend: start a CPU burner that
      matches the rule, observe the allowance drop within one cycle, run
      `release`, observe the original limit restored.
**Priority:** P0 · **Size:** L

**Story 4: Host-side exec telemetry** (#2637)**.**
As an operator, I want to see every process exec in a tenant box from the
host, attributed to the container, so that rules and humans can tell a
miner from a build.
**Acceptance criteria:**
- [ ] A `sched_process_exec` tracepoint program in the existing eBPF
      object emits `{host_pid, ppid, uid, cgroup_id, comm, argv[0..N],
      exe_path}` to a ring buffer; the loader maps `cgroup_id` to the
      container through Incus's cgroup path and discards host and
      core-infra execs.
- [ ] Events are available in-process to the rule engine and to
      `containarium security exec-events [--container] [--since]`
      (gRPC streaming RPC behind it); they are **not** written to the
      audit log by default (volume), only matched events are.
- [ ] Overhead measured on an 8-core host at 1,000 execs/s: < 1 % CPU
      and no dropped events at 100 execs/s; the numbers go in the
      operator doc.
- [ ] A backend whose kernel cannot attach the tracepoint reports
      `exec-telemetry: unavailable (<reason>)` in `sentry status` and
      Story 1's finding fires; the flow rules keep running.
- [ ] Argv is truncated at 512 bytes per event and never includes
      environment variables.
**Priority:** P0 · **Size:** L

**Story 5: `miner-signature` rule and the `kill-process` action** (#2638)**.**
As an operator, I want a HIGH finding the moment a known miner is
exec'd, matched on binary name, command-line markers, or binary hash,
and the option to kill that process from the host, so that an obvious
miner never gets its first minute of CPU.
**Acceptance criteria:**
- [ ] Ships with a versioned, embedded signature list (same shape as
      the bad-destination list): binary names (`xmrig`, `minerd`,
      `cpuminer*`, `nanominer`, `t-rex`, `lolminer`, `nbminer`,
      `gminer`), argv markers (`--donate-level`, `stratum+tcp://`,
      `stratum+ssl://`, `--coin `, `-o <host>:<stratum port>`), and
      optional SHA-256 of `exe_path` for the current upstream releases.
      Operators add and remove entries via
      `containarium security miner-signatures add|remove|list` without
      a rebuild.
- [ ] A match raises a HIGH finding with the exec event attached within
      one detection cycle (target: < 10 s after exec).
- [ ] The process policy gains `kill_process: true|false` (default
      false). When true, a signature match sends SIGKILL to `host_pid`
      from the host and the box's policy action (`alert|throttle|freeze`)
      still applies. A renamed binary that re-execs is caught by the
      argv or hash entries; the doc states that a rebuilt, renamed miner
      with a clean command line is caught only by Story 2.
- [ ] A test runs a stub named `xmrig` with `--donate-level 1` inside a
      box and asserts the finding, the kill, and the audit row; a stub
      named `gcc` with the same CPU profile raises nothing from this rule.
**Priority:** P0 · **Size:** M

**Story 6: Operator doc and rollout path** (#2639)**.**
As an operator, I want one page that says how to turn this on safely, so
that I arm it in the right order and know what it will and will not
catch.
**Acceptance criteria:**
- [ ] `docs/security/PROCESS-GUARDRAIL.md`: the three rules, the policy
      ladder, the release and TTL semantics, the rollout order (sentry
      armed → 4 weeks `alert` → `throttle` → `freeze`), the measured
      overhead, the evasion limits (self-throttled miner below
      `min_cores`, renamed and rebuilt binaries, pools on `:443`), and
      what a tenant with root can and cannot do about it.
- [ ] CHANGELOG entries per story; `sentry status` output in the doc
      matches the shipped binary.
**Priority:** P0 · **Size:** S

Six P0 stories. Stories 1 to 3 deliver detection and containment of both
known incidents on their own; 4 and 5 are the process-level layer the
title promises and can land in a second sprint without changing the
first three.

## Later phases

- **P1 — Policy by tenant class (cloud repo, cloud#2695).** Default `throttle` for
  free and new orgs, `alert` for paid, opt-in for enterprise and BYOC.
  The daemon exposes the per-container policy override; the cloud sets
  it from plan and account age (cloud#2466 covers signup velocity).
- **P1 — Org-level freeze wiring (cloud repo, cloud#2696).** A HIGH finding on a
  young org escalates to `FreezeOrg` once cloud#2451 makes the freeze
  reliable. Human-confirmed in the first phase.
- **P1 — Hostname-based pool list.** Resolve listed pool hostnames on a
  schedule and feed the IPs into the bad-destination rule, so a pool
  that moves IPs stays listed.
- **P1 — Pools on `:443`.** TLS SNI and JA3 from the egress program;
  needed once miners hide on the web port. Not in the MVP: the two
  incidents used `:3333`.
- **P2 — Binary hash scan on exec.** Hash `exe_path` for every exec
  under a size cap and match a larger hash feed (the provider's approach
  in memory, ours on disk). Cost and feed licensing unclear.
- **P2 — GPU miners.** GPU utilisation is not sampled today; add it when
  GPU boxes are common enough to be worth mining on.

## Out of scope

- **An agent inside the box.** The tenant has root there and can stop it;
  anything that must survive the tenant lives on the host.
- **Falco, Tetragon or another full runtime-security stack.** A per-host
  operational dependency for one tracepoint and three rules; the
  existing eBPF object already carries the loader, maps and rollout
  story. Revisit if the rule set grows past what a small engine can hold.
- **Blocking the upload of binaries.** Tenants must be able to bring
  their own software; the control is what runs and what it does, not
  what is on disk.
- **ML or anomaly scoring.** Three explainable rules first; the
  model-gateway anomaly engine can be reused at P2 with data.
- **Destroying state as a response.** Delete is never automatic; freeze
  keeps forensics and the human decides.
- **Signup abuse and account velocity.** Control-plane signal the daemon
  cannot see; cloud#2466.

## Open questions & assumptions

1. **Terms** (cloud#2697)**.** Assumption: the hosted service's terms allow throttling or
   freezing a workload identified as mining, and self-hosters set their
   own. Validate with whoever owns the terms before the default for any
   tenant class moves past `alert`.
2. **Default thresholds.** `min_cores` 1.5 over 5 min with a 3 min
   stratum flow is chosen from the two incidents, not from fleet data.
   The 4-week `alert` period exists to tune it; a build farm tenant with
   a `:3333` service is the false positive to look for.
3. **Freeze semantics under Incus.** Assumption: `freeze` on a running
   container is reliable and the instance survives a daemon restart in
   the frozen state. cloud#2451 saw slow stops under freeze; verify
   during Story 3 on a real backend before `FREEZE` is documented.
4. **cgroup mapping on hosts with the unprivileged runtime (#2084,
   #2150).** Assumption: the container's cgroup path is stable across
   privileged and unprivileged modes. Check during Story 4.
5. **Who owns the signature list.** Assumption: the repository ships a
   baseline and operators extend it locally; no central feed. If a feed
   is wanted, it is the cloud's to publish.
6. **Kill-process on the first offender.** Decided 2026-10-18 (cloud#2697):
   `kill_process` defaults **off everywhere**, including the hosted free
   tier; it is turned on only per org by an audited operator override.
   A false positive kills a tenant's process with no undo, while
   throttle and freeze are reversible.
