# Threat-Detection Sentry Operator Guide

The threat-detection sentry is a background engine inside the daemon that
watches the eBPF flow/deny signals already collected by the network-policy
enforcer and raises typed **security findings** — mining-abuse egress,
cross-tenant fence breaches, and fence-probing deny bursts — without a
scan schedule or a separate process. Every rule raises a finding and
alerts. Only a HIGH mining-behavior finding can also act on its container:
the process responder applies the operator-set process policy, which is
`ALERT` (record and notify, touch nothing) unless an operator sets
`THROTTLE` or `FREEZE`. See [Process policy](#process-policy-what-a-mining-finding-does).

For the architecture and design rationale, see
[`docs/architecture/continuous-threat-detection.md`](architecture/continuous-threat-detection.md).
This guide is the operator-facing "how do I turn this on and use it" doc.

## Architecture

```
eBPF flow poll (15s) / deny events ──▶ NetworkPolicyEnforcer
                                          │  SetFlowHook / SetDenyHook
                                          ▼
                                    threatdetect.Engine
                                      • bad-destination rule   (HIGH)
                                      • cross-tenant-flow rule (CRITICAL)
                                      • deny-burst rule        (MEDIUM)
                                      • mining-behavior rule   (HIGH)
                                          │
                                          ▼
                                    FindingStore (Postgres)
                                      • events.Bus  (SubscribeEvents)
                                      • audit hash chain
                                      • WebhookNotifier ──▶ operator's webhook
                                          │
                                          ▼
                      containarium security sentry status / findings
                      MCP: security_sentry_status / list_security_sentry_findings
```

## Enabling the sentry

Set `CONTAINARIUM_THREAT_SENTRY=1` and restart the daemon. Off by default,
same opt-in convention as the platform's other security features.

Prerequisites:

- The eBPF network-policy object must be loaded
  (`CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT` set) — the sentry runs in
  **observation mode**, so `CONTAINARIUM_NETWORK_POLICY_ENFORCE` does
  **not** need to be set. Detection works on a fleet that hasn't turned on
  enforcement yet.
- A working audit store (Postgres) — every finding rides the tamper-evident
  audit hash chain unconditionally, so no audit store means no sentry, not
  a degraded one.
- Postgres for `FindingStore` itself is optional but recommended: without
  it the sentry runs **DEGRADED**, backed by a bounded in-memory ring
  instead of persisted rows — findings still flow to the event bus, the
  audit chain, and the webhook, but they do not survive a daemon restart.

## The detection rules

| Rule | Severity | Fires when |
|------|----------|------------|
| Known-bad destination | HIGH | A flow's destination matches the embedded (versioned, mining-pools-first) or operator-added bad-destination list. |
| Cross-tenant flow | CRITICAL | A flow's source and destination resolve to containers in *different* tenants on the same backend — the continuous form of the one-shot isolation check. Never fires on an IP it can't attribute to a tenant. |
| Mining behavior | HIGH | A container's mean CPU over `window` (default 5 min) is at least `min(min_cores, min_fraction_of_limit × limits.cpu)` (defaults 1.5 cores and 0.75; a box with no CPU limit uses `min_cores` alone) **and** it holds a flow, at least `flow_min_age` (default 3 min) old and seen within the window, to a stratum port (default 3333, 4444, 5555, 7777, 14444, 14433) or to a listed bad destination on any port. Subject is the destination `ip:port`, so a second pool opens a second finding. Evidence: a CPU summary (mean, peak, window, samples) and the flow, with its first/last seen (anchored on the flow poll that reported it, since kernel flow stamps are monotonic) and what matched it (`port:<n>` or `bad-destination:<cidr>`). CPU samples come from the metrics collector's tick when one runs, otherwise from a standalone sampler in the daemon that reads each container's CPU counter every 30 s, so the rule does not need VictoriaMetrics. `containarium security sentry status` shows which source is active on its `cpu-sampler:` line. Thresholds are persisted in the daemon config store under `threatdetect.mining_behavior.thresholds` (protojson of `MiningBehaviorThresholds`; a zero field keeps its default) and are written with `containarium security process-policy set --rule mining-behavior` (see [Process policy](#process-policy-what-a-mining-finding-does)). |
| Miner signature | HIGH | A process exec in a box matches the miner-signature list (#2638): a known miner's binary name (basename or comm, exact or glob, case-insensitive), a command-line marker (`--donate-level`, `stratum+tcp://`, `-o <host>:<stratum port>`, …), or an operator-added SHA-256 of the executable. Fires on the exec itself, within one detection cycle. Subject is `<kind>:<pattern>` of the entry that hit; evidence is the exec (pid, ppid, uid, comm, path, argv, and the hash when computed). See [Miner signatures and kill-process](#miner-signatures-and-kill-process). Needs exec telemetry. |
| Deny burst | MEDIUM | A tenant accumulates ≥`CONTAINARIUM_THREAT_DENY_BURST_N` (default 20) policy denies within `CONTAINARIUM_THREAT_DENY_BURST_WINDOW_MINUTES` (default 5) minutes. Both tunable per operator, without a daemon rebuild — set the env var and restart. **Counts enforced drops only** by default: a would-deny from a tenant whose policy is only observed (`log_only`) is not counted, so enabling the sentry on an observation-only host does not raise "fence probing" findings for ordinary egress. Set `CONTAINARIUM_THREAT_DENY_BURST_COUNT_LOG_ONLY=1` to count those too. |

Two further finding types are not detection rules. They are raised by the
daemon itself and appear in the same findings list:

| Finding | Severity | Raised when |
|---------|----------|-------------|
| `SENTRY_UNAVAILABLE` | MEDIUM | The sentry is armed (`CONTAINARIUM_THREAT_SENTRY` set) but not running cleanly: status is `UNAVAILABLE` or `DEGRADED`, or any rule is unhealthy; it is also raised when status is `OK` but the `cpu-sampler:` line starts with `unavailable`, in which case its subject is `cpu-sampler unavailable`. The health loop only runs when a finding store exists, so it does not fire when the audit store (Postgres) is down. It is backend-level (no tenant or container), its subject is the status reason, and it resolves itself once status returns to `OK`. It is raised by a separate health loop, not a rule, because a rule cannot run when the engine is missing or broken. |
| `PROCESS_ACTION_EXPIRED` | MEDIUM | A throttle or freeze reached its TTL with no operator decision and was released automatically. Subject is the container name. |

A rule firing repeatedly for the same `(rule, tenant, subject)` dedupes
into one open finding with an updated count, rather than creating a new
row or re-alerting on every repeat.

### Soak first on an observation-only fleet

With `CONTAINARIUM_NETWORK_POLICY_ENFORCE` unset the enforcer logs every
flow that no allow-list covers as `deny ... log_only (not dropped)` and
nothing is dropped. Before enforcing, and before trusting deny-burst:

1. Run observation-only and review the would-deny volume per tenant in the
   daemon journal. Expect it to be large on a fleet with no curated
   allow-lists: one line per flow, so hundreds of lines per tenant per
   minute is possible, and journald growth of tens of MB per day on a busy
   host. `netbpf: perf ring lost N samples` means the event stream is
   incomplete at that volume.
2. Curate each tenant's allow-list until the would-deny volume reflects
   traffic you actually want blocked.
3. Only then enable enforcement. From that point the deny-burst rule counts
   the drops, and a burst is a real signal.

## Process policy: what a mining finding does

By default a finding only alerts. The process responder changes that for
HIGH `mining-behavior` findings only; no other rule's findings are acted
on. The action is chosen by the effective policy, resolved as a
per-container override, then the backend default, then the built-in
`ALERT` with a `10%` allowance and a 24 h TTL. The merge is per field, so
an override that sets only `action` still inherits the backend default's
allowance and TTL.

| Action | Effect on the container |
|--------|-------------------------|
| `alert` | Record the finding and notify. Nothing is done to the box. This is the default. |
| `throttle` | Record the box's current `limits.cpu` and `limits.cpu.allowance`, then set `limits.cpu.allowance` to the policy's throttle allowance, applied as a hard CPU quota: `N%` becomes `Nms/100ms`, and `Nms/Mms` is used as given. A box already limited below that quota keeps its tighter limit. |
| `freeze` | Pause the instance through Incus (cgroup freezer). Memory and disk are kept; no process runs until released. |

Every action is reversible and none destroys data. An applied action is
released by an operator, or by the TTL backstop, which also raises a
`PROCESS_ACTION_EXPIRED` finding so an unattended throttle never silently
becomes permanent. The finding's `response` records what was done and when.
On a backend whose finding store has no Postgres (`DEGRADED`), the
responder applies `ALERT` whatever the policy says, and status reports
"responses disabled".

```bash
containarium security process-policy get [--container <name>]
containarium security process-policy set --action throttle --throttle-allowance 10% --ttl 24h
containarium security process-policy set --action freeze --container <name>
containarium security process-policy set --container <name> --clear-override
containarium security process-policy set --rule mining-behavior --min-cores 2 --stratum-ports 3333,4444
containarium security process-policy release <container>
```

`--action` is `alert`, `throttle` or `freeze`; `--throttle-allowance` is
`N%` or `Nms/Mms`; omitted fields inherit. The mining-behavior thresholds
are backend-wide and cannot be combined with `--container`. `set` and
`release` are admin-only. Run `containarium security process-policy set
--help` for the full flag list. REST: `GET`/`PUT /v1/security/process-policy`
and `POST /v1/security/process-policy/release`.

MCP equivalents: `security_process_policy_get`,
`security_process_policy_set` and `security_process_policy_release`.

For the guardrail design and operating detail, see
[`docs/security/PROCESS-GUARDRAIL.md`](security/PROCESS-GUARDRAIL.md)
(added by PR #2716; the link resolves once that PR merges).

## Reading sentry status

```bash
containarium security sentry status
```

Reports one of four states:

| State | Meaning | Operator action |
|-------|---------|------------------|
| `DISABLED` | `CONTAINARIUM_THREAT_SENTRY` is unset — the engine was never constructed. | Set the env var and restart, if detection is wanted on this backend. |
| `UNAVAILABLE` | Enabled, but the eBPF object isn't loaded or the audit store is down. Nothing is being detected — never confused with "no findings." | Fix the missing prerequisite (load the eBPF object / restore Postgres connectivity), then restart. |
| `DEGRADED` | Running, but `FindingStore` has no Postgres connection — findings don't survive a restart. | Restore Postgres connectivity if persistence matters; otherwise no action needed. |
| `OK` | Running normally with Postgres-backed persistence. | None. |

`status` also lists every registered rule's health — a rule that
panicked shows `healthy=false` with its last error, while the engine and
every other rule keep running unaffected.

Two more lines report the signal sources that feed the rules: `cpu-sampler`
(#2645) and `exec-telemetry` (#2637, below). Each reads `ok` /
`metrics-collector` / `standalone (30s)` when the source runs, or
`unavailable (<reason>)` when it cannot; an `unavailable` source on an armed
backend raises the MEDIUM `SENTRY_UNAVAILABLE` finding with the stable
subject `cpu-sampler unavailable` or `exec-telemetry unavailable` (the
reason is in the finding's evidence note), resolved when the source
recovers. `exec-events-lost: N` appears when the kernel had to drop exec
events because the ring buffer was full (a counter, not a fault).

Add `--json` for the raw response. MCP equivalent: `security_sentry_status`
(no arguments).

## Exec telemetry (process guardrail)

Since #2637 the daemon also watches **process execs** in tenant boxes from
the host, with a second eBPF object (`execwatch.bpf.o`) on the
`sched/sched_process_exec` tracepoint. Tenants have root in their box, so
nothing inside it is trusted to report; the kernel filters in-kernel by the
container's cgroup, so host and core-infra execs are never emitted. Each
event carries the host pid/ppid/uid, the executable path and the argument
vector (capped at 512 bytes, **never** the environment), attributed to the
container. Events feed rules that implement `ExecConsumer` (the
miner-signature rule, #2638) and a live stream; they are **not** written to
the audit log — only matched findings are.

```bash
# the last five minutes of execs across all boxes (the daemon's in-memory buffer)
containarium security exec-events

# one box, live
containarium security exec-events --container box-a --follow

# machine-readable, one ExecEvent JSON per line
containarium security exec-events --since 1h --json
```

Output, one line per exec:

```
2026-10-19T05:07:18Z  box-a  pid=4242 ppid=4100 uid=1000  /tmp/.x/xmrig  ./xmrig -o pool:3333
```

Requirements and failure mode: the exec object needs kernel ≥ 5.8 (ring
buffer; 5.6 for the cgroup-ancestor helper) and kernel BTF
(`/sys/kernel/btf/vmlinux`) for its CO-RE reads — Ubuntu 22.04 and 24.04
LTS have both. The object is resolved from the same
`CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT` value as the network-policy object
(`embedded`, or the sibling `execwatch.bpf.o` of a netpolicy object path).
When it cannot be loaded or attached, `sentry status` reports
`exec-telemetry: unavailable (<reason>)`, `exec-events` fails with the same
reason, the `SENTRY_UNAVAILABLE` finding fires on an armed backend, and
**the flow rules keep running** — the two objects are independent.

Overhead, measured by `TestExecWatch_OverheadMeasurement` in the eBPF
loading lane: a separate process fork+execs `/bin/true` at a steady 1,000/s
for 60 s inside a watched cgroup; the program's cost is its own run time
(`BPF_STATS_RUN_TIME`) and the consumer's is the consuming process's CPU. The
kernel submits records without a wakeup and the daemon drains the ring every
50 ms in one batch (#2774), so an exec event reaches the rules at most
~50 ms later than it happened. On the 4-CPU lane runner (2026-10-20): 1,000
execs/s, **0 events lost**, kernel ~1.5 µs per exec plus the consumer, about
**0.1 % of the host** in total. The same run with the old per-event wakeup
cost ~0.7 % of the host; on an 8-vCPU KVM guest that shape had cost ~7 %,
which is why the acceptance number is re-measured on the sprint's
verification guest. Pair the object with the daemon: an `execwatch.bpf.o`
built before #2774 still loads on this daemon (its events are drained by the
timer, it just keeps the per-record wakeup cost), but an object built from
#2774 on needs a daemon from #2774 on — an older daemon blocks in an
`epoll_wait` the kernel never wakes, the ring fills, and `exec-telemetry`
still reports `ok` while `exec-events-lost` climbs.

**Ring capacity and floods.** One 4 MiB ring serves every watched box on
the host and holds ~5,090 events. The daemon drains it every 50 ms, and
immediately again while a drain returns 256 or more events, so a sustained
host-wide rate above ~5,000 execs/s is drained continuously. A host-wide
burst of more than ~5,090 execs inside one 50 ms interval (~100,000 execs/s)
overflows the ring: the excess events are **dropped and counted** in
`exec-events-lost`, the execs themselves are never blocked. A tenant can
cause this deliberately, flooding execs to hide one exec among the dropped
ones, so **alert on `exec-events-lost` increasing**: a non-zero delta means
the exec rules did not see every exec in that window. In the lane, 10,000
undrained execs keep exactly the ring's capacity and count the rest lost,
with no crash.

## Miner signatures and kill-process

The miner-signature rule (#2638) matches every exec the exec telemetry
reports against a signature list: the embedded, versioned baseline merged
with operator entries. Three matcher kinds:

| Kind | Matches | Example |
|------|---------|---------|
| `name` | basename of the exec'd file, and the task comm; exact or glob, case-insensitive | `xmrig`, `cpuminer*` |
| `argv` | the joined command line: a literal substring (case-insensitive), or, with a glob character, space-separated globs over consecutive arguments (option tokens such as `-o` case-sensitive, the rest not) | `--donate-level`, `-o *:3333` |
| `sha256` | hex SHA-256 of the executable (`/proc/<pid>/exe`) | operator-added only |

The baseline ships `name` and `argv` entries only (xmrig, minerd,
cpuminer*, nanominer, t-rex, lolminer, nbminer, gminer; `--donate-level`,
`stratum+tcp://`, `stratum+ssl://`, `--coin `, `--coin=*`, and for each
default stratum port `-o <host>:<port>`, `-o<host>:<port>`, `--url <host>:<port>`
and `--url=<host>:<port>`). It carries **no hashes**: a hash list goes stale with
every upstream release. Add your own hashes for builds you have seen; the
daemon hashes an executable only when such entries exist and no name or
argv entry matched, off the exec path (64 MiB cap, 200 ms budget, best
effort: a process that exited first is not hashed).

```bash
containarium security miner-signatures list
containarium security miner-signatures add --kind name --label SRBMiner 'srbminer*'
containarium security miner-signatures add --kind argv -- '--algo randomx'
containarium security miner-signatures add --kind sha256 <64 hex chars>
containarium security miner-signatures remove --kind name 'srbminer*'
```

Additions take effect immediately and persist in the daemon config store
(`threatdetect.miner_signatures.operator`); baseline entries cannot be
removed. Adding and removing need `security:write` and the admin role.

**What a match does.** A match always raises the HIGH finding, and the
box's process policy applies as for any mining finding: alert (default),
throttle or freeze (`containarium security process-policy`). With
`kill_process` set, the daemon also sends SIGKILL to the matched process
from the host:

```bash
containarium security process-policy set --kill-process=true                     # backend default
containarium security process-policy set --container box-a --kill-process=false  # one box opts out
```

`kill_process` defaults to **false** at every level and is never turned on
for you; unset inherits from the backend default. **`kill_process` is
Incus-only.** On any other container runtime (the box's init has no Incus
payload cgroup, `lxc.payload.<name>`) the daemon cannot confirm a pid
belongs to the box, so it refuses every kill up front: the finding is still
raised and the policy action still applies, and the response reads `kill
skipped: RUNTIME_UNSUPPORTED` (audit `kill-skipped`, reason
`kill_process is Incus-only`). Before the kill the
daemon pins the process with a pidfd (no pidfd, no kill), re-reads
`/proc/<pid>/cgroup` and confirms it is still under the container's cgroup,
so a pid reused by another process, on the host or in another box, is never
signalled. It then compares the pinned process's start time
(`/proc/<pid>/stat` field 22) with the one the exec watcher read when it
decoded the matched exec, so a pid reused by another process inside the
same box is not signalled either; an exec whose process had already exited
when it was decoded has no start time and is never killed. The container's
init is never killed. Every attempt is audited
under `security.action`: `kill` names the pid and start time, `kill-skipped`
gives the reason (`pid reused`, `start time unknown`, `process already
exited`, `kill_process is Incus-only`, …). The finding's response
shows `process killed (pid <host pid>, kills <n>)`, or `kill skipped:
<reason>` when the last attempt did not happen, and an action row opened by
the same finding records `killed_pid`. The kill and the throttle/freeze run on the responder's own
worker, never on the exec event path; if its queue (256) is full the
response is dropped, logged and audited as `response-dropped`. Before
acting, the worker re-reads the finding and the box's own action for that
finding: a response whose finding was resolved, or whose box had that
action released (by an operator or the TTL backstop) after the response was
queued, is left alone and audited as `response-skipped`, so a queued
response never undoes a release. A release of a different finding's action
on the same box does not count, and a store read that fails does not skip
the response (only a definite release or resolve does). A signature finding
is per tenant and pattern, so two boxes of one tenant running the same miner
share one finding; a release counts only for the box it was made on.
Releasing box A does not cancel box B's queued response, and while B still
holds the finding (an action open on B, or B's response still queued) the
release leaves the shared finding open (the `release` audit row says
`finding_kept_open=true`, the release response carries
`finding_kept_open`, and `containarium security process-policy release`
prints `Finding #N kept open: another box still has a response`);
releasing the last box resolves it. An action already applied on B holds
the finding open as much as a queued response does: releasing A never
resolves the finding while B is still throttled or frozen. If B's queued
response then ends
without an action (an ALERT policy or override, a policy read error, a
failed apply, a degraded backend, or a skip), the worker resolves the
finding itself (audited `resolve`), so a kept-open finding never outlives
the last response. The same holds when B's action ends without a release:
if B's TTL expires, the orphan sweep undoes B's never-confirmed apply, or B
is deleted, the write that records B's end also resolves the finding
(audited `resolve`, one post carrying B's record with finding `state: 2`).
That only finishes an operator's release on another box, and only while
that release is still the latest action on its box: if A was throttled
again after its release, A's release no longer counts, and when the
finding then ends by TTL or deletion with no operator involved it stays
open for you, as a single box's expiry always has. Every delete the daemon
makes (`containarium delete` and the TTL sweeper, cloud-managed boxes,
sandboxes) closes the deleted box's open action in the background, without
undoing anything on the box and without failing the delete (the delete
makes one extra Incus lookup), `released_by: container-deleted`, so the deleted box no longer holds the finding or shows
as `APPLIED`. A box removed outside the daemon (for example with `incus
delete`) keeps its action open until the action's TTL, the orphan sweep or
an operator release, which then finds the box missing, or replaced by a
new box with the same name, and closes the action without touching the new
box's limits. Until then a new box with that name gets no action of its
own; `process-policy release <box>` clears it at once. An apply that was recorded but never
confirmed (the daemon died between the two) on box B also holds the
finding open, since the throttle may have taken effect, but it is never
shown as `APPLIED`: releasing A then records A's `RELEASED`. The orphan
sweep ends such a row 5 minutes after it was recorded (up to one more
minute for the sweep), which bounds how long it can hold the finding.
The shared finding's response names the box it is about
(`findings list` prints `response THROTTLE APPLIED on box-b`; `--json` has
`response.container`). While any box still holds an applied action the
response is that box's `APPLIED` record, so releasing A, or A's TTL
expiring or apply failing, does not make the finding read `RELEASED`,
`EXPIRED` or `FAILED` while B is throttled; A's own release record is in
the `released` field of the release response (and is what the CLI's
`Released ... on box-a` line describes) and on the webhook. The
`process killed` flag is per finding: once any box's
process was killed it stays set, whichever box is released or expires
after. Resolving the finding by hand skips every box's queued response. On
a degraded backend (no Postgres) responses are off, the kill included.

**Limits.** A rebuilt, renamed miner with a clean command line matches no
name or argv entry, and a fresh build matches no hash: only the
mining-behavior rule (sustained CPU plus a stratum flow) catches it. The
rule sees the exec, not later renames inside the process.
Argv markers are matched against the real argument vector (the
NUL-separated argv the kernel records), not the space-joined line. A
literal marker must begin an argument, or the value of an option argument
`--opt=value`; a space in a marker is an argument boundary (`--coin ` is the
argument `--coin` followed by another). A marker that only appears inside an
argument is not a match: `git commit -m "document stratum+tcp:// pool
format"` raises nothing. An argument that *begins* with a marker matches
whatever the command, and there is no command allowlist: `grep -r
--donate-level docs/` (the argument `--donate-level`) and `grep
--regexp=stratum+tcp:// .` raise the finding, and with `kill_process` the
grep is killed. Keep that in mind before turning the kill on for boxes where
people inspect miner configs. A glob marker matches consecutive whole
arguments the same way. A glob token without `=`
never matches a `key=value` argument, so ssh's `-o ProxyJump=bastion:4444`
does not hit the `-o <host>:<port>` markers, and `-o` is case-sensitive, so
`cc -O ...` is not a match. Pool addresses in other spellings (a config file,
`--url` with a scheme other than stratum, a non-default port) are a known
gap here; the mining-behavior rule covers them by CPU and flow.

Two known false positives remain in the baseline's port markers, because
they match a host-and-port shape without knowing what the option means:

- `curl -ofile:3333 …` (curl's `-o` writes to the file `file:3333`)
  matches `-o<host>:<port>`.
- A scheme-less `--url=localhost:4444` on any tool matches
  `--url=<host>:<port>`, although nothing about it is a pool.

Both raise the HIGH finding and, with `kill_process`, kill the process. If
a box legitimately runs such a command, leave `kill_process` off for it
(`process-policy set --container <box> --kill-process=false`).

The kill and policy action run on the responder's queue, so a little time
can pass between the exec and the kill. The cgroup re-check stops a pid
reused by another box or the host, but a pid reused by another process in
the *same* box within that window would be killed; a process start-time
check to close it is a follow-up (#2765).

## Triaging findings

```bash
containarium security findings [--severity --tenant --since --state --limit]
```

`findings` with no subcommand lists (an explicit `findings list` alias
runs the identical thing). Filters, all optional:

| Flag | Values |
|------|--------|
| `--severity` | `low`, `medium`, `high`, `critical` |
| `--tenant` | Tenant id — admin-only; a non-admin caller always sees their own tenant regardless of this flag. |
| `--since` | RFC3339 timestamp; only findings last seen at or after this time. |
| `--state` | `open`, `resolved` |
| `--limit` | Max rows (server default 50, cap 200). |

Resolve a finding once handled:

```bash
containarium security findings resolve <id>
```

MCP equivalents: `list_security_sentry_findings` (same filter arguments)
and `resolve_security_sentry_finding` (`id`).

> **Naming note:** this is distinct from the pre-existing
> `containarium security-findings <username>` (hyphenated) command, which
> lists ClamAV/pentest/ZAP scanner findings for one container — an
> unrelated, older surface. `security findings` (space-separated
> subcommand) is the sentry findings covered by this guide.

## Configuring webhook delivery

MEDIUM+ findings deliver asynchronously to the operator's configured
webhook — the same `alert_webhook_url` / `alert_webhook_secret`
configuration and HMAC-SHA256 signing scheme the existing alert-webhook
relay uses (see [ALERTING-SETUP.md](ALERTING-SETUP.md)), so there is
nothing new to configure if alerting is already set up. Delivery
deliberately bypasses the vmalert/alertmanager pipeline — a direct POST
works on any backend, including a minimal BYOC host with no
VictoriaMetrics container.

Every delivery attempt (success or failure) is recorded in the same
`alert.DeliveryStore` the existing relay uses — a dead or slow webhook
never blocks detection; delivery is downstream of persistence, not the
hot path.

A finding is delivered when it is new, when its severity escalates, when
the process responder's response on a box changes, and once more when it
resolves.

`response.container` names the box a response is about. Every post that
carries a response names the same box in its top-level `container`, with
one exception: a post caused by a re-fire of the finding (the hourly
re-notify, or a held-back kill delivered by the finding's next write, see
below) names the box that re-fired, while `response.container` names the
box whose record the finding shows, which can be another box of a shared
finding. A post with no `response` names the box that wrote it. A
resolve names the box of the response it carries, whether it came from a
release, from the end of the last box holding the finding, or from
`findings resolve`. Read `response.container`, not `container`, to learn
which box a response is about. A miner-signature finding
is per tenant and pattern, so several boxes of one tenant running the same
miner share one finding (one `id`). Each box's apply, release, expiry and
failure is its own post, naming that box: for two boxes A and B under
`THROTTLE`, released A then B, the posts are the new finding, A `APPLIED`,
B `APPLIED`, A `RELEASED` (finding `state: 1`, open, because B is still
throttled), and B `RELEASED` with finding `state: 2`, resolved. Releasing
the last box (or the only one) is one post that carries both the release
and the resolve; there is no separate resolve post after it. A consumer
that tracks which boxes are throttled keys on (`id`,
`response.container`). Posts from a daemon before this field existed carry
no `response.container`. A killed process is one of those changes: with
`process-policy set --kill-process=true`, an `ALERT` policy delivers the
new finding and then a second post whose `response` names the kill:
`process_killed: true`, `killed_pid` (the **host** pid that was SIGKILLed,
not the pid inside the box) and `kills` (how many processes have been
killed for this finding). `response.state` stays `1`, `NONE`, because
`ALERT` does nothing else to the box. Under `THROTTLE` or `FREEZE` the
`APPLIED` post carries the kill.

A miner that respawns is killed again each time, so later kills are
rate-limited: the first kill is delivered at once, and further kills on
the same finding at most once a minute, each carrying the latest
`killed_pid` and the running `kills` count. A kill that lands inside that
minute is delivered by the finding's next write after it, so the last
kill of a burst can reach the webhook late. `containarium security
findings list` always shows the current state: its response line reads
`response ALERT NONE on box-a, process killed (pid 25872, kills 3)` or
`response THROTTLE APPLIED on box-a, kill skipped: CONTAINER_INIT`, and
`--json` carries `killedPid`, `kills` and `killSkipReason`. The kill count
is per finding, across the boxes that share it, so a miner respawning on
several boxes is bounded the same way. The bound holds when kills and
skipped kills mix: the first kill and the first skip are each delivered at
once, and after that the finding's kill outcome reaches the webhook at most
once a minute. A miner that respawns every second for an hour, with or
without an occasional skipped kill, gives 60 or 61 kill posts that hour. Each
box's response transitions (`APPLIED`, `RELEASED`, `EXPIRED`, `FAILED`) and
the resolve are delivered on top of that.

If a kill was attempted and did not happen, `response.kill_skip_reason`
says why, as a number: `1` PID_REUSED (the pid now belongs to another
cgroup, or to another process of the same box: its start time differs),
`2` PROCESS_GONE (it exited first), `3` CONTAINER_INIT (the box's init,
never signalled), `4` POLICY_UNREADABLE, `5` OTHER, `6` START_TIME_UNKNOWN
(the process had exited before its exec was decoded, so the pid could not
be confirmed), `7` RUNTIME_UNSUPPORTED (the box does not run under Incus;
`kill_process` is Incus-only). The first skip is
delivered at once and a different reason at most once a minute; the pid
and error detail stay in the audit log (`kill-skipped`), not the webhook.
`response.state` is a number: `1` NONE, `2` APPLIED, `3` FAILED, `4`
RELEASED, `5` EXPIRED. `response.released_by` is `operator`, `ttl`,
`orphan-sweep` or `container-deleted` (the box no longer exists, so
nothing was restored). Fields that are zero or empty are omitted from the
JSON.

## Managing the known-bad-destination list

```bash
containarium security bad-destinations list
containarium security bad-destinations add <cidr> [label]
containarium security bad-destinations remove <cidr>
```

The list is the embedded, versioned baseline (mining pools first) merged
with operator-added entries — additions take effect immediately, no
daemon rebuild required. Baseline entries cannot be removed; `remove`
only ever targets a previously operator-added entry.

MCP equivalents: `list_bad_destinations`, `add_bad_destination` (`cidr`,
`label`), `remove_bad_destination` (`cidr`).

## REST reference

Every CLI/MCP surface above is a thin wrapper over these RPCs
(`ThreatDetectionService`), reachable directly if needed:

| Method | Path |
|--------|------|
| `GET` | `/v1/security/sentry/status` |
| `GET` | `/v1/security/exec-events` (server stream; `container`, `since`, `follow`) |
| `GET` | `/v1/security/findings` |
| `POST` | `/v1/security/findings/{id}/resolve` |
| `GET` | `/v1/security/bad-destinations` |
| `POST` | `/v1/security/bad-destinations` |
| `DELETE` | `/v1/security/bad-destinations/{cidr}` |
| `GET` | `/v1/security/process-policy` |
| `PUT` | `/v1/security/process-policy` |
| `POST` | `/v1/security/process-policy/release` |
| `GET` | `/v1/security/miner-signatures` |
| `POST` | `/v1/security/miner-signatures` |
| `DELETE` | `/v1/security/miner-signatures?kind=&pattern=` |

## Known gaps

- **Two-org e2e coverage**: the fence-probe rules (cross-tenant flow,
  deny-burst) ship with an engine-level test using a faked tenant-IP
  resolver, not a real two-org Incus deployment — tracked in #1660.
- **Cloud aggregation**: the cloud control plane does not yet forward
  findings from connected backends — P0 pass-through is tracked in
  `Containarium-cloud#1412`; a rolled-up UI is a later phase.
