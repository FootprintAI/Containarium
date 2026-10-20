# Process guardrail operator guide

The process guardrail is the part of the threat-detection sentry that
recognises cryptomining inside a box and, if you ask it to, contains it:
it raises a HIGH finding and applies a reversible action to the box
(`ALERT`, `THROTTLE` or `FREEZE`). It also tells you when the sentry that
should be watching is not.

This page describes the guardrail as it behaves on `main`. v0.109.0 is
the latest release; it has the CPU and flow rule, exec telemetry, the
miner-signature rule with the optional kill, and webhook delivery of what
the responder did. Fixes merged after that tag ship in the next release and
are marked **(next release)**: batched exec-ring wakeups (#2774), exec-events
streaming over REST (#2773), kill delivery through the webhook (#2775),
per-box release of a shared finding (#2766), and the sentry reporting
`DEGRADED` when the responder can only alert (#2719).

Read first:

- [Threat-Detection Sentry Operator Guide](../THREAT-DETECTION-SENTRY-GUIDE.md):
  arming the sentry, its states, the findings CLI and webhook delivery.
  This page assumes it.
- Design: [`docs/architecture/continuous-threat-detection.md`](../architecture/continuous-threat-detection.md)
  (the engine) and the process-exec-guardrail design (rules, responder,
  contracts).

Everything here runs on the host. Detection uses host-side signals (eBPF
flow records on the host, per-container CPU counters read through Incus),
and actions go through Incus. Nothing is installed in the box.

## The three rules and what they watch

Three signals feed the guardrail:

- **CPU.** Per-container cores, from the cumulative CPU counter Incus
  reports. Where a metrics collector runs (a metrics export target is
  configured), the sampler is a hook on the collector's tick and adds no
  Incus polling. Where none runs (for example a BYOC host), the sampler
  polls Incus itself every 30 s, one read per running container; stopped
  containers are not read. Never both at once. A container's first
  reading after start, a counter that went backwards (restart) and a
  reading with no wall-clock advance are dropped.
- **Flows.** The eBPF flow records the network-policy enforcer already
  polls (every 15 s). The sentry works in observation mode; enforcement
  does not need to be on.

- **Process execs.** A second eBPF object on the host sees every exec in a
  box's cgroup. See [Exec telemetry](#exec-telemetry).

### Rule: `mining-behavior` (HIGH)

A box fires when, over the window:

1. its **mean CPU** is at least the bar, and
2. it holds a **qualifying flow**: to a stratum port, or to any port on a
   listed bad destination, at least `flow_min_age` old and seen by a flow
   poll inside the window.

| Threshold | Default | CLI flag |
|---|---|---|
| `min_cores` | 1.5 | `--min-cores` |
| `min_fraction_of_limit` | 0.75 | `--min-fraction-of-limit` |
| `window` | 5 min (accepted range 3 min to 128 min) | `--window` |
| `flow_min_age` | 3 min (must not exceed the window) | `--flow-min-age` |
| `stratum_ports` | 3333, 4444, 5555, 7777, 14444, 14433 | `--stratum-ports` |

**The CPU bar** is `min(min_cores, min_fraction_of_limit × limits.cpu)`.
A box with no CPU limit uses `min_cores` alone. With the defaults, a
1-core box trips at 0.75 cores, a 2-core box at 1.5, and a 4-core or
unlimited box at 1.5.

**Coverage.** The mean is only taken over a window the samples actually
cover: at least 3 samples, and the oldest one at least 80 % of the window
old. A burst at the end of the window, or one sample after a gap, does
not count.

**Why the window has a floor and a cap.** Samples arrive every 30 s. A
window shorter than about 150 s can never meet the 80 % coverage rule at
that cadence, so the rule would accept the setting and then never fire.
The floor, `MinMiningWindow`, is 3 min (six ticks, with headroom). At the
other end the rule keeps at most 256 samples per box, which is 128 min at
30 s; a longer window could never be covered either, so `MaxMiningWindow`
is 128 min. `process-policy set` rejects windows outside that range.

**Flow age** is the flow record's own last-packet time minus its
first-packet time. A connection that sits idle does not age: a flow that
sent one packet ten minutes ago and nothing since has an age near zero.
A real miner talks to its pool continuously.

**Bad-destination qualifier.** An address on the known-bad-destination
list (`containarium security bad-destinations`) qualifies on any port, and
the evidence names the list entry (`bad-destination:<cidr>`) in
preference to a port match (`port:<n>`).

**Subject and dedupe.** The finding's subject is the destination
`ip:port`. While the condition holds, every 30 s sweep re-fires the same
subject, which dedupes into one open finding with a climbing count. A
second pool opens a second finding. The evidence carries a CPU summary
(mean, peak, window, number of samples) and the flow: 5-tuple, bytes,
packets, first and last seen, and what matched.

**State.** A box's CPU history is dropped when no sample has arrived for
twice the window. Candidate flows not seen inside the window are dropped.

Thresholds are backend-wide (there is no per-container threshold). They
are persisted in the daemon config store under
`threatdetect.mining_behavior.thresholds`. A field you never set keeps
its default.

### Rule: `sentry-unavailable` (MEDIUM)

On a backend with `CONTAINARIUM_THREAT_SENTRY` set, a health loop runs at
daemon start and every 60 s. It raises a MEDIUM `SENTRY_UNAVAILABLE`
finding (no tenant, no container) while any of these is true:

- the sentry state is `UNAVAILABLE` or `DEGRADED`;
- a rule is unhealthy (it panicked);
- the CPU sampler cannot run: `cpu-sampler` in `sentry status` begins
  with `unavailable`. A backend blind to CPU cannot fire
  `mining-behavior`, so this is a fault even when the state reads `OK`.

The subject is the reason `sentry status` prints, with the volatile parts
removed so repeats dedupe: an unhealthy rule appears as
`rule <RULE> unhealthy` (its error text is in the evidence note), and a
sampler fault as `cpu-sampler unavailable` (the sampler's detail is in the
note). Several faults at once are one finding. A changed reason resolves
the old finding and opens a new one; recovery resolves it, including a
finding left open by an earlier daemon process.

It is deliberately not a rule inside the engine: the faults it reports
are the ones where the engine is missing or broken.

It cannot fire in two cases. A backend without the variable set runs no
loop (not armed is a choice, not a fault). And with no audit store (no
Postgres) there is nowhere to record a finding; the daemon logs a warning
and `sentry status` still says `UNAVAILABLE`. Watch `sentry status`
directly on such a backend.

### Rule: `miner-signature` (HIGH)

Fires on the exec itself, when a process started in a box matches the
signature list. Needs [exec telemetry](#exec-telemetry). Three matcher
kinds:

| Kind | Matches | Example |
|---|---|---|
| `name` | basename of the exec'd file and the task comm; exact or glob, case-insensitive | `xmrig`, `cpuminer*` |
| `argv` | the joined command line: a literal substring, or, with a glob character, space-separated globs over consecutive arguments (option tokens such as `-o` are case-sensitive) | `--donate-level`, `-o *:3333` |
| `sha256` | hex SHA-256 of the executable | operator entries only |

The embedded baseline ships `name` and `argv` entries only (well-known
miner binaries; `--donate-level`, `stratum+tcp://`, `stratum+ssl://`,
`--coin`, and `-o`/`--url` forms for each default stratum port). It has
**no SHA-256 entries**: a hash list goes stale with every upstream release.
Add hashes for builds you have seen; the daemon hashes an executable only
when such entries exist and no name or argv entry matched, off the exec
path (64 MiB cap, 200 ms budget, best effort).

```bash
containarium security miner-signatures list [--json]
containarium security miner-signatures add --kind name --label SRBMiner 'srbminer*'
containarium security miner-signatures add --kind argv -- '--algo randomx'
containarium security miner-signatures add --kind sha256 <64 hex chars>
containarium security miner-signatures remove --kind name 'srbminer*'
```

Additions and removals take effect immediately, persist in the daemon
config store, and need `security:write` and admin. Baseline entries cannot
be removed.

The finding's subject is `<kind>:<pattern>` of the entry that hit; the
evidence is the exec (pid, ppid, uid, comm, path, argv, and the hash when
computed). The finding is subject to the same process policy as
`mining-behavior`. A literal argv marker matches any command line that
mentions it: `grep -r -- --donate-level .` raises the finding too. Keep
that in mind before enabling `kill_process` on boxes where people inspect
miner configs.

### Exec telemetry

The daemon loads `execwatch.bpf.o` on the `sched_process_exec` tracepoint
and filters in the kernel by box cgroup, so host and core-infrastructure
execs are never emitted. Each event carries host pid, ppid, uid, the
executable path and the argument vector **capped at 512 bytes**, never the
environment. Tenants have root in their box, so nothing inside it reports.

- **Kernel floor:** 5.8 (ring buffer) and kernel BTF
  (`/sys/kernel/btf/vmlinux`). Ubuntu 22.04 and 24.04 have both. The object
  comes from the same `CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT` value as the
  flow object.
- **Not audited.** Events are not written to the audit log; the daemon keeps
  a short in-memory buffer (4,096 events). Only matched findings persist.
- **Failure mode.** If the object cannot load or attach, `sentry status`
  prints `exec-telemetry: unavailable (<reason>)`, `exec-events` fails with
  the same reason, and a MEDIUM `SENTRY_UNAVAILABLE` finding with subject
  `exec-telemetry unavailable` opens within a minute. The flow rules keep
  running. **Limitation:** the `MINER_SIGNATURE` row of the rule table keeps
  reading `true` while exec telemetry is down, although the rule sees no
  execs. Read the `exec-telemetry:` line, not the rule row, to know whether
  it can fire.
- **Lost events and floods.** One 4 MiB ring serves every watched box on
  the host. The daemon drains it every 50 ms (**next release**; an exec
  event therefore reaches the rules up to about 50 ms after it happened). If
  more execs arrive inside one drain window than the ring holds, the excess
  is dropped and counted, never hidden, and shown as `exec-events-lost: N`.
  A tenant can cause this deliberately by flooding execs, so **alert on
  `exec-events-lost` increasing**: a non-zero change means the exec rules did
  not see every exec in that window. The execs themselves are never blocked.
- **Overhead.** The bar is under 1 % of host CPU at 1,000 execs/s. With the
  batched wakeups (**next release**) the verification pass on an 8-vCPU
  guest measured **0.063 % of host CPU above idle** at 1,000 execs/s for
  60 s, 0 events lost, the kernel program costing about 1.2 us per exec. The
  CI lane measured 0.078 %. Before the batching fix the same guest measured
  about 7 %; v0.109.0 as tagged has that cost.

```bash
containarium security exec-events                          # last 5 minutes, all boxes
containarium security exec-events --container box-a --follow
containarium security exec-events --since 1h --json
```

One line per exec, in text:

```text
2026-10-20T03:10:34Z  box-a  pid=23582 ppid=23579 uid=1000000  /usr/bin/sh  sh -c true example-marker
```

and with `--json`, one object per line:

```json
{"container":"box-a","tenantId":"acme","at":"2026-10-20T03:10:34.954851557Z","exec":{"pid":23582,"ppid":23579,"uid":1000000,"comm":"sh","filename":"/usr/bin/sh","argv":"sh -c true example-marker","argvTruncated":false,"sha256":"","matched":""}}
```

`uid` is the host-side uid (an unprivileged box maps its root to a high
uid). `sha256` and `matched` are always empty here: the stream shows what
ran, not what a rule decided; matches are findings. Streaming over REST
works from the next release (#2773).

## The policy ladder

The process policy says what a HIGH finding from a mining rule does to
its box. That is the two mining rules, `mining-behavior` and `miner-signature`; no
other rule's findings are acted on.

| Action | What it does to the box | Release |
|---|---|---|
| `ALERT` (default) | Nothing. The finding is recorded and delivered, with response `ALERT / NONE`. | Nothing to release. |
| `THROTTLE` | Reads and records the box's `limits.cpu` and `limits.cpu.allowance`, then sets `limits.cpu.allowance` to a hard CFS quota. `limits.cpu` is left as it was. | Writes the recorded `limits.cpu` and `limits.cpu.allowance` back verbatim. |
| `FREEZE` | Freezes the instance through Incus. Processes stop; memory and disk are kept for inspection. | Unfreezes it. |

**What `10%` means.** `throttle_allowance` is either `N%` (1 to 100) or an
explicit quota `Xms/Yms`. `N%` means N percent of **one core** and is
written as the hard quota `Nms/100ms`; an explicit `Xms/Yms` is written as
given. The default `10%` becomes `limits.cpu.allowance = 10ms/100ms`,
which the kernel shows as `cpu.max = 10000 100000` in the box's cgroup:
0.1 core, whatever the box's size. (Incus reads a bare `N%` as a soft
share that does nothing on an idle host, which is why it is converted.)
A throttle is never looser than the box's existing hard cap: if the box
already had a tighter `Xms/Yms` quota, that is kept.

**One open action per box.** While an action is open on a box, further
findings on it (another pool, a later sweep) do not stack a second one. A
re-fire after release or expiry is a new decision under the policy in
effect then.

**Record first, act second.** The action row, with the previous limits,
is written as pending before the box is touched, and confirmed after.
Every apply, release, expiry and failure is an audit entry with resource
type `security.action`, and the finding's `response` field shows the
action and its state (`NONE`, `APPLIED`, `FAILED`, `RELEASED`, `EXPIRED`).

**TTL backstop.** Every action carries a TTL (default 24 h, minimum 1 min).
A sweep every 60 s undoes any action whose TTL has passed with no
operator decision, marks the finding's response `EXPIRED`, and raises a
MEDIUM `PROCESS_ACTION_EXPIRED` finding on the box saying so, so an
unattended throttle never silently becomes permanent. The original
mining finding stays open. If the box keeps mining, the rule fires again
once its window re-fills and the policy applies again.

**Pending and orphaned actions.** If the daemon dies between recording an
action and confirming it, the row stays pending. The same 60 s sweep
undoes pending rows older than 5 minutes (writing back the recorded
limits, which is harmless if the box was never touched) and records them
released by the orphan sweep.

**Failures.** If an Incus call fails, the row records the error, the
finding's response says `FAILED` with the error, and an audit entry is
written. The responder does not retry in a loop: for 10 minutes after a
failed apply it leaves that box alone, and after that the next re-fire of
the rule is the retry.

**Release.** `containarium security process-policy release <box>`
undoes the open action (restores the recorded limits, or unfreezes),
marks it released by the operator and resolves the finding. When several
boxes of one tenant share the finding (same rule and subject), release is
per box: while another box still has a response the finding stays open
(**next release**, #2766). If the Incus
call fails the action stays open so you can retry. With nothing open it
fails with 404.

**Per-container overrides.** The policy is stored per backend, with an
optional override per container. The effective policy is resolved field
by field: container override, then backend default, then the built-in
`ALERT`, `10%`, `24h`. An override can set only `action` and leave the
allowance and TTL to the backend. `process-policy set` changes only the
fields you pass. Remove an override with `--clear-override`.

**Degraded store means `ALERT` only.** When the finding store has no
Postgres (the sentry is `DEGRADED`), the responder applies `ALERT`
whatever the policy says, and `sentry status` reports
`DEGRADED (no persistence): responses disabled`. **(Unreleased, #2719.)**
The same state, with the cause named, is reported when findings persist
but the responder is ALERT-only anyway (for example the action store is
unavailable): `DEGRADED (security_actions store unavailable): responses
disabled`, and a MEDIUM `SENTRY_UNAVAILABLE` finding opens for it. Before
that fix such a backend read `OK` while a `THROTTLE` policy did nothing. A throttle whose
recorded previous limit could vanish on restart, leaving a box throttled
with nothing saying so, is worse than an alert. The policy itself can
still be read and set.

**`kill_process`.** An optional extra for `miner-signature` findings only
(the behavior rule names no process, so it never kills). Default **off at
every level**, and the hosted service will not turn it on: a false
positive kills a tenant's process with no undo, while throttle and freeze
reverse.

```bash
containarium security process-policy set --kill-process=true                     # backend default
containarium security process-policy set --container box-a --kill-process=false  # one box opts out
```

With it on, a match still applies the box's action (`ALERT`, `THROTTLE`
or `FREEZE`) and also SIGKILLs the matched process from the host.

- The daemon pins the process with a pidfd (no pidfd, no kill), then
  re-reads `/proc/<pid>/cgroup` and confirms it is still in that box's
  cgroup, so a reused pid on the host or in another box is never signalled.
  A reused pid inside the same box within the queue delay is not excluded
  (start-time check tracked in #2765).
- A box's init is never killed.
- Every attempt is audited under `security.action`: `kill` (names the pid)
  or `kill-skipped` (with the pid and the reason, for example
  `kill_skipped="pid 211757: process already exited"`).
- `findings list` shows the result under the finding:

  ```text
  response ALERT NONE, process killed (pid 210932, kills 1)
  response THROTTLE APPLIED, process killed (pid 211547, kills 1)
  response ALERT NONE, kill skipped: PROCESS_GONE
  ```

  A miner that respawns is killed again each time; `kills` counts them.
  The skip reasons are `PID_REUSED`, `PROCESS_GONE`, `CONTAINER_INIT`,
  `POLICY_UNREADABLE` and `OTHER`.
- The kill runs on the responder's own queue, never on the exec path. A
  full queue (256) drops the response, logged and audited as
  `response-dropped`.
- **A queued response never undoes a release.** Before acting, the worker
  re-reads the finding; one resolved, or whose action an operator or the
  TTL released after queueing, is left alone and audited as
  `response-skipped`.

## CLI reference

All verbs talk to the daemon's REST API (`--server` or
`CONTAINARIUM_SERVER`). `get`, `list` and `exec-events` need `security:read`; `set`, `release`,
`miner-signatures add|remove` need `security:write` and admin. MCP equivalents:
`security_process_policy_get`, `security_process_policy_set`,
`security_process_policy_release` (thresholds are CLI-only), `list_miner_signatures`,
`add_miner_signature`, `remove_miner_signature` (`kill_process` is a field of
`security_process_policy_set`) and
`security_sentry_status`.

### `containarium security process-policy get [--container <box>] [--json]`

Shows the stored policy at one level (backend default, or the box's
override with `--container`) and the effective policy. On a fresh backend:

```text
Backend default
Stored:    (none; the built-in default applies)
Effective:
  action:             ALERT
  throttle allowance: 10%
  ttl:                24h0m0s
  kill process:       false
Mining-behavior thresholds:
  min cores:              1.5
  min fraction of limit:  0.75
  window:                 5m0s
  flow min age:           3m0s
  stratum ports:          3333,4444,5555,7777,14444,14433
```

The thresholds block is the effective thresholds the rule is using, and
appears when the sentry engine is running.

### `containarium security process-policy set`

| Flag | Meaning |
|---|---|
| `--action alert\|throttle\|freeze` | What a HIGH mining finding does |
| `--throttle-allowance N%\|Xms/Yms` | Quota `THROTTLE` applies (default `10%`) |
| `--kill-process[=false]` | Also SIGKILL the process of a `miner-signature` match (default off; `=false` turns it off or opts a box out) |
| `--ttl <duration>` | TTL backstop (default `24h`, minimum `1m`) |
| `--container <box>` | Write that box's override instead of the backend default |
| `--clear-override` | Remove the box's override (needs `--container`, no policy flags) |
| `--rule mining-behavior` | Tune thresholds, with any of `--min-cores`, `--min-fraction-of-limit`, `--window`, `--flow-min-age`, `--stratum-ports`; backend-wide, so not with `--container` |

```bash
containarium security process-policy set --action throttle --throttle-allowance 10% --ttl 24h
containarium security process-policy set --action freeze --container box-1
containarium security process-policy set --container box-1 --clear-override
containarium security process-policy set --rule mining-behavior --min-cores 2 --stratum-ports 3333,4444
```

A container override prints `kill process: inherit` until it is set.
Prints `Process policy updated.` (or `Cleared override on <box>.`) and
the effective action, allowance and TTL.

### `containarium security process-policy release <box>`

```text
Released THROTTLE on box-1: CPU limit restored. Finding #42 resolved.
Released FREEZE on box-1: container unfrozen. Finding #43 resolved.
Released THROTTLE on box-2: CPU limit restored. Finding #44 kept open: another box still has a response.
```

The last form is for a finding shared by several boxes of one tenant
(**next release**, #2766). It resolves when the last box is released. In
the audit log the release carries `finding_kept_open=true` or `false`.

### `containarium security sentry status [--json]`

Besides the state, the `Reason`, `cpu-sampler`, `exec-telemetry` and
`exec-events-lost` lines matter.

```text
Sentry: OK
cpu-sampler: standalone (30s)
exec-telemetry: ok

RULE                             HEALTHY  LAST ERROR
CROSS_TENANT_FLOW                true     -
DENY_BURST                       true     -
BAD_DESTINATION                  true     -
MINING_BEHAVIOR                  true     -
MINER_SIGNATURE                  true     -
```

`cpu-sampler` is `metrics-collector`, `standalone (30s)` or
`unavailable (<reason>)`; `exec-telemetry` is `ok` or `unavailable
(<reason>)`. `exec-events-lost: N` is printed only when N is not 0. Other
shapes:

```text
Sentry: DEGRADED
Reason: DEGRADED (no persistence): responses disabled
cpu-sampler: metrics-collector
exec-telemetry: ok
```

```text
Sentry: OK
cpu-sampler: metrics-collector
exec-telemetry: unavailable (<reason>)
exec-events-lost: 120
```

An unhealthy rule adds `rule <RULE> unhealthy: <error>` to the `Reason`
line. `DISABLED` and `UNAVAILABLE` print their reason and no rules. The
`DEGRADED (<cause>): responses disabled` form for an ALERT-only responder
with persisted findings is unreleased (#2719). The sample layout comes from the shipped formatter; the rule rows are
whatever the running engine registers.

### `containarium security findings list`

Flags: `--state open|resolved`, `--severity low|medium|high|critical`,
`--tenant`, `--since <RFC3339>`, `--limit`, `--json`. There is no rule
filter. Mining findings show as rule `MINING_BEHAVIOR` (subject: the pool's
`ip:port`) or `MINER_SIGNATURE` (subject: `<kind>:<pattern>`). Under each
finding the table prints its evidence and, once the responder has acted,
the `response` line shown above. `--json` has the full CPU summary, flow and
response. `findings resolve <id>` resolves a finding by hand; it does not
release an action (use `process-policy release`).

### `containarium security miner-signatures list`

```text
Baseline version: 1
KIND    SOURCE    PATTERN                    LABEL
name    baseline  "xmrig"                    XMRig (Monero CPU/GPU miner)
name    baseline  "minerd"                   pooler cpuminer (minerd)
name    baseline  "cpuminer*"                cpuminer family
...
argv    baseline  "--donate-level"           XMRig donate-level flag
argv    baseline  "stratum+tcp://"           stratum pool URL
argv    baseline  "-o *:3333"                pool on stratum port 3333
...
```

The baseline is 8 `name` entries and the `argv` entries above, plus the
`-o`, `--url` forms for each default stratum port. There are no `sha256`
entries; yours show with source `operator`.

### `miner-signatures` and `exec-events`

Described with the rules above. The REST routes are `/v1/security/miner-signatures` and
`/v1/security/exec-events`.

### Webhook delivery of responses

The finding webhook fires again when the responder's result changes.
Enums are numbers in the payload. `rule`: `mining-behavior`=6,
`miner-signature`=7. `severity`: HIGH=3. `response.action`: ALERT=1.
`response.state`: `NONE`=1, `APPLIED`=2, `FAILED`=3, `RELEASED`=4,
`EXPIRED`=5.

- The **first post** for a new finding has **no `response` key**: the
  responder has not acted yet. It is not `NONE`.
- A **second post** follows when the action is `APPLIED` or `FAILED`, then
  one on release or expiry, each inside the re-notify interval.
- An operator release that also resolves the finding is one post: the
  resolve within 30 s is coalesced. Its `state` field is still the finding's
  (open) state, with `response.state: 4`. A TTL expiry or orphan-sweep
  release leaves the finding open, so its later resolve is posted.
- **Kills** (next release, #2775): a kill adds `response.process_killed:
  true`, `killed_pid` and `kills` and is posted at once, then at most once a
  minute for a respawning miner. After a storm stops, the last `kills` in
  the webhook can be short of the true count; `findings list` is exact. A
  skipped kill carries a numeric `kill_skip_reason` (`PID_REUSED`=1,
  `PROCESS_GONE`=2, `CONTAINER_INIT`=3, `POLICY_UNREADABLE`=4, `OTHER`=5).

Abridged kill post:

```json
{"id": 3, "rule": 7, "severity": 3, "container": "box-a", "subject": "name:xmrig", "state": 1, "count": 1, "response": {"action": 1, "state": 1, "process_killed": true, "killed_pid": 210932, "kills": 1}}
```

The gate is in memory, so a restart re-posts an open finding once.

**Known limitation (#2820, remove when it lands).** For a finding shared by
several boxes of one tenant, the webhook currently names only the first box:
the second box's throttle, its release and the resolve are not posted. Use
`findings list --json` or the audit log for those boxes.

## Rollout order

Move one step at a time, per backend, and check `sentry status` at each.

1. **Deploy a daemon at v0.109.0 or later.** Nothing changes: the
   built-in policy is `ALERT` and, unarmed, the sentry runs nothing.
   `sentry status`: `Sentry: DISABLED`, reason
   `CONTAINARIUM_THREAT_SENTRY is not set`. You may set the policy
   already; it is stored and used once the sentry runs. The
   mining-behavior thresholds can only be set on a running sentry.
2. **Arm the sentry.** Set `CONTAINARIUM_THREAT_SENTRY=1`, load the eBPF
   object (`CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT`; enforcement not
   needed), make sure Postgres is reachable, restart. `sentry status`
   must say `Sentry: OK`, no `Reason` line, `cpu-sampler:` either
   `metrics-collector` or `standalone (30s)`, and `MINING_BEHAVIOR true`.
   `exec-telemetry: ok` is required too, and `MINER_SIGNATURE true` alone
   proves nothing (the row stays `true` while exec telemetry is down). Alert
   on `exec-events-lost` increasing.
   Anything else is a `SENTRY_UNAVAILABLE` finding within a minute; fix
   it before going on. `DEGRADED` here means no action will ever be taken
   whatever you set later.
3. **Watch `ALERT` for about four weeks.** Read
   `findings list --state open --severity high --json` and the webhook.
   Look for:
   - **False positives**: a build farm, a test suite or a game server
     that is legitimately busy and holds a long-lived connection to one
     of the stratum ports (3333 is a common development port). Each one
     is a box that `THROTTLE` would have slowed to 0.1 core. Tune with
     `--min-cores`, `--stratum-ports`, or put an `ALERT` override on that
     box.
   - **Time to detect** on real findings against your containment
     target. The window and flow age dominate it.
   - **Signature hits** on legitimate boxes (a security course, a box
     that greps miner configs). Add nothing to the list for those; leave
     `kill_process` off.
   - `SENTRY_UNAVAILABLE` findings: a sentry that drops out is a
     backend with no guardrail.
4. **`THROTTLE`.** `process-policy set --action throttle`. Keep the TTL at
   24 h at first so an unattended mistake undoes itself. Expect, on a
   real hit, response `THROTTLE / APPLIED` on the finding and an audit
   entry; `sentry status` unchanged (`OK`, no reason). A
   `PROCESS_ACTION_EXPIRED` finding means nobody decided within the TTL.
   Leave `kill_process` off. It is a separate, later decision (above).
5. **`FREEZE`.** Only once throttles have been right for a while.
   A frozen box stops serving entirely, so start with overrides on the
   boxes you are surest about, or with tenant classes whose terms allow
   it. `sentry status` must still read `OK`.

## Evasion limits

What the guardrail will not catch, stated plainly:

- **A self-throttled miner below `min_cores`.** A miner held at 1.4 cores
  on an unlimited box, or below 75 % of a small box's limit, never fires
  `mining-behavior`. Spreading the work over several boxes, each under its
  own bar, does the same: each box is evaluated alone.
- **A renamed or rebuilt binary with a clean command line.** It matches no
  `name` or `argv` entry, and a fresh build matches no hash. Only
  `mining-behavior` (sustained CPU plus a pool flow) catches it. The
  signature rule sees the exec, not later renames inside the process.
- **Pools on `:443`** (or any port outside the stratum set) at an address
  not on the bad-destination list: no qualifying flow, so
  `mining-behavior` does not fire however busy the box is. Adding 443 to
  `--stratum-ports` would make every busy box with a web connection a
  finding. TLS metadata is not read.
- **Scheme-less and non-default-port spellings.** The baseline argv
  markers cover `stratum+tcp://`, `stratum+ssl://` and `-o`/`--url` forms
  only for the default stratum ports. A pool address in a config file,
  `--url` with another scheme, or a non-default port matches nothing in the
  signature rule; add an `argv` entry for spellings you see, and rely on
  the behavior rule meanwhile.
- **A connection that is idle most of the time.** Flow age is first to
  last packet, so a quiet connection does not age. Real pool connections
  are chatty.
- **Short-lived processes.** The hash is computed best effort; a process
  that exits before it can be read is not hashed.
- **Webhook ordering.** The first delivery is queued when the finding is
  written, before the responder acts, so it has no `response` key; the
  transition arrives as a later delivery. Do not read the first as "no
  action was taken".

### What a tenant with root in the box can and cannot do

- **Cannot** hide CPU use: the counter is the host's view of the box's
  cgroup, read through Incus.
- **Cannot** hide or forge flows or execs: both come from eBPF programs on
  the host, not from inside the box.
- **Cannot** stop the sentry or the responder, or lift a throttle or
  freeze from inside: they run in the host daemon and act on the box's
  cgroup through Incus.
- **Cannot** prevent a kill by renaming after the fact: the signal goes to
  the pinned process from the host. A box's init is the one process the
  kill never touches.
- **Can** stay under the bar, use a port or spelling outside the lists,
  rename or rebuild the miner, or run it so that it exits before it is
  hashed. These are the evasion limits above.

## Verification

### By hand on a throwaway box

Use a throwaway guest or test host, not a backend that serves tenants:
this burns CPU in a box and will throttle and freeze it.

Setup: a daemon at v0.109.0 or later with the sentry armed and Postgres
up (`sentry status` reads `OK`), and a running box with a known limit,
for example `limits.cpu=2`. Note its original limits:

```bash
incus config get <box> limits.cpu
incus config get <box> limits.cpu.allowance
cat /sys/fs/cgroup/lxc.payload.<box>/cpu.max     # on the host
```

1. **Policy.** `containarium security process-policy set --action throttle`.
2. **Pool stand-in on the host.** Listen on a stratum port on the bridge
   address the box can reach (loopback inside the box does not cross the
   host's eBPF program):

   ```bash
   nc -lk <bridge-ip> 3333 > /dev/null
   ```

3. **Miner stand-in in the box.** Two CPU burners (2 cores, above the
   1.5-core bar of a 2-core box) and a connection that keeps sending:

   ```bash
   for i in 1 2; do sh -c 'while :; do :; done' & done
   while :; do date; sleep 5; done | nc <bridge-ip> 3333
   ```

4. **Finding.** With the burners already running, expect a HIGH
   `MINING_BEHAVIOR` finding with subject `<bridge-ip>:3333` about 3.5 to
   4.5 minutes after the connection starts (verified on the default 5 min
   window): `containarium security findings list --state open --json`.
5. **Throttle.** The finding's response is `THROTTLE / APPLIED`;
   `limits.cpu.allowance` is `10ms/100ms`, `limits.cpu` is unchanged, the
   host's `cpu.max` reads `10000 100000`, and the box now runs at about
   0.1 core (measured: 0.1 core over 30 s).
6. **Release.** `containarium security process-policy release <box>`
   restores exactly the original `limits.cpu.allowance` and `cpu.max`,
   and resolves the finding. If the burners are still running the rule
   fires again a few minutes later and throttles again: one action at a
   time, never stacked.
7. **Freeze.** Set `--action freeze`, let it re-fire: `incus list` shows
   the box `FROZEN`. Restart the daemon: the box is still frozen and the
   action is still open. `release` unfreezes it.
8. **Window floor.** `process-policy set --rule mining-behavior --window 2m`
   is rejected with `window 2m0s is below the minimum 3m0s`.

Clean up: stop the burners and the listener, then
`process-policy set --action alert` (or clear the override).

These steps were verified on a throwaway guest (Ubuntu 24.04, Incus
6.0.0, PostgreSQL 16, eBPF observation mode) during the v0.108.0 sprint
(#2636). Not verified on a real host: the degraded-store path
(`ALERT` only without Postgres). Without Postgres there is no audit
store, so the sentry is `UNAVAILABLE` rather than `DEGRADED`; the
degraded path is only reached when the audit store is up but the finding
store cannot connect, and it is covered by unit tests only.

### Real-Incus e2e

The responder's actuator path has an end-to-end test against a real Incus,
which throttles a running container, checks the kernel `cpu.max` when it
can read it, releases, then freezes and unfreezes:

```bash
CONTAINARIUM_E2E_INCUS_CONTAINER=<name> go test -tags=incus -run TestProcessResponderE2E ./internal/server/
```

It skips without a container to act on. It restores the container's
original limits and unfreezes it when it finishes.
