# Sprint 2026-W44 verification, pass 2: process guardrail fixes

This is the second batched pass for #2711. It re-verifies the fixes from
pass 1 (`docs/verification/2026-W44-process-guardrail.md`, PR #2777) and
re-runs the queue rows. Everything ran against one build on a fresh
throwaway KVM guest.

## Version and environment

- **Verified commit:** `d287d803155df82786f61814943e48e1a29e17ec`, the
  newest `main` when the pass started. The brief named `53b79c192`; the only
  commit after it is #2817 (a Helm chart test), which touches no sentry,
  BPF, audit or gateway code. Since pass 1 (`dbbf801ff`), the commits that
  touch that code are #2788 (#2773), #2812 (#2774), #2789 (#2775), #2772
  (#2766) and #2758 (`MemFindingStore.Upsert` snapshot).
- **Build:** pinned bpftool v7.6.0 (sha256 verified), clang 18, libbpf-dev
  1.3.0, then `make build-bpf`. `execwatch.bpf.o` sha256 `a6930b20…`,
  `netpolicy.bpf.o` `0a119693…`. `containariumd` built with
  `-tags embed_bpf`, sha256 `e0938b4b…`. The client
  (`-tags containarium_client`) has sha256 `7a91e5b6…`. Both report
  `v0.109.0`; no such tag exists.
- **Guest:** 8 vCPU / 12 GiB KVM guest, Ubuntu 24.04 cloud image (sha256
  verified), kernel `6.8.0-147-generic` with `/sys/kernel/btf/vmlinux`,
  Incus 6.0.0 (dir), PostgreSQL 16.15. The daemon runs `--standalone --rest`
  with `CONTAINARIUM_THREAT_SENTRY=1` and
  `CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT=embedded` (observation mode). The
  finding webhook points at a local receiver that logs each POST.
- **Boxes:** four boxes, created with `--cpu 2 --memory 2GB`; all have
  `limits.cpu=2` and `limits.cpu.allowance=200ms/100ms`.
  - `pbox-container`: privileged.
  - `vbox-container`: unprivileged.
  - `vbox2-container` and `vbox3-container`: unprivileged and in one tenant,
    `acme`, via the `cloud_org_id` label.
- **Stubs:** a static C busy loop installed as `xmrig`, `gcc` and `worker`
  in every box. The load generator is `loadgen.c` from PR #2812
  (`posix_spawn`, evenly paced), and the measurement uses that PR's
  `measure.sh`.
- **Run:** 2026-10-20 03:04–03:25 UTC.

## Results

| Row | Result |
|---|---|
| #2773 exec-events streaming | ✅ |
| #2774 exec-telemetry overhead | ✅ |
| #2775 kill delivered by webhook | ✅ |
| #2766 per-container release | ✅ on the host. ❌ webhook for the second box (#2820) |
| #2637 queue row | ✅ |
| #2638 queue row | ✅ |
| #2718 queue row | ✅ |

### #2773: exec-events over REST

| Check | Result |
|---|---|
| `exec-events --since 2m` prints multiple events, with no decode error | ✅ 606 lines, 0 `decode stream chunk` |
| `--json` | ✅ 606 lines, 0 errors |
| `sh -c true <marker>` in a box gives exactly one event, attributed to that box | ✅ `vbox-container` 1 (uid 1000000), `pbox-container` 1 (uid 0) |
| The same command on the host (user and root) gives no event | ✅ 0 |
| `--follow` streams with argv | ✅ all three marker execs arrived live, with argv |
| No `Flush not supported` in the daemon log | ✅ 0 |

```text
$ containarium security exec-events --since 0 --follow
2026-10-20T03:10:34Z  vbox-container  pid=23582 ppid=23579 uid=1000000  /usr/bin/sh  sh -c true p21792465831-vbox
2026-10-20T03:10:35Z  pbox-container  pid=23595 ppid=23593 uid=0  /usr/bin/sh  sh -c true p21792465831-pbox
2026-10-20T03:10:35Z  vbox-container  pid=23612 ppid=23609 uid=1000000  /usr/bin/sh  sh -c echo follow-argv-check p21792465831-follow > /dev/null
```

### #2774: overhead (PR #2812 recipe)

Measured with `./measure.sh vbox-container <rate> 60` and
`kernel.bpf_stats_enabled=1`. "Above idle" is (total − idle total) / 8.

| Run | Rate | Daemon | execwatch prog | Total (one core) | Of 8 CPUs | Above idle (host) | `exec_events_lost` |
|---|---|---|---|---|---|---|---|
| idle | — | 1.92 % | 0.000 % | 1.92 % | 0.240 % | — | 0 |
| loadgen | 1000.0/s | 2.30 % | 0.122 % | 2.42 % | 0.303 % | **0.063 %** | 0 |
| loadgen | 100.0/s | 1.47 % | 0.043 % | 1.51 % | 0.189 % | < 0 (noise) | 0 |
| pass-1 generator (serial fork+exec) | 1000.0/s | 2.13 % | 0.206 % | 2.34 % | 0.292 % | 0.053 % | 0 → 0 |

`measure.sh` prints the lost counter from the text status, which omits the
line at 0. The counter, read with `sentry status --json` (`execEventsLost`),
was 0 before and after every run.

How this compares with pass 1 on `dbbf801ff`:

| | Idle | ~800–1,000/s | 100/s |
|---|---|---|---|
| Pass 1 (of 8 CPUs) | 0.36 % | 7.07 % at 798/s | 1.89 % |
| Pass 2 (of 8 CPUs) | 0.24 % | 0.30 % at 1,000/s | 0.19 % |

The bar is < 1 % of host CPU at ~1,000 execs/s. It is met with a wide
margin: 0.063 % above idle. The kernel program now costs ~1.2 µs per run at
1,000/s (`run_time_ns` delta / `run_cnt` delta), against ~197 µs in pass 1.

Detection latency from launch to an open finding (budget < 10 s):

| Case | Latency |
|---|---|
| `xmrig --donate-level 1` | **0.06 s** |
| renamed `worker` with `stratum+tcp://` | 0.33 s |

Kill latency (time until the process was gone):

| Case | Latency |
|---|---|
| `ALERT` + kill | **0.08 s** |
| `THROTTLE` + kill | 0.22 s |

Pass 1 measured 0.13–0.42 s. The 50 ms drain interval did not change the
latencies measurably.

**Shutdown with an open `--follow` client:**
- `systemctl stop containariumd` returned in **0.11 s**, `Result=success`,
  `ExecMainStatus=0`.
- The client exited with `Error: status 499: … grpc: the client connection
  is closing`.
- The log has no panic or goroutine dump.

### #2775: kill delivered through the webhook

| Check | Result |
|---|---|
| `ALERT` + kill: finding plus a second post for the kill | ✅ two posts: new (no `response`), then `response.process_killed: true`, `killed_pid: 210932`, `kills: 1`, `state: 1` |
| Numeric enums unchanged | ✅ `rule: 7`, `severity: 3`, `state: 1`, `response.action: 1`, `response.state: 1` |
| Skipped kill gives a numeric `kill_skip_reason` | ✅ An `xmrig` that exits at once gave `kill_skip_reason: 2` (`PROCESS_GONE`). Audit `kill-skipped … kill_skipped="pid 211757: process already exited"`; CLI `kill skipped: PROCESS_GONE` |
| `THROTTLE` + kill: new, `APPLIED` with the kill, then `RELEASED` with the right pid | ✅ new; then `state: 2` with `killed_pid: 211547`, `kills: 1`; then on release `state: 4`, `released_by: operator`, `killed_pid: 211547` |
| Respawn storm: stub restarted once per second for 120 s | ✅ bounded: 121 kills (audit), **2 posts** in 125 s, at 03:19:23 (`kills: 58`, pid 211113) and 03:20:23 (`kills: 118`, pid 211267). That is one per minute after the first kill's post. |

Observation, not filed as a defect: the storm's last kills (`kills` 119 to
121, at 03:20:24–25) were never delivered. They landed inside the 1-minute
interval after the 03:20:23 post, and no later write to the finding
followed. PR #2789 describes it this way ("delivered by the finding's next
write"), but a storm that stops leaves the webhook's last `kills` short of
the truth. The CLI shows the true value (`kills 121`, pid 211275).

Kill post as received:

```json
{"id": 3, "rule": 7, "severity": 3, "tenant_id": "vbox", "container": "vbox-container", "backend_id": "verify-guest", "subject": "name:xmrig", "state": 1, "count": 1, "evidence": {"execs": [{"pid": 210932, "ppid": 21941, "uid": 1000000, "comm": "xmrig", "filename": "/usr/local/bin/xmrig", "argv": "/usr/local/bin/xmrig --donate-level 1", "matched": "name:xmrig"}]}, "first_seen": {"seconds": 1792466303, "nanos": 606074000}, "last_seen": {"seconds": 1792466303, "nanos": 606074000}, "response": {"action": 1, "state": 1, "process_killed": true, "applied_at": {"seconds": 1792466303, "nanos": 630481993}, "killed_pid": 210932, "kills": 1}}
```

Skipped kill (evidence omitted):

```json
{"id": 5, "rule": 7, "severity": 3, "tenant_id": "pbox", "container": "pbox-container", "backend_id": "verify-guest", "subject": "name:xmrig", "state": 1, "count": 1, "first_seen": {…}, "last_seen": {…}, "response": {"action": 1, "state": 1, "applied_at": {"seconds": 1792466509, "nanos": 70004100}, "kill_skip_reason": 2}}
```

### #2766: shared finding, per-container release

| Check | Result |
|---|---|
| Two boxes of tenant `acme` running the same signature share one finding | ✅ finding #6 (tenant `acme`, `name:xmrig`, count 2, both execs in evidence) |
| Both boxes throttled | ✅ two `security_actions` rows (`vbox2-container`, `vbox3-container`), both `10ms/100ms` and `cpu.max 10000 100000` |
| Release box A; box B's response stays applied | ✅ CLI `Released THROTTLE on vbox2-container: CPU limit restored. Finding #6 kept open: another box still has a response.` vbox2 back to `200ms/100ms`; vbox3 still `10ms/100ms`. Audit `release … vbox2-container … finding_kept_open=true`; vbox3's row unreleased |
| Releasing the last box resolves the finding | ✅ `Released THROTTLE on vbox3-container: CPU limit restored. Finding #6 resolved.` Audit `finding_kept_open=false`; finding `RESOLVED` |
| Webhook for the shared finding | ❌ **#2820**. Three posts, all naming `vbox2-container`: new, `APPLIED`, `RELEASED`. vbox3's throttle, vbox3's release and the resolve were never delivered. After A's release, `findings list` also shows the finding's response as `THROTTLE RELEASED` while vbox3 is still throttled. |

In this run, releasing A kept the finding open while B held an applied
throttle. The CLI reports "another box still has a response". So the
scenario in #2779 (A's release resolving the finding while B is throttled)
did not reproduce live here; #2779 is open, and this note is for whoever
picks it up.

### Queue rows re-run (#2637, #2638, #2718)

| Row | Check | Result |
|---|---|---|
| #2637 | Object loads (6.8, BTF) | ✅ `exec telemetry started (tracepoint sched/sched_process_exec)`, `exec-telemetry: ok` |
| #2637 | No lost events at 100/s and at 800/s or more | ✅ 0 at 100/s and 1,000/s (both generators) |
| #2637 | Without BTF: `exec-telemetry: unavailable`, flow rules keep running | ✅ simulated by bind-mounting `/dev/null` over `/sys/kernel/btf/vmlinux`. Status shows `unavailable (…parsing .BTF header…)`; `exec-events` returns 503 with the reason; the flow enforcer started; `SENTRY_UNAVAILABLE` `exec-telemetry unavailable` opened within 60 s and was resolved after recovery |
| #2638 | `xmrig --donate-level 1` gives a HIGH finding < 10 s with the exec in evidence | ✅ 0.06 s |
| #2638 | Same stub as `gcc` at the same CPU gives no finding | ✅ 99.9 % CPU for 60 s, no finding |
| #2638 | `kill_process` kills within one cycle; audit names the pid | ✅ 0.08 s / 0.22 s. Audit `kill … pid=…`; CLI `process killed (pid 210932, kills 1)` |
| #2638 | Renamed binary with `stratum+tcp://` in argv is caught | ✅ 0.33 s, `argv:stratum+tcp://` with the `worker` exec in evidence |
| #2638 | `ssh -o ProxyJump=bastion:4444` gives no finding | ✅ no finding, both for a stub with that argv and for real `ssh -o ProxyJump=bastion:4444 …`. All four execs appear in `exec-events`, unmatched |
| #2718 | Webhook goes from no `response` (new) to `APPLIED`, then a single `RELEASED` on release | ✅ for a single box (finding #4: new, `state: 2`, `state: 4`). For two boxes sharing a finding, see #2820 |

## Real outputs, compared with `docs/security/PROCESS-GUARDRAIL.md`

PR #2716's head is `f98e6a15`. The file is byte-identical to the
`496d87b0` copy that pass 1 compared against.

### `containarium security sentry status`

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

`--json`: `{"state":"SENTRY_STATE_OK","reason":"","cpuSampler":"standalone (30s)","execTelemetry":"ok","execEventsLost":0,"rules":[…]}`.
The BTF-missing shape is unchanged from pass 1: `Sentry: OK` with
`exec-telemetry: unavailable (…)`, and every rule `true`.

### `containarium security process-policy get` (fresh backend)

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

### `containarium security exec-events`

Text format:

```text
2026-10-20T03:10:34Z  vbox-container  pid=23582 ppid=23579 uid=1000000  /usr/bin/sh  sh -c true p21792465831-vbox
```

`--json`, one object per line:

```json
{"container":"vbox-container","tenantId":"vbox","at":"2026-10-20T03:10:34.954851557Z","exec":{"pid":23582,"ppid":23579,"uid":1000000,"comm":"sh","filename":"/usr/bin/sh","argv":"sh -c true p21792465831-vbox","argvTruncated":false,"sha256":"","matched":""}}
```

### `containarium security miner-signatures list`

Identical to pass 1: `Baseline version: 1`, 8 `name` entries, then the
`argv` entries (`--donate-level`, `stratum+tcp://`, `stratum+ssl://`,
`--coin `, `--coin=*`, and the `-o *:<port>`, `--url=*:<port>`,
`--url *:<port>` and `-o[^/]*:<port>` forms for each default stratum port).
There are no sha256 entries.

### `findings list` responses

```text
response ALERT NONE, process killed (pid 210932, kills 1)
response THROTTLE APPLIED, process killed (pid 211547, kills 1)
response ALERT NONE, kill skipped: PROCESS_GONE
```

### Release messages

```text
Released THROTTLE on pbox-container: CPU limit restored. Finding #4 resolved.
Released THROTTLE on vbox2-container: CPU limit restored. Finding #6 kept open: another box still has a response.
```

### Differences from the doc that remain

Pass 1 listed 11. Status of each, then the new ones:

| # | Pass 1 difference | Now |
|---|---|---|
| 1 | Doc says "as shipped in v0.109.0"; no such tag | **Remains** (latest release is still v0.108.0) |
| 2 | `process-policy get` sample shows `kill process: inherit`; real is `false` | **Remains** |
| 3 | `exec-events` examples fail after one event; line format undocumented | **Fixed in code** (#2773); line format still undocumented |
| 4 | `exec-events` JSON `matched` is always `""` | **Remains** |
| 5 | Runtime errors print the full usage | **Remains** (the 503 in the BTF-missing check printed usage) |
| 6 | First webhook post has no `response` object; `rule`, `severity` and `state` are numeric | **Remains** |
| 7 | Coalesced release post shows finding `state: 1`; the resolve is not delivered | **Remains** (finding #4's release post: `state: 1`, `response.state: 4`) |
| 8 | Kill never delivered by the webhook | **Fixed in code** (#2775). The doc's webhook section doesn't describe `killed_pid`, `kills`, `kill_skip_reason`, or the 1-minute kill re-notify interval |
| 9 | Overhead numbers are the lane's; not met on a KVM guest | **Fixed in code** (#2774): 0.063 % of host above idle at 1,000/s. The doc still quotes the old lane numbers (2.95 % of one core) and should quote the batched path and the 50 ms drain |
| 10 | `MINER_SIGNATURE` reads `true` while exec telemetry is down | **Remains** |
| 11 | `findings list` renders `= in  — …` for `SENTRY_UNAVAILABLE` | **Remains** |
| 12 (new) | The release message for a shared finding ("Finding #N kept open: another box still has a response.") and the shared-finding behavior are not in the doc | New |
| 13 (new) | `findings list` now prints `process killed (pid N, kills K)` and `kill skipped: <REASON>`; the doc says only "process killed" | New |
| 14 (new) | The `kill-skipped` audit detail is `kill_skipped="pid N: process already exited"`; the doc's example reason text is "process already exited" without the pid | New, minor |
| 15 (new) | `exec_events_lost` should be alerted on (#2812 added that to the sentry guide); the process guardrail doc doesn't say so, and it doesn't mention the 4 MiB ring | New |

## Teardown

The guest was destroyed and undefined with its storage. Also removed: the
host proxy, its `verify-pass2` iptables rule, and the
`/var/lib/libvirt/verify-pass2` directory. The lab host's other guest was
left as it was (shut off).
