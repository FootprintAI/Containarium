# Sprint 2026-W44 verification: process guardrail half B

Batched verification pass for the #2711 queue (#2637, #2718, #2638), run
against one build on a throwaway KVM guest (Q3 on #2711).

- **Verified commit:** `dbbf801ffafffbe6c7cae404f22fd085a9133e50` (main
  after #2759 merged). `main` has since moved 16 commits; none of them
  touches `internal/threatdetect`, `internal/netbpf`, `internal/audit` or
  the security CLI.
- **Build:** `make build-bpf` with pinned bpftool v7.6.0 (checksum
  verified) and clang 18. `execwatch.bpf.o` sha256 `35963405…`,
  `netpolicy.bpf.o` `8479ffd8…`. `containariumd` built with
  `-tags embed_bpf`, sha256 `3743ad6a…`. It reports `v0.109.0` (see the
  doc notes: no v0.109.0 tag or release exists).
- **Guest:** 8 vCPU / 12 GiB, Ubuntu 24.04.5, kernel `6.8.0-147-generic`,
  `/sys/kernel/btf/vmlinux` present, Incus 6.0.0 (dir storage),
  PostgreSQL 16. The daemon runs `--standalone --rest` with
  `CONTAINARIUM_THREAT_SENTRY=1` and
  `CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT=embedded` (observation mode).
  The finding webhook points at a local receiver that logs every POST.
- **Boxes:** two boxes created through the daemon with `--cpu 2`:
  `pbox-container` (privileged) and `vbox-container` (unprivileged,
  `security.privileged=false`). Both have `limits.cpu=2` and
  `limits.cpu.allowance=200ms/100ms`.
- **Stubs:** a static C busy loop (`for(;;) x++;`) pushed into each box as
  `/usr/local/bin/xmrig`, `/usr/local/bin/gcc` and `/usr/local/bin/worker`,
  with identical bytes. Exec load came from a static `fork`+`exec /bin/true`
  generator paced to a target rate.
- **Run:** 2026-10-19 21:10–21:31 UTC.

## Results

| Issue | Check | Result |
|---|---|---|
| #2637 | Object loads on the guest kernel (6.8, BTF) | ✅ `exec telemetry started (tracepoint sched/sched_process_exec)`, `exec-telemetry: ok`, `MINER_SIGNATURE true` |
| #2637 | `sh -c true` in a box ⇒ exactly one exec event attributed to that box; host exec ⇒ none | ⚠️ kernel side ✅, CLI ❌. Only checkable on a diagnostic build (below): one event each for `vbox-container` and `pbox-container`, zero for the same command on the host (as user and as root). On the verified build the stream stops after its first event (#2773). |
| #2637 | `exec-events --follow` shows argv | ❌ #2773. On the verified build at most one event is printed, then `Error: decode stream chunk: invalid character 'u' looking for beginning of value`. On the diagnostic build `--follow` streamed every event with argv. |
| #2637 | Overhead at ~1,000 execs/s for 60 s under the bar (< 1 % of host CPU) | ❌ #2774. **7.07 % of 8 cores** at 798 execs/s (56.6 % of one core: daemon 40.9 %, kernel program 15.7 %). Idle baseline is 0.36 %. |
| #2637 | `exec_events_lost` stays 0 at 100/s | ✅ 0 → 0 at 100/s for 60 s, and also 0 → 0 at 798/s for 65 s |
| #2637 | A kernel without BTF ⇒ `exec-telemetry: unavailable`, flow rules keep running | ✅ (simulated: `/dev/null` bind-mounted over `/sys/kernel/btf/vmlinux`, daemon restarted). Status shows `exec-telemetry: unavailable (…parsing .BTF header…)`, `exec-events` fails with 503 and the same reason, and the flow enforcer started and kept logging flows. `SENTRY_UNAVAILABLE` `exec-telemetry unavailable` opened within 60 s and resolved after recovery. |
| #2718 | One mining incident ⇒ webhook posts for the finding with `response: NONE`, then `APPLIED`, and one on release | ✅ with `THROTTLE`, finding #1 got three posts: no `response` object at 21:14:20, `response.state=2` (`APPLIED`) at 21:14:21, `response.state=4` (`RELEASED`, `released_by: operator`) at 21:15:15. The release was one post (the resolve coalesced). ❌ For `kill_process` no post reports the kill (#2775). |
| #2638 | Stub as `xmrig --donate-level 1` ⇒ HIGH finding < 10 s with the exec in evidence | ✅ **0.13 s** from launch to finding #2 `name:xmrig` (evidence: pid 25050, `/usr/local/bin/xmrig`, argv `/usr/local/bin/xmrig --donate-level 1`). The launching `sh -c` and `nohup` raised `argv:--donate-level` (#1) too. |
| #2638 | Same stub as `gcc`, same CPU profile ⇒ no signature finding | ✅ `gcc -O2 -c main.c` at 99.9 % CPU for 60 s produced no findings |
| #2638 | `kill_process=true` ⇒ process gone within one cycle, audit row names the pid | ✅ gone in **0.36 s** (privileged box) and **0.42 s** (unprivileged). Audit `kill … pid=25872 comm="xmrig" …` and `kill … pid=25940 …`. Findings show `response ALERT NONE, process killed`. |
| #2638 | Renamed binary with `stratum+tcp://` in argv still caught | ✅ `worker -a rx -o stratum+tcp://<bridge>:3333 -u wallet` raised finding #3 `argv:stratum+tcp://` in **0.28 s**, with the `worker` exec (pid 25699) in evidence |

Overall: #2638 ✅. #2718 ✅ for the queued check, with a kill gap filed
(#2775). #2637 ❌ on two items (#2773 CLI streaming, #2774 overhead), with
the kernel-side checks ✅.

### Diagnostic build (not the verified version)

Because #2773 hides all but one event, the attribution check was re-run on
the same guest with a daemon built from the same tree plus one method on
each of the two `responseWriter` wrappers
(`internal/audit/middleware.go`, `internal/metrics/http_middleware.go`):

```go
func (rw *responseWriter) Unwrap() http.ResponseWriter { return rw.ResponseWriter }
```

The diagnostic daemon's sha256 was `71aa677f…`. Nothing else changed. The
verified binary was put back afterwards (sha256 `3743ad6a…` confirmed) and
the failure reproduced again.

```text
$ containarium security exec-events --since 0 --follow      # diagnostic build
2026-10-19T21:29:16Z  vbox-container  pid=140030 ppid=140027 uid=1000000  /usr/bin/sh  sh -c true d1792445353-vbox
2026-10-19T21:29:17Z  pbox-container  pid=140046 ppid=140044 uid=0  /usr/bin/sh  sh -c true d1792445353-pbox
2026-10-19T21:29:17Z  vbox-container  pid=140068 ppid=140060 uid=1000000  /usr/bin/sh  sh -c echo argv-check --donate-level-not d1792445353-follow > /dev/null
2026-10-19T21:29:20Z  pbox-container  pid=140090 ppid=140079 uid=0  /usr/bin/grep  grep Accepted /var/log/auth.log
```

In the 1-minute JSON replay the marker appeared three times (once per box
command above). The `-host` markers from `sh -c "true …"` and
`sudo sh -c "true …"` on the host appeared zero times.

### Overhead measurement

The CPU figures are `utime+stime` deltas of the daemon from
`/proc/<pid>/stat`, plus the `execwatch` program's `run_time_ns` delta
(`kernel.bpf_stats_enabled=1`), divided by wall time.

| Run | Rate | Daemon | Kernel prog | Total (one core) | Of 8 cores | Lost |
|---|---|---|---|---|---|---|
| idle | — | 2.88 % | 0.000 % | 2.88 % | 0.36 % | 0 → 0 |
| box execs, 65 s | 798.5/s | 40.88 % | 15.71 % | 56.59 % | 7.07 % | 0 → 0 |
| box execs, 60 s | 100.0/s | 10.91 % | 4.22 % | 15.13 % | 1.89 % | 0 → 0 |
| host execs (filtered in kernel), 35 s | 822.8/s | 3.17 % | 0.081 % | 3.25 % | 0.41 % | — |

The generator is serial `fork`+`waitpid` inside a 2-core box. It reached
798/s, not 1,000/s.

Filtered execs cost ~1 µs per program run. Emitted execs cost ~197 µs at
800/s and ~420 µs at 100/s. `perf record -g` on the daemon at 800/s put 82 %
of its samples in `ringbuf.(*Reader).Read` → `epoll.(*Poller).Wait`. That
points to one consumer wakeup per event, not to per-event allocation, so
the fix is not the same as #2747's. Details are in #2774.

## Real outputs, compared with `docs/security/PROCESS-GUARDRAIL.md` (PR #2716 at `496d87b0`)

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

With BTF unavailable:

```text
Sentry: OK
cpu-sampler: standalone (30s)
exec-telemetry: unavailable (netbpf: execwatch: load collection: program execwatch: apply CO-RE relocations: load kernel spec: parsing .BTF header: read header: buffer too small)

RULE                             HEALTHY  LAST ERROR
CROSS_TENANT_FLOW                true     -
DENY_BURST                       true     -
BAD_DESTINATION                  true     -
MINING_BEHAVIOR                  true     -
MINER_SIGNATURE                  true     -
```

`--json`: `{"state": "SENTRY_STATE_OK", "reason": "", "cpuSampler": "standalone (30s)", "execTelemetry": "ok", "execEventsLost": 0, "rules": [{"rule": "THREAT_RULE_ID_CROSS_TENANT_FLOW", "healthy": true, "lastError": "", "lastErrorAt": ""}, …]}`

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

On the verified build, with Postgres up:

```text
2026-10-19T21:10:40Z  pbox-container  pid=23255 ppid=23253 uid=0  /usr/bin/sh  sh -c echo @tcp; cat /proc/net/tcp 2>/dev/null\necho @tcp6; …
Error: decode stream chunk: invalid character 'u' looking for beginning of value
Usage:
  containarium security exec-events [flags]
  …
```

`--json` line format (one per event):

```json
{"container":"vbox-container","tenantId":"vbox","at":"2026-10-19T21:29:16.820937435Z","exec":{"pid":140030,"ppid":140027,"uid":1000000,"comm":"sh","filename":"/usr/bin/sh","argv":"sh -c true d1792445353-vbox","argvTruncated":false,"sha256":"","matched":""}}
```

### `containarium security miner-signatures list`

```text
Baseline version: 1
KIND    SOURCE    PATTERN                    LABEL
name    baseline  "xmrig"                    XMRig (Monero CPU/GPU miner)
name    baseline  "minerd"                   pooler cpuminer (minerd)
name    baseline  "cpuminer*"                cpuminer family
name    baseline  "nanominer"                nanominer
name    baseline  "t-rex"                    T-Rex GPU miner
name    baseline  "lolminer"                 lolMiner
name    baseline  "nbminer"                  NBMiner
name    baseline  "gminer"                   GMiner
argv    baseline  "--donate-level"           XMRig donate-level flag
argv    baseline  "stratum+tcp://"           stratum pool URL
argv    baseline  "stratum+ssl://"           stratum pool URL (TLS)
argv    baseline  "--coin "                  miner --coin flag
argv    baseline  "--coin=*"                 miner --coin=<coin> flag
argv    baseline  "-o *:3333"                pool on stratum port 3333
…       (likewise "-o *:<port>" for 4444 5555 7777 14444 14433)
argv    baseline  "--url=*:3333"             pool on stratum port 3333 (--url=)
argv    baseline  "--url *:3333"             pool on stratum port 3333 (--url)
argv    baseline  "-o[^/]*:3333"             pool on stratum port 3333 (-o attached)
…       (likewise for each default stratum port; 37 entries in all)
```

### `containarium security process-policy release`

```text
Released THROTTLE on vbox-container: CPU limit restored. Finding #1 resolved.
```

Restored exactly: `limits.cpu.allowance` `10ms/100ms` → `200ms/100ms`, and
`cpu.max` `10000 100000` → `200000 100000`.

### `findings list` row for a kill

```text
4      MINER_SIGNATURE              HIGH       OPEN     pbox           1      2026-10-19T21:17:46.009364Z name:xmrig
       exec pid 25872 /usr/local/bin/xmrig (comm xmrig) argv "/usr/local/bin/xmrig --donate-level 1" — matched name:xmrig
       response ALERT NONE, process killed
```

### Webhook payloads (as received)

New finding (no `response` key):

```json
{"id": 2, "rule": 7, "severity": 3, "tenant_id": "vbox", "container": "vbox-container", "backend_id": "verify-guest",
 "subject": "name:xmrig", "state": 1, "count": 1,
 "evidence": {"execs": [{"pid": 25050, "ppid": 23613, "uid": 1000000, "comm": "xmrig", "filename": "/usr/local/bin/xmrig",
   "argv": "/usr/local/bin/xmrig --donate-level 1", "matched": "name:xmrig"}]},
 "first_seen": {"seconds": 1792444461, "nanos": 2957307}, "last_seen": {"seconds": 1792444461, "nanos": 2957307}}
```

Applied, then released (finding #1, evidence omitted here):

```json
{"id": 1, "subject": "argv:--donate-level", "state": 1, "count": 2,
 "response": {"action": 2, "state": 2, "applied_at": {"seconds": 1792444461, "nanos": 14861150}, "expires_at": {"seconds": 1792530861, "nanos": 14861150}}}
{"id": 1, "subject": "argv:--donate-level", "state": 1, "count": 2,
 "response": {"action": 2, "state": 4, "applied_at": {…}, "expires_at": {…}, "released_at": {"seconds": 1792444515, "nanos": 645707221}, "released_by": "operator"}}
```

`SENTRY_UNAVAILABLE` (`rule: 8`, `severity: 2`) carries
`evidence.configs` instead of `execs`.

### Differences from the doc

1. **Release.** The doc says it covers the guardrail "as shipped in
   v0.109.0". No v0.109.0 tag or release exists (latest is v0.108.0), and
   #2711 records that W44 work is not in a release yet. The binary reports
   `v0.109.0` only because `version.go` is already bumped.
2. **`process-policy get` on a fresh backend.** The doc sample shows
   `kill process:       inherit`. The real output is
   `kill process:       false`. `inherit` would only make sense for a
   container override.
3. **`exec-events` examples.** On a Postgres-backed daemon all three doc
   examples print one event and then fail (#2773). The doc doesn't show
   the line format. The real format is
   `<RFC3339>  <container>  pid=<n> ppid=<n> uid=<n>  <path>  <argv>`,
   with newlines in argv shown as `\n`. `uid` is the host uid (an
   unprivileged box's root shows as `1000000`).
4. **`exec-events` JSON `matched`.** It is `""` even for an exec that
   raised a signature finding: the stream carries the event before it is
   matched. Say so, or readers will expect the stream to flag hits.
5. **Errors print the usage.** A runtime error from `exec-events` (503,
   decode error) prints the full cobra usage after the error.
6. **Webhook, first delivery.** The doc says a mining finding "is delivered
   at once as new (`NONE` …)". The payload has **no `response` object**,
   not `response.state: 1`. Consumers must treat a missing `response` as
   `NONE`. `rule`, `severity` and the finding `state` are numbers too, not
   only `response.state`.
7. **Webhook on operator release.** The single coalesced delivery still
   carries finding `state: 1` (open), although the same release resolved
   the finding. The resolve itself is never delivered.
8. **Webhook on kill.** The doc says "The finding's response shows
   `process killed`". That is true in `findings list` but never delivered
   by the webhook (#2775).
9. **Exec-telemetry overhead.** The doc's measured numbers (2.95 % of one
   core, 0.37 % of 8 cores) are the lane's. On an 8-vCPU KVM guest the
   same load cost 56.6 % of one core, 7.07 % of host CPU (#2774). Until
   #2774 lands, the doc should not state that the bar is met.
10. **`sentry status` with exec telemetry down.** The output matches the
    doc's shape (`Sentry: OK` with `exec-telemetry: unavailable (…)`), but
    `MINER_SIGNATURE` still reads `true` while the rule is blind. Rollout
    step 2 asks for `MINER_SIGNATURE true` *and* `exec-telemetry: ok`; the
    doc could say that the rule row alone does not show blindness.
11. **`findings list` row for `SENTRY_UNAVAILABLE`.** It renders an odd
    second line, `= in  — exec-telemetry: unavailable (…)` (no tenant, no
    exec evidence).
12. **Unchanged, matching the doc:** the `sentry status` OK layout, the
    `exec-events-lost` line omitted at 0, the `miner-signatures` matcher
    kinds and baseline (no sha256 entries), the literal argv substring rule
    (`--donate-level-not` matched `argv:--donate-level`), the release
    message format, the `THROTTLE` arithmetic (`10%` → `10ms/100ms`,
    `cpu.max 10000 100000`, `limits.cpu` unchanged), and the
    `kill`/`alert` audit entries under `security.action`.

## Environment notes (not defects)

- `PUT /v1/system/alerting` returns 503 `alerting is not configured` in
  `--standalone` mode. The webhook URL was set in `daemon_config`
  (`alert_webhook_url`) directly.
- Guest disks lived outside `/var/lib/libvirt/images`, which sits on a
  nearly full ZFS pool on the lab host. The guest, its disks, the proxy and
  its firewall rule were removed after the pass.
