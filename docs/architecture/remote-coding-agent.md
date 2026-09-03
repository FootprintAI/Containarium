# Design: remote coding agent — durable run records & the disconnect harness

**Date:** 2026-09-02
**Status:** proposed
**Stack:** Go 1.26.6; protobuf/gRPC for the `SpawnService` boundary. No new
languages, no new services, no new deployables.

> Scope: the two hard parts only — (A) durable run-record semantics in
> `internal/agentbox`, (B) the forced-disconnect test harness that proves the
> north-star metric. The architecture is settled in
> `docs/product/remote-coding-agent.md` and is not restated here.
> Issues: #1672 (A), #1674 (consumes A + B), #1673, #1675.

## Problem

`agent-box` loses a run's identity when the connection that started it dies
(`processRegistry` is an in-memory map, `process.go:59`) and discards its exit
status (`process.go:184`). Both must become durable for a run to be driveable
over a link that drops. Separately, the feature's north-star metric — *0 bytes
lost or duplicated across ≥20 forced mid-run disconnects* — has no harness that
can produce those disconnects deterministically.

---

# Part A — durable run records

## Two findings that shape the design

**A1. `processLogDir` is a `const` (`process.go:44`).** Every process test today
writes to the real `/tmp/agent-box`. Record tests need to assert on-disk state,
so this must become an **injectable package var** set by tests to `t.TempDir()`.
This is a prerequisite, not a nicety: without it the record tests are neither
isolated nor parallel-safe.

**A2. Atomicity of the write is not liveness of the writer.** The exit status is
recorded by a goroutine after `cmd.Wait()`. If the box dies between the process
exiting and the record being written, no atomic-write technique helps — the write
never happens. So "PID dead, no recorded exit code" is a **real, reachable
state** and must be modelled as a first-class outcome, not an error or an
assumed-success.

## Data model

The record is a boundary: written by one `agent-box` process, read by a
different one. Per CLAUDE.md it gets a named struct, not a map, and a version
field because a newer agent-box may read an older record.

```go
// RunRecordVersion is bumped when the on-disk shape changes incompatibly.
const RunRecordVersion = 1

type RunOutcome string

const (
    RunOutcomeRunning  RunOutcome = "running"  // boot matches, PID alive
    RunOutcomeExited   RunOutcome = "exited"   // ExitCode is authoritative
    RunOutcomeUnknown  RunOutcome = "unknown"  // see A2 / boot mismatch
)

type CaptureMode string

const (
    CaptureCombined CaptureMode = "combined" // default: today's plain text
    CaptureFramed   CaptureMode = "framed"   // opt-in: see Part A, framing
)

type RunRecord struct {
    Version     int         `json:"version"`
    Name        string      `json:"name"`
    PID         int         `json:"pid"`
    BootID      string      `json:"boot_id"`
    Command     string      `json:"command"`
    Cwd         string      `json:"cwd"`
    CaptureMode CaptureMode `json:"capture_mode"`
    LogPath     string      `json:"log_path"`
    StartedAt   time.Time   `json:"started_at"`

    // Written only by the reaper goroutine, at exit.
    FinishedAt *time.Time `json:"finished_at,omitempty"`
    ExitCode   *int       `json:"exit_code,omitempty"`
}
```

`ExitCode` and `FinishedAt` are **pointers on purpose**: absent ≠ zero. A
non-pointer `int` would render a killed box indistinguishable from `exit 0`,
which is precisely the bug this design exists to prevent.

Stored at `<processLogDir>/<sanitized-name>.json`, beside its `.log`. Records
and logs then share one directory and one cleanup story, so an orphan record
pointing at a deleted log cannot arise.

## Outcome resolution — the core logic

This is the only interesting logic in Part A, and it is pure: `(record,
currentBootID, aliveFn) → RunOutcome`. Pure means table-driven tests with no
processes, no filesystem, no clock.

| Boot ID | `ExitCode` | `isAlive(PID)` | Outcome | Why |
|---|---|---|---|---|
| matches | set | — | `exited` | Recorded status is authoritative |
| matches | absent | true | `running` | Live process, still going |
| matches | absent | false | **`unknown`** | A2: died before the reaper wrote |
| **differs** | set | — | `exited` | Status was recorded before the reboot; still true |
| **differs** | absent | — | **`unknown`** | PID belongs to another boot — never trust it |

The boot-ID rule is a **correctness** requirement, not hygiene. `isAlive` is
`syscall.Kill(pid, 0)` (`process.go:314`); across a reboot the kernel may have
reassigned that PID, so consulting liveness on a stale boot would report a
finished run as *alive* and let `process_kill` signal an unrelated process.
Because `/tmp` is not guaranteed to clear on reboot (Ubuntu 24.04 does not
default it to tmpfs), the guard must live in the record, not the filesystem.

Boot ID source: `/proc/sys/kernel/random/boot_id`, read once at startup and
injected — a package var, so tests set it directly rather than faking `/proc`.

## Write path & atomicity

Reuse the temp-then-rename pattern already idiomatic in this package
(`files.go:264-283`): `os.CreateTemp` in the same directory, write, `fsync`,
`os.Rename`. Rename within a directory is atomic, so a reader never observes a
half-written record. Two writes per run:

1. `spawnBackgroundProcess` — the initial record, **before** returning, so the
   run is discoverable even if the caller dies immediately after.
2. The reaper goroutine — rewrite with `ExitCode` + `FinishedAt` captured from
   `cmd.Wait()` instead of discarding it.

Both land in `spawnBackgroundProcess`, the shared core behind the MCP tool *and*
`SpawnService.Spawn` ("one implementation, two transports", `process.go:120-125`),
so both transports inherit durability from one change.

## Name collision across connections

`spawnBackgroundProcess` opens the log `O_TRUNC` (`process.go:148`) and checks
collisions only against the in-memory registry (`:137`). After a reconnect the
registry is empty, so reusing a name **silently truncates the previous run's
log** — destroying the output the whole feature exists to preserve. Worse,
`tail_log` seeks to a caller-supplied offset with no truncation detection
(`tail_log.go:108`), so a resuming client would read from a stale offset into a
new file and return garbage without erroring.

Resolution — the collision check consults records, not just the registry:

| Existing record's outcome | Behavior |
|---|---|
| `running` | **Reject** — `ErrProcessNameInUse`, as today |
| `unknown` | **Reject** — refusing to destroy the only evidence of an unresolved run |
| `exited` | **Rotate**: rename `.log`/`.json` to `.<started_at unix>.log/.json`, then start fresh |

Never silently truncate.

## Framing (`capture_mode`) — corrected from the issue thread

**The decision recorded on #1674 named Docker's `stdcopy` binary header. That is
wrong here.** `tail_log` returns file content inside an **MCP text result**
(`tail_log.go:162`, `mcp.NewToolResultText`). Binary framing bytes — and any
multi-byte rune split across a read boundary — would be mangled by JSON's UTF-8
encoding, silently corrupting the very stream we are trying to keep intact.

Framing must therefore be **text-safe**. One frame per line:

```
<stream> <base64(payload)>\n        # stream ∈ {"1","2"} (stdout, stderr)
```

- **Line-oriented** → a read cut mid-line is detectable; the client buffers the
  partial line and completes it on the next read. Byte-exact resume makes this
  sound: successive reads concatenate to exactly the original stream.
- **base64 payload** → immune to invalid UTF-8 and to runes split across writes.
  Costs ~33% size, which is the right trade for a mode whose only consumer is a
  demuxing client.
- **One file, one offset** → `tail_log`'s `start_offset`/`end_offset` contract is
  **completely unchanged**. It stays a dumb byte-range reader, which it must
  remain: it is used on files it did not create, e.g. `/var/log/caddy/access.log`
  (`tail_log.go:22`).

`combined` stays the default, so every existing caller and every human-tailed log
(dev servers, builds) is unaffected and stays plain text.

## Contract change: `SpawnRequest.capture_mode`

`SpawnServer.Spawn` calls the same shared core (`spawn_server.go:36`). Leaving
`capture_mode` MCP-only would make the two transports asymmetric over one
implementation. Per CLAUDE.md (proto-first, enums over magic strings), add to
`proto/containarium/v1/sandbox.proto`:

```proto
enum CaptureMode {
  CAPTURE_MODE_UNSPECIFIED = 0;  // treated as COMBINED
  CAPTURE_MODE_COMBINED    = 1;
  CAPTURE_MODE_FRAMED      = 2;
}
// in SpawnRequest:
CaptureMode capture_mode = <next>;
```

`SpawnService` has no `google.api.http` annotations by design
(`sandbox.proto:253`) and must stay off the REST gateway.

> **Correction to an earlier claim:** I previously told the user "no proto
> changes needed for any of the four issues." That was wrong — this is one. It
> is additive and backward-compatible (`UNSPECIFIED` → `COMBINED`), and
> `make proto` churns `.pb.gw.go` files that should be `git checkout --`'d.

---

# Part B — the forced-disconnect harness

## The assertion

One assertion catches both failure modes. The box runs a **deterministic
generator** emitting a seeded, self-describing byte stream of known length. The
client reads it through drops and reconnects, concatenating what it receives.

```
received == expected   (byte-for-byte)
```

Loss shortens or gaps it; duplication lengthens it. No separate "did we
duplicate?" check is needed, and any failure is localizable to a byte offset.

The generator must **not** be `yes` or a constant — a duplicated constant chunk
is invisible. Use a seeded PRNG rendered as fixed-width numbered lines, so the
first divergent line names the offset and the failure mode on sight.

## Two layers

The valuable layer is the one that runs in CI. Both are required; only the first
gates the build.

### B1 — resume logic, no box (`internal/...`, standard `go test` lane)

The client's resumable reader takes a transport interface:

```go
type LogReader interface {
    // Read returns bytes from startOffset, the new end offset, and whether
    // the read was cut short by the output limit.
    Read(ctx context.Context, path string, startOffset int64, follow time.Duration) (data []byte, endOffset int64, truncated bool, err error)
}
```

That seam is the whole design for testability. A `faultyReader` wraps a real
local-file reader and fails on a **seeded, deterministic schedule** (drop after
every N bytes, N from the seed). A failing run reproduces exactly from its seed —
non-negotiable for a test asserting on 20+ drops.

Cases: clean read; drop mid-read; drop between reads; reconnect at a
frame boundary; reconnect **mid-frame** (the partial-line buffer); `truncated:
true` handling; ≥20 drops over a multi-MB stream; zero-length reads; offset past
EOF.

**One case that is easy to miss:** `tailLogOutputLimit` is 256 KiB
(`tail_log.go:28`); on hitting it the reader returns `truncated: true` with a
correct `endOffset` (`:160`). A client that treats that like "no more data yet"
and sleeps `tailLogPollInterval` before re-reading is correct but slow; one that
treats it as EOF **silently truncates the run's output**. The harness must assert
the client re-reads *immediately* on `truncated: true`.

### B2 — real transport, real drops (`test/integration`, `needs-verification`)

Same generator and same assertion, over real SSH to a real box, with drops
produced by killing the ssh process mid-run. Proves what B1 stubs: that a real
transport failure surfaces as an error the client retries rather than as a silent
short read. Cannot run in the unit lane (needs a live box — the repo's standing
"needs a live box" seam), so it is a separate lane and does not gate the unit
build.

## Test strategy

| Component | Unit (CI gate) | Contract | Integration / e2e |
|---|---|---|---|
| Outcome resolution | Table-driven over the 5-row matrix above + zero/negative PID | — | — |
| Record write/read | Temp+rename atomicity; concurrent readers see old-or-new, never partial; version mismatch rejected cleanly | JSON round-trip: `ExitCode` absent ≠ `0` | — |
| Cross-connection recovery | Clear the in-memory registry, re-read from disk, assert `process_list`/`process_kill` still resolve | — | Real agent-box restart over SSH (B2) |
| Name collision | Table over `running`/`unknown`/`exited` → reject/reject/rotate; assert **no** `O_TRUNC` on a live log | — | — |
| Framing | Encode/decode round-trip; multi-byte runes split across writes; interleaved stdout/stderr ordering preserved | Generated `SpawnRequest.capture_mode` honored identically via MCP and gRPC | — |
| Resumable reader | B1, seeded, ≥20 drops | Against the real `tail_log` handler, not a hand-rolled fake | B2 |

Type gate: `go vet` + `go build`, as the existing lane.

`processLogDir` becomes an injectable var (A1) so every row above uses
`t.TempDir()` and runs parallel-safe.

## Language choices

| Component | Language | Why this one | Type gate in CI |
|---|---|---|---|
| `internal/agentbox` records + framing | Go | Existing package; `SpawnService`'s shared core is already here | `go vet` / `go build` |
| `containarium code` client | Go | Existing cobra CLI; CLI-first per CLAUDE.md | `go vet` / `go build` |
| Disconnect harness | Go | Same lane as the code under test | `go vet` / `go build` |

No new languages. No new deployables — this ships inside the existing
`agent-box` and `containarium` binaries.

## Deviations from the default stack

**None.** The on-disk record is JSON rather than protobuf: it is process-local
state under `/tmp` read only by the same binary that wrote it, not a wire
contract between components, and JSON keeps it debuggable with `cat`. The
cross-process contract that *is* on the wire — `SpawnRequest.capture_mode` — is
protobuf, as required.

## Rejected alternatives

- **Two log files (stdout, stderr).** Doubles the reconnect contract to two
  offsets that must resume consistently, and makes true interleaving order
  unrecoverable. The single framed stream keeps one offset and preserves order.
- **Docker `stdcopy` binary framing.** Recorded on #1674, rejected here: it does
  not survive the MCP **text** result channel (`tail_log.go:162`). See Framing.
- **A persistent path for records (`/var/lib/...`).** Rejected as a *liability*:
  surviving a reboot means holding PIDs the kernel may have reassigned. The
  boot-ID guard is required regardless (because `/tmp` may not clear), and with
  it in place the extra durability buys nothing the feature needs.
- **A dedicated streaming RPC instead of offset polling.** Would make `tail_log`
  stateful and add a transport the CLI does not otherwise need; polling with
  byte-exact offsets already yields lossless resume, and the resume logic must
  exist anyway for the reconnect case.
- **SQLite for run state.** A dependency and a lockfile for what is a handful of
  small files with single-writer-per-name semantics.

## What changes at 10x

Nothing here is throughput-sensitive — one record per run, one reader per run.
The first thing to break is **unbounded log growth** in `/tmp` (already tracked
as a phase-2 item in the PRD), and log rotation would then have to preserve the
offset contract: rotating mid-run invalidates a client's offset, so rotation must
either be run-boundary-only or the record must carry a rotation generation the
client can detect.
