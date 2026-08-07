# Spike — Containarium as an AX harness (`HarnessService` adapter)

> Status: **Executed 2026-08-07 — result: NO-GO for now.** The spike was built
> and run against `google/ax@f327e23` (2026-07-28). Two of four measurements
> passed; the two that carried the value failed. **The premise this spike was
> written on turned out to be false** — see [Correction](#correction) — and the
> durability gap it was meant to close is not closeable this way today.
>
> Read alongside [`AX-COMPARISON.md`](AX-COMPARISON.md) and
> [`product/agent-substrate-roadmap-position.md`](product/agent-substrate-roadmap-position.md).

## What was built

Two throwaway programs (scratchpad, not committed):

- **`harnessd`** — implements `ax.HarnessService.Connect`. Receives a turn,
  streams N `HarnessOutputs` frames, terminates with one `HarnessEnd`. It logs
  exactly what AX hands it on a first call vs. a resume.
- **`spike`** — drives the *real* AX controller with the *real* SQLite event
  log against `harnessd` over a plain dialed endpoint. Lives inside a clone of
  the ax module because `controller/` and `eventlog/` are under `internal/`.

## Correction

The proposal version of this doc claimed:

> *"AX replays history to the harness. `HarnessStart` carries
> `repeated Message messages`… a harness is stateless per execution, so
> adopting it doesn't just save us writing a durable store — it removes the
> requirement to have one."*

**That is wrong, and it was the whole reason to do this.** `HarnessStart.messages`
carries only the inputs supplied to *that* `Exec` call — never the conversation
history from the event log. Measured directly: a second turn on a conversation
with 7 logged events delivered `messages=1`, containing only the new input.

The implication inverts: a harness **must hold its own durable per-conversation
state**, keyed by `conversation_id`. AX's own `Harness` doc comment says so, and
I quoted it earlier without registering what it meant — *"a harness that durably
persists per-conversation state may use a last-write-wins store without
compare-and-swap."* The event log is the controller's **client-facing
transcript**, not a mechanism that relieves the harness of state.

So adopting AX would give us *more* state to keep, not less.

## Results

| # | Measurement | Result |
|---|---|---|
| 1 | Turn-model fit | **PASS** |
| 2 | How much of our state disappears | **FAIL — none** |
| 3 | Controller-restart resumption | **FAIL — not implemented** |
| 4 | Weight on a no-cluster host | **PASS** |

### 1. Turn-model fit — PASS

Incremental `HarnessOutputs` stream through live, each becoming its own event-log
step. Our in-box loop can yield mid-turn; we would not lose streaming.

```
11:44:47 [FIRST call#1] conversation="c1" messages=1
11:44:48   <- step=2  chunk 1/5
11:44:49   <- step=3  chunk 2/5
...                       (1s apart on both sides — genuinely incremental)
```

The event log persisted all of it: 7 rows for one turn, terminal
`STATE_COMPLETED` recorded.

### 2. State that disappears — FAIL

Nothing. Per the [correction](#correction), history is never replayed to the
harness. Neither `agent_task_queue.go` nor `crew_run_store.go` could be deleted;
we would additionally need a durable per-conversation store *inside* the harness
to make resumption mean anything.

### 3. Controller-restart resumption — FAIL

Killed the controller mid-turn (2 of 5 chunks written), leaving the conversation
`STATE_PENDING` with 3 events. Re-ran against the same `conversation_id`:

```
Exec conv="c2" inputs=0
Exec: harness execution failed: no input messages queued for execution turn
```

The resume **never reached the harness** — `harnessd` logged no second call. The
controller's resume branch calls `Start` + `Run` having queued nothing, and the
reference harness rejects an empty turn (`internal/harness/antigravity/antigravity.go:177-178`).
That error is itself the proof that the controller queues zero messages on resume.

This matches the code: `internal/controller/controller.go:72` —
`// TODO(jbd): Resume an incomplete execution if there exists one.` The
`last_step` field on `ExecRequest` is likewise **sent by the CLI and never read
by the server** — the only non-generated references are in `cmd/ax/exec.go`.
So client-side "replay missed events on reconnect" is not implemented either.

**Resumption — the reason to adopt AX — is a documented TODO, not a feature.**

Related, and worse: after the controller died the harness kept running, emitted
into a dead stream, and abandoned the turn. Its work was lost and nothing
recorded that it had happened. A controller crash orphans in-flight harness work.

### 4. Weight on a no-cluster host — PASS

The controller plus the SQLite event log plus a plain-dial harness links into a
**30.5 MB** static binary and ran on a laptop with no Kubernetes anywhere. The
event log was 12 KB after three conversations. `harnessd` itself is 15.3 MB.

AX's *core* genuinely does not need a cluster, even though the packaged
`ax serve` path pushes you toward Substrate.

## Two things the spike proved that are worth keeping

1. **The adapter is buildable with the public package alone.** `harnessd`
   depends on exactly one ax package — `go list -deps` returns
   `github.com/google/ax/proto` and nothing else. No `internal/` needed. If we
   ever revisit this, the integration is not blocked by packaging.
2. **The plain-endpoint slot works — but only with a patched binary.** Stock
   `ax serve` hardcodes `autoStart=true` for the built-in harness
   (`cmd/ax/internal/cliutil/cliutil.go:113`), and the sidecar will
   `killOrphanProcessOnAddr` any process already listening, then refuse to start
   with *"endpoint is already in use by another process"*
   (`internal/pythonsidecar/sidecar.go:91-97`). Our spike bypassed this by
   driving the controller directly. Upstream, the fix is one condition — pass
   `autoStart=false` when `endpoint` is explicitly configured — but external PRs
   are paused.

## Verdict against the stated go/no-go

The proposal set four go criteria. Two failed:

- ✅ In-box loop yields incremental outputs inside the turn model.
- ❌ At least the task queue is deletable — **nothing is deletable**.
- ❌ Controller-restart resumption demonstrated — **it is a TODO upstream**.
- ✅ Runs on a single host without Kubernetes.

**NO-GO.** Build the durable run store ourselves — the ~300 lines of Postgres
already scoped against `crew_run_store.go` and `agent_task_queue.go`. It is
strictly less work than adopting AX *and then still* having to build
per-conversation harness state to make AX's resumption work once upstream
implements it.

## What to keep from AX regardless

- **The single-writer invariant.** At most one execution per conversation,
  which is what licenses last-write-wins with no compare-and-swap. We are
  multi-backend and distributed and have no such guarantee today. This is the
  most valuable idea in their repo and it costs nothing.
- **The event-log shape.** `conversation_log(conversation_id, step, payload)`,
  protojson payloads, monotonic step as the ordering key, terminal state as its
  own row. ~290 lines total for the interface plus SQLite and Postgres drivers.
  A good model for ours.

## Re-check trigger

Revisit when `controller.go:72` stops being a TODO — i.e. when AX actually
implements resuming an incomplete execution, and decides whether the controller
replays history to the harness or the harness owns that state. That decision
determines whether this integration is ever attractive. Nothing else about AX
needs re-checking before then.

## Reproducing

Sources are in this session's scratchpad (`harnessd/`, `ax/internal/cmd/spike/`),
not committed — they are throwaway instruments, and the spike is closed.
