# PRD: Remote coding agent — the laptop runs nothing

**Date:** 2026-09-02
**Status:** draft
**Owner:** hsinhoyeh

## Problem

A coding agent today runs on the developer's **laptop**. That couples every
long-running task to one machine being awake, unlocked, on power, and on a
stable network. The developer cannot start a refactor and walk away, and the
agent's CPU, disk, and context compete with everything else on the machine.

The workaround is expert-only: `ssh` to a host, start `tmux`, run the agent,
reconnect later. It works, but it is manual every time, and it degrades badly
on exactly the connection a mobile developer has.

**Evidence (in-repo, not user research):**

- `docs/PRD-HOSTED-AGENT-WORKSPACE.md` §1 names the same problem for the *chat*
  workspace case and frames "SSH to a server, run an agent in tmux, reconnect
  later" as the unacceptable status quo. This PRD covers the **CLI/repo** case
  that PRD deferred.
- `internal/cmd/quickstart.go:116` — `--agent claude|gemini|codex` launches
  **your local agent** on your laptop. Every agent path we ship today either
  runs the harness locally (quickstart, `agent-box` over SSH) or runs it
  headless with no repo (`agent-runtime`). Nothing runs a *coding* agent on a
  *repo* in a box.
- No user quotes, tickets, or usage metrics exist. The demand signal is a
  single internal request. **This is an assumption, not validated demand** —
  see Open questions.

## Target user

**The developer who wants their laptop out of the loop — including the tests.**
Comfortable with a terminal and with a coding agent. Wants to start, watch,
steer, and land an agent-driven change on a real repo, over a connection that
will drop, without the laptop being the compute or a requirement.

**JTBD:** *"Start a coding task against my repo from a thin local command, have
it and my test suite run in a box, drop off the network without losing the run
or its output, and pick the stream back up where I left it."*

**Not this PRD:** the browser-chat/preview builder
(`docs/PRD-HOSTED-AGENT-WORKSPACE.md`, OpenHands-in-a-box), the headless
one-shot skill user (`agent-runtime` / `containarium agent run`), and the
multi-agent crew operator.

## Architecture decision (settled)

**The pipe is the interface; a resumable reader is the mechanism.**

It should *feel* local — `claude -p "…"` with output streaming to the terminal.
It must not *be* a pipe: on a mobile connection the link drops mid-run, and a
pipe loses every byte the client was not attached for. So the run is spawned
detached on the box, its output is captured to a durable log, and the local
client is a **resumable reader over (log, offset)** rather than a pipe consumer.

The primitives are in `agent-box` (`internal/agentbox/process.go`):

| Tool | Role |
| --- | --- |
| `process_start` | `setsid` + spawn; combined stdout+stderr → `/tmp/agent-box/<name>.log`, mode 0600 |
| `tail_log` | read from `start_offset`, return `end_offset`, bounded by `follow_seconds` |
| `process_list` | PID, command, liveness |
| `process_kill` | SIGTERM/SIGKILL; the log file is deliberately left in place |

**What was verified against the code — three findings that set the scope:**

1. **Resumable byte-exact reads: already correct, no work needed.**
   `internal/agentbox/tail_log.go:42` documents `end_offset` as *"suitable for
   resuming on the next call"*; `start_offset` defaults to file-size-at-call
   (`tail -f` from now) and accepts `0` to backfill (`tail_log.go:95-97`,
   seek at `:108`). Reconnect is lossless and duplicate-free. This is the
   contract the whole design rests on, and it exists.

2. **Process identity does not survive a dropped link.** `processRegistry`
   (`process.go:59`) is an **in-memory map**, and agent-box is a stdio MCP
   server spawned per SSH connection (`cmd/agent-box/main.go`). When the network
   drops: the `setsid`'d agent survives, the log file survives, but the registry
   dies with the connection. A reconnected agent-box has an empty map, so
   `process_list` shows nothing and `process_kill <name>` returns not-found.
   Output is recoverable (the log is addressed by *path*, needing no registry);
   **liveness, PID, and control are not.**

3. **Exit status is discarded.** `process.go:184` is
   `go func() { _ = cmd.Wait(); _ = logFile.Close() }()` — the exit status is
   dropped, and `process_list` reports only `isAlive(mp.PID)` (`:222`). After a
   run ends you can learn *that* it finished, never *whether it succeeded*. For
   "did the agent's test run pass?" that is the one bit that matters, and if
   you were not attached at exit it is unrecoverable.

Findings 2 and 3 share one fix: **persist a run record on disk beside the log**,
so the run's *state* becomes as durable as its *output*.

**Rejected transport — `connect --session --exec`.** An earlier draft of this
PRD proposed it. It is wrong for agent-length work: ssh is capped at 90s and the
box-side poll at 60s (`internal/cmd/connect.go:270`,
`BuildSessionExecArgs(..., 60)`; `connectcore/session.go:36` →
`ErrSessionTimeout`), and output is buffered into a `bytes.Buffer`
(`connect.go:280`) rather than streamed. An agent run times out. `connect`
remains the right tool for *attaching a terminal* (`--session` with no
`--exec`), not for driving a run.

**The box is the developer's existing dev environment.** "Run the tests
remotely too" means the box needs the project's toolchain, dependencies,
services, and fixtures. A fresh single-purpose box would have Claude and none of
the project. So the unit of work is **"add Claude to a box you already have"**,
not "a new box type".

## Success metrics

| Metric | Baseline | Target |
| --- | --- | --- |
| **Reconnect losslessness** — bytes missing or duplicated across a forced mid-run disconnect | unverified; `tail_log` offsets suggest 0 but nobody has measured it | **0 bytes**, over ≥ 20 forced drops |
| Run survival — run still alive and its outcome still recoverable after the client dies | output: expected to survive; **outcome: 0%** today (exit status discarded, `process.go:184`) | > 99% for both |
| Time from `containarium code run` to first streamed output | unknown — instrument first | < 10s on an existing box |

Reconnect losslessness is the north star. It is the one property that separates
this from "ssh and tmux", and the only one the mobile case actually turns on.

## MVP scope — the core journey

> From a thin local command against a box I already use: give a prompt, watch
> the agent and my tests run remotely, lose the network, reconnect, and pick the
> stream up exactly where it stopped — then learn whether it passed.

---

**Story 1 — durable run records in `agent-box`**

**Story:** As a developer on an unstable connection, I want a run's identity and
outcome to survive my connection dying, so that reconnecting restores control
and tells me whether the run succeeded.

**Acceptance criteria:**
- [ ] `process_start` writes a run record to disk beside the log (name, PID,
      command, started-at), readable by any later agent-box instance.
- [ ] The `cmd.Wait()` goroutine records **exit code and finished-at** into that
      record instead of discarding the status (`process.go:184`).
- [ ] After the spawning agent-box exits and a **new one starts**,
      `process_list` still reports the run with correct liveness, and
      `process_kill <name>` finds and stops it.
- [ ] `process_list` reports the exit code of a run that has already finished,
      including one that finished while no client was connected.
- [ ] A run record whose PID is dead but which has no recorded exit code is
      reported as such, rather than silently as "finished" — a killed box or an
      OOM must be distinguishable from a clean exit.
- [ ] Records survive an agent-box restart but are not required to survive a box
      reboot (`/tmp` semantics documented, not fought).

**Priority:** P0 — this is the whole mobility property, and it is ~one struct
plus two writes.

---

**Story 2 — Claude toolchain into an existing box**

**Story:** As a developer, I want to add Claude Code and its credential to a box
I already use, so that the agent runs where my toolchain, dependencies, and
tests already live.

**Acceptance criteria:**
- [ ] One command installs `claude` onto an **existing, already-provisioned**
      box and leaves the rest of that box untouched. (Recipes today deploy new
      boxes; if no apply-to-existing path exists, that is the work.)
- [ ] The credential is delivered via the secrets mechanism as
      `CLAUDE_CODE_OAUTH_TOKEN` — minted once on a trusted machine with
      `claude setup-token`, then
      `containarium secrets set <user> CLAUDE_CODE_OAUTH_TOKEN <token>` — and
      never appears as a parameter or in an install log.
- [ ] `claude -p "print the current working directory"` on the box returns a
      non-empty response with no interactive prompt and no TTY attached.
- [ ] The install asserts `ANTHROPIC_API_KEY` and `ANTHROPIC_AUTH_TOKEN` are
      **unset** on the box — both outrank `CLAUDE_CODE_OAUTH_TOKEN` in Claude
      Code's auth precedence and would silently win.
- [ ] `--bare` is not used anywhere on this path; bare mode does not read
      `CLAUDE_CODE_OAUTH_TOKEN`.
- [ ] Installing with no credential set fails naming the `secrets set` command,
      rather than hanging on a login prompt.

**Priority:** P0

---

**Story 3 — `containarium code`, a resumable reader**

**Story:** As a developer, I want a local command that feels like running the
agent in a pipe but survives my network dropping, so that mobility costs me
nothing.

**Acceptance criteria:**
- [ ] `containarium code run <box> --prompt "<text>"` spawns the agent detached
      on the box and streams output locally **as it is produced** — not buffered
      to completion, and with no 60s/90s ceiling anywhere on the path.
- [ ] Killing the local client does not kill the run.
- [ ] `containarium code attach <box>` reconnects and **replays output produced
      while disconnected**, byte-exact: nothing missing, nothing repeated.
- [ ] A mid-run network drop is recovered automatically by resuming at the last
      `end_offset`, without the user re-issuing a command.
- [ ] `containarium code status <box>` reports liveness and, once finished, the
      exit code — including for a run that ended while disconnected.
- [ ] `containarium code stop <box>` reaps the run and leaves its log readable.
- [ ] stdout and stderr are separable: with `--output-format stream-json` the
      structured stream is not corrupted by interleaved diagnostics.
      (`process_start` captures them **combined** today — `process.go:117` — so
      this needs a split, or an explicit decision to keep combined logs and
      forgo structured output.)
- [ ] Per the CLI-first convention, the MCP tool wraps the same Go function.

**Priority:** P0

---

**Story 4 — getting the work back without adding a credential**

**Story:** As a developer, I want the agent's commits back on my laptop without
granting the box any forge access it did not already have, so that an agent with
a shell cannot push somewhere I did not intend.

**Acceptance criteria:**
- [ ] The documented journey ends with the agent's work on a local branch the
      developer reviews and pushes themselves.
- [ ] `containarium push <box>` / pull over the existing SSH path (real
      `git push` into the bare repo at `~/work.git`) is sufficient for the round
      trip — no new credential is introduced for the MVP journey.
- [ ] Where the box **already** holds git credentials (likely, since it is the
      developer's existing dev box), this is stated explicitly rather than
      assumed away: the MVP commitment is *"adds no new forge access"*, not
      *"the box has none"*.
- [ ] The limitation is documented plainly: the agent cannot open a PR on its
      own, and that is the deliberate price of adding no credential.

**Priority:** P0

## Later phases

- **P1 — attach from a phone.** The web-ui Terminal
  (`internal/gateway/terminal.go`) execs a fresh `su - <user>` per WebSocket;
  point it at a run's log instead so a phone tails a live run. Once Story 1
  lands this is nearly free, and it converts "the laptop is not the compute"
  into "the laptop is not required".
- **P1 — egress allowlist + audit.** The box must reach `api.anthropic.com` and
  the git remote. Land the allowlist entries and prove a clean run under eBPF
  `LOG_ONLY` with zero denies for legitimate flows **before** anything is armed
  — `agent-runtime/README.md` and issue #611 warn that arming ENFORCE first
  strands the agent.
- **P1 — log rotation / size bounds.** A long agent run writing to a single
  `/tmp` file is unbounded. Not MVP-blocking, but it is a disk-full incident
  waiting to happen (cf. project memory: disk-full corrupts Go module caches).
- **P1 — run-finished signal.** "Walk away" is half-delivered if you have to
  poll for the exit code Story 1 now records.
- **P1 — per-repo deploy key**, generated in-box with only the public half
  registered, for the case where the agent should push on its own. Manual today
  (cloud collaborator/CI-CD gap, #1105–#1109).
- **P1 — `apiKeyHelper` instead of a resident token.** Claude Code re-runs the
  helper every 5 min (`CLAUDE_CODE_API_KEY_HELPER_TTL_MS`); pointing it at the
  secrets store means the credential is fetched, never resident on box disk or
  env. Needs the spike in Open questions.
- **P2 — GitHub App installation tokens** (1h, repo-scoped) as the real
  credential answer at scale.
- **P2 — engine choice (Codex / Gemini).** `agent-runtime` already abstracts
  three engines behind `src/engine.ts`; same pattern once the Claude path is
  proven.

## Out of scope

- **`connect --session --exec` as the run transport.** Timeout-bounded and
  buffered; see Architecture decision. It stays the terminal-attach tool.
- **A native chat UI.** `PRD-HOSTED-AGENT-WORKSPACE` deferred this to its Phase
  3, and a terminal attach already exists. Building a chat surface to reach a
  CLI agent is strictly more work than attaching to the CLI.
- **A new single-purpose `claude-code` box type.** It would have Claude and none
  of the developer's toolchain, which defeats "run the tests remotely".
- **Interactive `claude` login as the supported path.** It does work in a
  container — the browser shows a code you paste at the `Paste code here if
  prompted` prompt — but the login expires, and Anthropic's docs note that an
  unattended session outliving its login stops making progress and cannot
  recover until someone signs in again. A one-year `setup-token` is the right
  credential for a long-lived box. Interactive login stays a documented manual
  fallback.
- **Remote Control** (`claude remote-control` + claude.ai/code + the mobile app)
  as the mobility surface. Attractive and zero-UI, but it requires a claude.ai
  `/login` — **API keys are not supported** — and a `setup-token` credential
  explicitly *cannot* establish Remote Control sessions. Adopting it would force
  back the expiring-login model this PRD rejects. Revisit if that changes.
- **A GitHub PAT added to the box** for MVP. The easy answer and the wrong one:
  an agent with a shell plus a broad PAT can push anywhere the PAT reaches, and
  it contradicts the principle already stated at
  `internal/cmd/runner_reconcile.go:43` — *"so no GitHub PAT or privileged auth
  context has to live inside the daemon."*
- **SSH agent forwarding** for git. It requires the laptop live, defeating the
  premise.
- **Replacing `agent-runtime`.** That is the headless task→artifact path and
  stays as-is; this is the interactive, repo-attached path.
- **Multi-agent crews**, **model gateway metering for this path**, and **GPU
  boxes.** None are on the core journey.

## Open questions & assumptions

1. **Is `/tmp/agent-box/` the right home for run records?** `process.go:44`
   puts logs there, so records beside them is the consistent choice — but `/tmp`
   may be cleaned or tmpfs-backed, losing history across a box reboot. *Decide:*
   accept and document `/tmp` semantics for MVP, or move both to a persistent
   path. Do not let this block Story 1.

2. **Combined vs split stdout/stderr.** `process.go:117` captures them combined,
   which is right for human reading and wrong for `--output-format stream-json`.
   *Decide before Story 3:* split into two logs (two offsets to track), or keep
   combined and drop structured output from MVP.

3. **Does `apiKeyHelper` accept an OAuth token value?** The docs describe it as
   returning "an API key", and it ranks *above* `CLAUDE_CODE_OAUTH_TOKEN` in
   precedence. If it only accepts Console API keys, the P1 "fetch, never
   resident" improvement does not apply to subscription auth. *Validate:*
   one-line spike.

4. **Enterprise managed settings could block this entirely.** If a managed
   settings source sets `forceLoginOrgUUID`, sessions authenticated by
   `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, or `apiKeyHelper` are blocked at
   startup, and `claude setup-token` enforces only `forceLoginMethod` — so a
   token could be minted in the wrong organization. *Validate:* confirm our own
   plan's settings before dogfooding; document the constraint for any customer
   on Enterprise.

5. **Terms of a subscription credential on a hosted box.** The token is the
   *user's own* credential in *their own* tenant's secrets, which is materially
   more defensible than pooling credentials — but it remains a terms question,
   not an engineering one, before this ships as a customer-facing feature rather
   than internal tooling. *Validate:* read the subscription terms.

6. **Token expiry on a long-lived box.** `setup-token` is one year, which defers
   rather than removes the problem, and there is no renewal path that avoids a
   human and a browser. *Assumption:* one year suffices for MVP.

7. **Demand is assumed, not evidenced.** One internal request; no tickets, no
   quotes, no usage data. *Validate:* the MVP is small enough to be its own
   experiment — ship it, dogfood it for two weeks, and measure whether anyone
   uses it twice.
