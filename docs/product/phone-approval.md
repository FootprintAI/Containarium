# PRD: Approve an agent's permission request from your phone

**Date:** 2026-09-30
**Status:** draft
**Owner:** hsinhoyeh

## Problem

`containarium code run` already takes the laptop out of the loop: the agent
runs detached on a box, and `code attach` resumes its output losslessly
(`docs/product/remote-coding-agent.md`). What it cannot do is **wait for you**.

A headless agent that reaches an action needing permission has two outcomes
today, and both are bad:

1. **It is denied.** `code run` launches `claude -p` with no permission prompt
   hook (`internal/coderun/ops.go` `BuildClaudeRunCommand`,
   `internal/coderun/engine/claude.go` `claudeRunBody`). A gated tool call is
   refused, the agent works around it or gives up, and the developer finds out
   hours later when they read the log. The run "succeeded" at the wrong task.
2. **It is pre-authorized broadly.** To avoid (1), the developer grants wide
   permissions up front (allow-lists or bypass mode). The agent then runs
   unsupervised with a shell and a credential inside their infrastructure,
   which is exactly what `docs/product/agent-governance.md` says blocks an
   enterprise purchase.

There is no third option where the run **pauses, tells you, and continues
when you answer**, even though that is the whole reason to run an agent on a
box instead of on the laptop. Nothing in the product reaches the developer
when they are away from a terminal except the completion email
(Containarium-cloud #1862), and that fires only on terminal states.

**Evidence:**

- OSS #2124 states the same gap for crew and skill runs: "No run pauses to
  ask … a permission prompt … either auto-denies or blocks inside the engine
  with nothing observable."
- Containarium-cloud `docs/product/mobile-agent-supervision.md`, open
  question 5: "'Needs input' does not exist as a platform state."
- Market signal, not user research: at least one competitor
  (a hosted "cloud computer for agents" product) leads its pitch with
  "your computer is off, the task keeps running; when it needs you, your
  phone notifies you and you approve." Its launch post drew more replies than
  likes. That shows the framing resonates; it does not show our users want it.
- **No user quotes, tickets, or usage data exist.** How often `code run` hits
  a gated action is not instrumented. Demand is an **assumption**; see Open
  questions.

## Target user

**The developer who starts a coding run on a box and walks away.** Terminal
comfortable, uses `code run` (or will), and has at least one task that needs
something the agent should not do unasked: push a branch, run a migration,
install a package, touch a file outside the repo.

**JTBD:** *"Let my agent run with narrow permissions while I'm away; when it
needs a wider one, ask me on my phone, and keep going as soon as I tap."*

**Not this PRD:** the browser run page and "needs you" email for crew runs
(Containarium-cloud #1889), and console attach to an interactive tmux
session (cloud PRD, P1). This PRD is the **OSS, CLI-first** slice: `code run`
on any box, cloud or self-hosted, answered from the CLI and from a push
notification.

## Relationship to existing work (read first)

This PRD does **not** introduce a second pause/answer mechanism.

- **Mechanism = OSS #2124.** Journal events `input_request` /
  `input_response`, a `waiting_input` state, and a proto-first
  `AnswerRunInput` RPC. #2124 scopes it to crew runs; this PRD extends the
  same contract to `code run` box runs, whose records OSS #2123
  (`ListBoxRuns`, `TailBoxRunLog`) already exposes.
- **Push channel = pulls the cloud PRD's P2 "chat-app bridge" forward, and
  narrows it.** The cloud PRD deferred Telegram/Slack/LINE over bot-token
  custody. This PRD's MVP channel is **ntfy**: self-hostable, no bot account,
  one access token the operator already controls, and notification action
  buttons that can call back an HTTP endpoint. LINE and Telegram are P1.
- **Gate = cloud #1865 spike.** #2124 waits for the relay-app verdict. See
  Open question 1 for why the CLI half should not wait.

## Success metrics

| Metric | Baseline | Target |
|---|---|---|
| Share of `code run` runs that raise ≥1 permission request and get it answered (either way) instead of auto-denied or expired | 0% (no mechanism); request rate unknown, so **instrument first** | ≥ 60% of requests answered before expiry, among users with a channel configured, 30 days after release |
| Median request → answer latency, answers from the push channel | n/a | < 5 min |
| Share of runs started with `--approvals ask` rather than broad pre-authorization | unknown, **instrument first** | directional: rising release over release (no target until a baseline exists) |

The first metric is the demand test. If users configure a channel and then let
most requests expire, the phone is not where they want to answer, and P1
channels are not built.

## MVP scope: the core journey

> Start a run with `--approvals ask` → close the laptop → the agent asks to
> run a gated command → phone buzzes with the command and Allow / Deny → tap
> Allow → the run continues and finishes → `code attach` later shows the
> request, who answered, from where, and when.

Engine scope: **Claude Code only** in the MVP. pi and others get the #2124
documented fallback (auto-deny, journaled) so behavior is visible, never
silent.

### Story 1: a run pauses instead of auto-denying

**Story:** As a developer, I want a `code run` agent to pause on a permission
request instead of being silently denied, so that a narrow-permission run can
still finish the task.

**Acceptance criteria:**
- [ ] `containarium code run <box> --approvals ask` (default: `deny`, which is
      today's behavior, unchanged) wires the engine's permission hook so a
      gated tool call emits an `input_request {request_id, kind: permission,
      prompt, options: [allow, deny], default: deny, expires_at}` to the run
      journal and the run reports `waiting_input` in `code status`.
- [ ] The agent process blocks on that request and resumes on the answer; an
      `allow` executes the tool call, a `deny` returns a refusal to the agent.
- [ ] An unanswered request expires (default 30 min, `--approval-timeout`)
      into `deny`, and the expiry is journaled.
- [ ] With `--approvals ask` on an engine without a hook (pi), the run starts,
      and every gated action is auto-denied **and journaled** as such; the CLI
      prints a one-line warning at start.
- [ ] Integration test: a fixture prompt that needs one gated command; answer
      `allow` → exit 0 with the command's effect present; answer `deny` →
      effect absent; no answer → expiry line in the journal.

**Priority:** P0

### Story 2: answer from the CLI

**Story:** As a developer at a terminal, I want to see and answer pending
requests without attaching to the stream, so that the CLI is a complete
surface on its own (CLI-first; the phone is one more consumer).

**Acceptance criteria:**
- [ ] Proto first: `AnswerRunInput` (from #2124) accepts a box-run id;
      `make proto` regenerates gateway + swagger.
- [ ] `containarium code pending <box>` lists open requests (id, prompt,
      age, expires in).
- [ ] `containarium code answer <box> <request_id> allow|deny` answers one;
      answering an already-answered or expired request is an idempotent,
      non-zero-exit no-op that prints the existing outcome.
- [ ] `code attach` renders an open request inline and accepts `a` / `d`
      when stdin is a TTY.
- [ ] MCP tools `code_pending` / `code_answer` are thin wrappers over the
      same client functions.

**Priority:** P0

### Story 3: the request reaches the phone

**Story:** As a developer away from my laptop, I want a push notification when
a run is waiting on me, so that I don't have to poll.

**Acceptance criteria:**
- [ ] `containarium notify set ntfy --server <url> --topic <topic>` stores
      the channel for the current user; the access token is stored with the
      existing secrets API, never in a flag's shell history (read from stdin
      or `--token-file`). `containarium notify test` sends one test push.
- [ ] Opening a request sends one push within 10 s: box name, run name, the
      tool and a truncated command (≤ 200 chars), and the expiry.
- [ ] **Payload minimization:** no file contents, environment values, or
      secrets in the push; the default template carries the tool name and
      command only, and `--redact-command` sends the tool name alone.
- [ ] A burst of requests from one run produces at most one push per 30 s
      with a count, never a dropped request.
- [ ] Works with self-hosted ntfy and with ntfy.sh; the docs state that
      ntfy.sh topics are public by name and recommend an access-controlled
      topic or a self-hosted server.

**Priority:** P0

### Story 4: answer from the notification

**Story:** As a developer holding my phone, I want Allow / Deny buttons on the
notification, so that answering is one tap, not an app or an SSH session.

**Acceptance criteria:**
- [ ] The push carries two HTTP action buttons that call the daemon's
      public API with a **single-use token bound to (run, request_id,
      answer)**, expiring with the request. A replayed, expired, or
      mismatched token is refused and changes nothing.
- [ ] The token is not a user credential: it can answer that one request
      and nothing else (no read access, no other runs).
- [ ] After a tap, the run resumes; a second tap on either button reports
      "already answered: allow by <channel> at <time>".
- [ ] Works for a box on a self-hosted backend reachable at its gateway
      hostname and for a cloud box. BYOC behind NAT goes through the
      existing sentinel path; if that is not reachable from the internet,
      the push says "answer with `containarium code answer …`" instead of
      showing buttons.

**Priority:** P0

### Story 5: every answer is attributable

**Story:** As the owner of the box, I want every request and answer recorded
with who answered and through which channel, so that "who approved this?"
has an answer.

**Acceptance criteria:**
- [ ] `input_response` journal lines carry `{answer, by: <user id>, via:
      cli|mcp|ntfy, at}`; expiries carry `by: system`.
- [ ] Answers are also written to the platform audit log (hash-chained), in
      line with `docs/product/agent-governance.md`.
- [ ] `containarium code logs <box>` shows request and response lines
      without parsing engine output.

**Priority:** P0

## Later phases

- **P1: LINE channel.** Largest messaging reach in our home market; needs a
  LINE Official Account and Messaging API channel token (custody decision).
  Build once Story 3's ntfy answer rate proves people answer from the phone.
- **P1: Telegram channel.** Same shape, bot token custody.
- **P1: "Allow for this run" scope on an answer.** Reduces repeat prompts for
  the same command; must stay run-scoped (see Out of scope).
- **P1: Question kind.** A free-text clarifying question (#2124 `kind:
  question`); needs a reply channel richer than two buttons.
- **P1: Codex and other engines** mapped onto the same request/answer events.
- **P2: Cloud consumers.** The run page card and "needs you" email
  (Containarium-cloud #1889) read the same journal events; nothing here
  blocks them.
- **P2: Per-rule policy** (auto-allow `git push` to non-default branches,
  always ask for `rm -rf`, and so on), once real request logs show which
  rules matter.

## Out of scope

- **"Bypass permissions" or "allow everything forever" from the phone.** A
  phone tap must never widen what an agent can do beyond one request (P1:
  one run). Same rule as the cloud PRD.
- **A native mobile app.** The notification is the surface; the cloud PRD
  already rejected a store app.
- **Vendor-owned remote control** (e.g. an agent vendor's own mobile app) as
  the mechanism. Rejected in the cloud PRD as lock-in; this PRD must work
  for any engine and any credential.
- **Slack.** Not a phone-first channel for this user; revisit on request.
- **Running our own push service.** ntfy (self-hosted or hosted) is the
  transport; we do not operate APNs/FCM infrastructure.

## Open questions & assumptions

1. **Does the CLI half wait for the #1865 relay-app spike?** #2124 is gated
   on it because an adopted relay app could supply the permission object.
   **Default: no.** The CLI (`code pending` / `code answer`) needs a
   vendor-neutral request/answer contract whatever the phone surface is, and
   an adopted relay app would be one more consumer of it. Needs an explicit
   decision because it reorders #2124.
2. **Does this pull the cloud PRD's P2 chat-app bridge forward?** Yes, for
   ntfy only. The cloud PRD's condition was "if email tap-through is poor";
   this PRD's argument is that email cannot carry an answer button for a
   self-hosted user with no cloud account. **Default: accept for ntfy, keep
   LINE/Telegram behind the answer-rate metric.**
3. **Demand is assumed.** No user asked. Validate by shipping Story 1 with
   instrumentation first (how often do `code run` runs hit gated actions at
   all?) before Stories 3–4 are built. If gated actions are rare, the value
   is in Story 1 plus the CLI, and the phone is a nice-to-have.
4. **Engine hook.** Assumed: Claude Code's headless mode exposes a
   permission-prompt hook the box can serve (the box already ships an MCP
   config at `coderun.ContainariumMCPConfigPath`). #2124's sketch names the
   Agent SDK callback instead. `/architect-design` picks one; this PRD
   only requires that the run blocks and resumes.
5. **Default expiry.** 30 min assumed for a phone answer (#2124 sketched
   5 min for crew runs). Too short and requests expire in a meeting; too long
   and a run holds a box. Validate with the latency metric.
6. **Reachability for Story 4.** Assumed the daemon's public API is
   reachable from the phone for cloud and self-hosted-with-gateway boxes.
   BYOC-behind-NAT falls back to the CLI instruction; confirm with the
   sentinel owners that the tunnel path can carry it.
7. **Push content is a disclosure.** A command line can contain a hostname,
   a path, or worse. Minimization is P0 (Story 3); whether the default
   should be redacted is a security decision. **Default: show the command,
   truncated; `--redact-command` opts out.**

## References

- `docs/product/remote-coding-agent.md` (the `code run` PRD)
- `docs/product/agent-governance.md` (attribution, audit)
- OSS #2124 (needs-input mechanism), #2123 (box run records), #2095/#2096
  (run journal, `TailRunLog`)
- Containarium-cloud `docs/product/mobile-agent-supervision.md`, #1879
  (sprint), #1865 (relay-app spike), #1889 (cloud "needs you"), #1862
  (completion email)
