# Platform-started box runs (`StartBoxRun`)

`StartBoxRun` (`POST /v1/containers/{username}/code-runs`, see `proto/containarium/v1/box_run.proto`)
starts or resumes a coding-agent run on a box through the daemon, with no SSH
client. The run leaves the same on-disk contract `containarium code run` leaves
in the box's run directory (`/tmp/agent-box`), so `ListBoxRuns`, `TailBoxRunLog`
and `containarium code runs|attach|status|logs` read it the same way. This page
covers what a platform caller (a control plane starting runs for members) needs
beyond the CLI.

## Naming a run: `run_name`

By default a run is named after the session id when resuming, else `code`.
A caller that cannot rely on `code` being free sets `run_name`:

- The run is named exactly that. The name must match `[A-Za-z0-9._-]{1,128}`
  and not be `.` or `..`; anything else is `INVALID_ARGUMENT` before anything
  runs on the box.
- A name ending in `.stderr` or in `.<digits>` is `INVALID_ARGUMENT`: it would
  alias a run's stderr log or the rotation suffix of a finished run.
- The usual rules apply to that name: a finished run of the same name is
  rotated aside, a `RUNNING` or `UNKNOWN` one is `FAILED_PRECONDITION`.
- A named run never collides with the default `code` run, so a member's own
  `containarium code run` is unaffected. Pick a unique name per run to keep
  every log (a reused name rotates the previous log aside before the new run
  starts).
- With `session_id` also set, the run resumes that session but keeps
  `run_name` as its name.

The CLI counterpart is the existing `containarium code run <box> --name <name>`
(the SSH path); there is no separate flag.

## Refused while skill sets are being applied: `APPLY_IN_PROGRESS`

A `StartBoxRun` that arrives while `ApplyBoxSkillSets` is installing skill sets
on the same box is refused at once with `FAILED_PRECONDITION`, before anything
on the box is touched (a finished run of the same name is not rotated). The
daemon does not queue the start or wait for the apply, so a run never reads a
half-written skills tree. It is the mirror of the apply's own `RUN_IN_PROGRESS`
refusal.

The reason is typed, not message text: the error's details carry a
`google.rpc.PreconditionFailure` whose violation `type` is
`BOX_SKILL_SETS_REFUSAL_APPLY_IN_PROGRESS` (the `BoxSkillSetsRefusal` enum
value name) and whose `subject` is the box. A caller should treat it as
transient and retry the start once the apply has returned.

### The apply's own wait for the box

`ApplyBoxSkillSets` shares a per-box gate with run starts, and applies on one
box are serialized by it. An apply that finds the gate busy waits for it, at
most 30 seconds, and stops waiting at once if the caller cancels (the call
returns `CANCELED`, or `DEADLINE_EXCEEDED` when the caller's own deadline
passed). A waiting apply does not make run starts fail: only an apply that
holds the gate does. When the 30 seconds pass, the apply changes
nothing and is refused with `FAILED_PRECONDITION`, and the typed reason says
what held the gate:

- `APPLY_IN_PROGRESS` when another `ApplyBoxSkillSets` call on the box was
  still installing. Retry once it has returned.
- `RUN_IN_PROGRESS` when run starts held it. The message names the starts still
  in flight at that moment, which is a snapshot, not a claim that they ran for
  30 seconds. A steady stream of overlapping run starts can keep an apply off
  the gate for the whole cap, because a waiting apply does not queue ahead of
  them; retry shortly. If the gate is free at the moment the cap fires, the
  apply takes it and proceeds. When no start is recorded in flight, the message
  says so instead of naming any.

## Structured output: `structured_output`

With `structured_output: true` (Claude Code boxes only; other engines are
`FAILED_PRECONDITION`, refused before anything on the box is touched, so a
finished run of the same name is not rotated) the engine runs with
`--output-format json`:

| File | Content |
| --- | --- |
| `<run_name>.log` | Exactly the engine's one JSON result object: `type` (`result`), `subtype` (for example `success` or an error subtype), `is_error`, `result` (the final text), `session_id`, `usage`, and the engine's other result fields. |
| `/tmp/agent-box/<run_name>.stderr.log` | The engine's stderr, kept apart so the main log stays valid JSON. It is not served by `TailBoxRunLog` (no RPC reads it yet); read it on the box. |

The object is written when the run ends; while it runs the main log is empty.
`TailBoxRunLog` and `containarium code logs` return the log as opaque bytes, so
they return the object verbatim. The run record's capture mode is still
`combined` ("plain text, not framed"): the name predates this option and does
not mean stdout and stderr are merged here. For a structured run the log holds
stdout only; stderr is in the separate file above.

`BoxRun.session_id` is decoded by the daemon, not by a shell script: once the
run has exited, `ListBoxRuns` parses the log with a JSON decoder and uses ONLY
the object's top-level `session_id` (a `session_id` key nested inside, say, a
tool input is ignored) provided it is a safe identifier. It takes precedence
over the literal id of a resumed run. A truncated or invalid object, a missing
id, or an object larger than 1 MiB yields no id. The default (`false`) leaves
plain-text behaviour unchanged.

## Session id of a fresh plain-text run (best effort)

**A caller that needs the session id reliably MUST use `structured_output`.**
The plain-text id is best-effort and may be missing.

Without `structured_output`, the id of a fresh run is found by looking at the
engine's session directory. The daemon lists that directory just before
launching the engine, then polls for the run's whole budget (about 12
seconds, or until the run exits, whichever is first) and only then looks for
entries that were not in the listing. If there is exactly one, it is the run's
session id. If there are none, or more than one (a member's interactive
session, or another run, created a transcript meanwhile, in either order),
`session_id` stays empty; an older entry is never used as a fallback. The
poll deliberately does not stop at the first new entry, since that may belong
to somebody else.

A run started with `continue_session` gets no id from discovery at all (it
appends to an existing file, which is never new). A resumed run's id is the
`session_id` it was started with.

## Command mode: `command`

With `command` set (and `prompt` empty) the box runs that shell command in the
engine's place: `timeout -k 5 <timeout_seconds> sh -c '<command>'`, detached
like an engine run, with the same record, log, listing, tailing and stop. Use it
for work that must not involve a model: a build, the test suite, a lint, a
verification of a pushed commit.

- No engine starts and no agent credential is loaded. The box's `code.json` is
  not consulted (a box whose engine run would be refused, say one on the gateway
  credential, still takes a command run), and the run user's agent sign-in is
  **not** required.
- Identity is an engine run's; tool access is weaker. On a box with a recorded
  tool-access level the recorded level selects the run user and that level's
  sudo grant and staged home; on a box with none the command runs as the owner.
  `BUILD_TOOLS` is what gives it the managed toolchains. The engine's allow/deny
  tool policy (the tools and shell commands an agent may call) applies to engine
  runs only: a command is a plain `sh -c` as the run user and is not limited by
  it. A caller holding the command-mode scope can therefore run any program the
  run user can, including on a box recorded at a restrictive level, which an
  engine run at that level could not be told to do by a prompt. The level
  bounds what the run user may do as a Unix account (its sudo grant), not what
  a command may invoke. With `command_policy` set, the command is decided like
  an engine run's shell command instead; see the next section.
- The working directory is the run user's home, or `workdir` under it (see
  Working directory below). A command that needs a checkout
  makes it: for example `git clone <url> work && cd work && git checkout <sha>
  && make test`, through the box's own credential helper.
- `timeout_seconds` bounds it (default 900, at most 3600; `INVALID_ARGUMENT`
  above that or without `command`). A command that outlives its budget gets
  SIGTERM, then SIGKILL five seconds later, and the run's exit code is `124`.
- `command` is mutually exclusive with `prompt`, `session_id`,
  `continue_session`, `structured_output` and `model` (`INVALID_ARGUMENT`,
  before anything on the box is touched). `BoxRun.session_id` stays empty and
  `BoxRun.model` is empty.
- The text is single-quoted whole, so the outer shell interprets none of it; the
  command's own `sh -c` runs it as written. It is the caller's text and runs with
  the box owner's code and secrets reachable, like anything a run on that box can
  do: a control plane must only ever send text a repository manager configured or
  the platform itself wrote, never text from an issue, a pull request or an
  agent's output.

The CLI counterpart is `containarium code run <box> --command '<text>'
[--timeout 15m] [--name <run>] [--workdir <dir>]` (the SSH path, as the box's
own user).

## Command allowlist and audit events: `command_policy`

`command_policy` (capability `box_run_command_policy`) puts every shell
command of a run through one decision before it runs, and records an audit
event for it. It needs a box with a recorded tool-access level
(`FAILED_PRECONDITION` otherwise) and, for an engine run, the Claude Code
engine. It applies to both kinds of run:

- **Engine run.** The daemon installs a PreToolUse and a PostToolUse hook pair
  (`agent-box permission-hook pre|post`) through `--settings`. Each shell
  command the agent requests is decided by the pre hook.
- **Command run** (`command`). The run executes `agent-box permission-hook
  command` in place of `sh -c`. It applies the same decision to the command,
  which the daemon wrote into the run's root-owned configuration, and runs it
  only if it is allowed. The timeout and exit code work as for a plain command
  run.

The decision, in order:

1. **Hard denies** refuse the command whatever the allowlist says: network
   client executables, `git push`, `git remote`, git transport options, and any
   `GIT_*` environment assignment. The check also reads command substitutions,
   subshells and quoted redirection targets, and the values of `NAME=value`
   assignments, which are otherwise left out of the audit event.
2. **Unresolvable commands** are refused (`UNRESOLVABLE`) after the hard
   denies, only when the parser cannot tell what will execute: brace expansion,
   a glob character in the executable word, ANSI-C quoting (`$'...'`) and
   arithmetic expansion (`$((...))`) in a command word, and a quoted shell
   command (`sh -c '...'`) nested more than three deep. They are refused by
   name, not left to the fact that no rule allows them. Compound lines
   (`&&`, `||`, `;`), pipes, redirections, substitutions and globs in arguments
   are not refused for their shape: the hard-deny scan reads every segment, and
   every segment must also be covered by the level's own rules, otherwise the
   line is refused (`NOT_ALLOWED`, or `HARD_DENY`). The allowlist cannot cover
   a compound line or a segment of one: it matches only a simple command. A
   leading `NAME=value` is judged as written, on a simple line and in a
   segment alike, so `PATH=/tmp ls` is not covered by a rule for `ls`.
3. **The org allowlist** (`command_policy.allow`) runs a command outside the
   level when an entry matches: an argv glob with an exact executable, `*`
   within one argument, and no shell operators.
4. **The level's own rules** run the command as before.
5. **Anything else** is refused.

**The engine is root-staged.** For an engine run, the daemon installs the
owner's engine as a root-owned `0755` copy in the root-owned audit directory
(`/var/lib/containarium-run-audit/bin/claude`) and the run executes that copy,
not the run user's own `~/.local/bin/claude` (which the run user can replace). The
owner's file is trusted only if it is owned by the box owner and writable by
neither group nor others, and is re-checked after copying. The copy is replaced
whenever the owner's file changes. If the engine cannot be staged that way, the
run is refused with `FAILED_PRECONDITION` and the violation type
`ENGINE_NOT_ROOT_STAGED`; it never falls back to the run user's copy. The
root-owned copy cannot update itself: a new engine version reaches a run when
the owner's copy is updated (the next run re-stages it).

A refused command ends the run. Nothing waits for an answer: an approved re-run
is a new run that carries `approval`. A refusal records a `BLOCKED` event with
an `AgentCommandCloseReason` (`HARD_DENY`, `NOT_ALLOWED`, `UNRESOLVABLE`, or
`AUDIT_UNAVAILABLE` when the start event cannot be recorded). An engine run is
stopped by the hook (`continue: false`). A command run never starts the
command: it prints the reason to its log and exits `120`.

Every command that runs gets a `START` event before it runs and an `END` event
with its exit code. Every `START` gets exactly one `END`, and each `END` has an
`outcome` (`AgentCommandOutcome`):

- **`RAN`**: the post hook (engine run) or the command hook (command run)
  reported that the command finished.
- **`NOT_RUN`**, close reason `ENGINE_REFUSED`: the pre hook allowed or deferred
  the command, but the engine then refused it itself (for example
  `--restricted` working-directory confinement), so no post hook fired. The
  sink writes this `END` when the run ends cleanly (exit status `0`) with the
  `START` still open. The engine fires a post hook for every command it runs,
  so such a command did not run. This rests on the engine's report and on the
  run's exit status. That status is recorded by `agent-box run-supervise`, a
  root process the daemon starts in place of spawning the run as the run user:
  it runs the run as the run user, in its own session, and as its parent writes
  the exit status to `/var/lib/containarium-run-audit/exit/<run>.exit` (root,
  `0600`, in a root `0700` directory the setup creates with the events
  directory). The sink reads only that file, never the run directory's
  `<run>.exit`, which the run user can write.
- **`UNKNOWN`**, close reason `INTERRUPTED`: the run ended any other way with
  the `START` still open (killed, timed out, crashed, a non-zero or missing
  exit status, or the sink stopped by a signal). The command may have run in
  part. The sink writes this `END` too.

A sink-written `END` has no exit code. The pre hook's own process cannot write
it, because it exits before the engine decides; the sink is the one process
that lives until the run ends.

**Exit code.** `exit_code` is absent when it is not known, never `0` by
default. For an engine run it comes from the engine's hook input:

- an exit-code field in `tool_response`, when the engine sends one;
- `PostToolUse` without such a field: `0`, since the engine fires
  `PostToolUse` only for exit status `0`;
- `PostToolUseFailure`: `N` when the error text begins with the line
  `Exit code N` (`0`-`255`, then a newline or the end of the text). Any
  other text (missing, non-numeric, out of range, the phrase on a later line)
  records no exit code.

That error text is the engine's display format (observed with Claude Code
2.1.319), not a documented field. If an engine release changes it, failed
commands are recorded with no exit code until the parser follows. A command
run records the shell's own status.

Output and environment are never recorded, and arguments
are redacted from a default list plus `command_policy.redact_patterns`. Events
are protojson `AgentCommandEvent` lines in
`/var/lib/containarium-run-audit/events/<run_name>.jsonl` inside the box. A
root-run sink (`agent-box run-audit-sink`) that the daemon starts before the run
is the only writer, and the run user cannot write that file.

Limits:

- **At `FULL_SUDO` these controls are advisory.** The allowlist, the hard
  denies and the hooks are installed and decide exactly as at the other levels.
  But the run user has passwordless sudo, so it can become root. As root it can
  change the configuration, stop the sink or run commands the hooks never see.
  At `FULL_SUDO` they do not bind the run user and are not a security
  boundary. Use `NONE` or `BUILD_TOOLS` where the allowlist must hold.
- **An allowlist entry cannot name an interpreter on caller-chosen code.** An
  entry whose executable is a shell, `python*`, `perl`, `ruby`, `node` and the
  like is refused when it has a `-c`/`-e`/`-m`-style flag or a `*` argument, so
  the allowlist cannot be widened into "run anything". A fixed interpreter
  entry (`python3 scripts/check.py`) is accepted, and so is whatever that
  script does. Wrappers (`env`, `xargs`, `timeout`) are not recognised, so an
  entry that wraps an interpreter is the operator's to avoid.
- **The `agent-box` that root runs must be trusted.** The daemon copies a
  root-owned `agent-box` (from `/usr/local/bin`, else the owner's
  `~/.local/bin`) and runs it as root. A copy that is not owned by root, or is
  group- or world-writable, is skipped, and with none left the run is refused.
  If the setup is refused after a finished run of the same name was rotated
  aside, that run is restored under its name.
- **Network denial is command-level only.** It refuses network client
  executables. `git clone`/`git fetch` and package managers still reach their
  remotes and registries, and nothing filters network traffic itself.
- A command is decided as one line. Programs that the command or a script it
  runs start in turn are not decided again.

## Working directory: `workdir`

A run starts in its home directory: the box user's home, or the unprivileged
run user's home on a box with a recorded tool-access level. `workdir` starts it
in a directory under that home instead, for prompt and command runs alike, so an
instruction relative to a project (for example "put the slide under
`slides/<id>/`") lands in the project.

- `workdir` is relative to that home, in the canonical form `WriteBoxFile`'s
  `path` uses (no leading `/`, no `..`, `.`, empty or trailing segment, no
  control character, nothing under `.ssh` or `.containarium`). Anything else is
  `INVALID_ARGUMENT`, before the box is touched.
- The directory must already exist and be a directory the run user can enter.
  It is checked as that user before anything on the box changes (a finished run
  under the same name is not rotated aside); otherwise the call is
  `FAILED_PRECONDITION` naming the directory and no run starts. It is never
  created, and there is no fallback to the home.
- Empty keeps the home, exactly as before.
- An engine run's session folder follows the directory (Claude Code keys its
  sessions by the directory it starts in), so session discovery and
  `continue_session` work in it.
- `BoxRun.workdir` reports it on `StartBoxRun` and `ListBoxRuns`; it is empty for
  a run started in the home and for runs from before the field.

The capability name is `box_run_workdir`.

The CLI counterpart is `containarium code run <box> --workdir <dir>` (prompt
and `--command` runs), and the platform MCP tool `code_run` takes a `workdir`
argument. Over the SSH path both apply the same rule as the box's own user:
the path is checked locally before anything connects, and the directory is
checked under the box user's home before anything on the box changes (before
the gateway token is written or a finished run under the same name is rotated
aside). A refused value starts no run. With `--run-token-file` the value goes to
the daemon as `workdir`, and the CLI sends it only to a daemon that lists
`box_run_workdir` (an older daemon would drop the field over gRPC and start the
run in the home).

## Per-run token: `run_token`

`run_token` is the platform credential for one run. The caller mints it; the
daemon only delivers it.

- The daemon writes the token to `/run/containarium/run-tokens/<run_name>.token`
  inside the box, mode 0600 and owned by the user the run executes as, and
  exports `CONTAINARIUM_JWT_TOKEN_FILE` with that path in the run's shell. The
  token travels as file content only: it is in no command line and no script.
- The file is removed when the run exits and when it is stopped
  (`StopBoxRun`). A start that fails after asking for the install (the install
  fails, times out after 30 seconds, the request is cancelled, or the spawn
  fails) removes it too, as root. When the start stopped waiting while the
  install was still running, the removal runs once that install finishes. A
  removal that fails is retried a few times. Until the removal is done,
  another start of the same run name is `UNAVAILABLE` ("has not finished
  installing or removing its token; retry shortly"). Other run names on the
  box are not affected.
- At most 8 KiB, with no NUL and no line break; anything else is
  `INVALID_ARGUMENT` before the box is touched.
- **A run as the unprivileged run user must carry it.** On a box with a
  recorded tool-access level (prompt and command mode alike) a request without
  `run_token` is `FAILED_PRECONDITION`, naming `run_token` and `box_run_token`,
  before the run user is provisioned and before anything is staged, rotated or
  spawned. A run on a box with no recorded level executes as the box owner, is
  unchanged, and may omit the token.
- The box principal is no longer copied into the run user's home
  (`~/.config/containarium/box-token`), and a copy left by an earlier daemon is
  removed the next time a run is prepared. Whatever the run starts (a
  credential helper, an MCP server) must read the file named by
  `CONTAINARIUM_JWT_TOKEN_FILE`. The platform MCP server (`mcp-server`) already
  does, on every request. The daemon does not rewrite an MCP configuration
  staged from the owner's home: one that names the old principal path must be
  changed by whoever maintains it.
- Capability `box_run_token`. A daemon without it accepts the field and
  ignores it, so check the capability before sending a token. `GetSystemInfo`
  needs an admin principal; the typed client and the CLI refuse to send a token
  when they cannot read the capability list.

## From the CLI: `code run --run-token-file`

`containarium code run <box>` starts its run over an SSH session by default.
With `--run-token-file <path>` it calls `StartBoxRun` instead and sends the
token in that file as `run_token`:

```
containarium code run <box> --prompt '<task>' --name <run> \
  --run-token-file <path> --server <host>
```

- The file holds the token on one line. It is read, never printed or logged,
  and the token is never taken as an argument. An unreadable or empty file is
  an error before any request is made. The CLI does not mint a token.
- The token is sent only to a daemon that lists `box_run_token` in
  `SystemInfo.capabilities`. For any other daemon the CLI refuses, naming the
  capability, and no run is started.
- Sending a per-run token needs an admin token. The CLI reads the capability
  list through `GetSystemInfo`, which is admin-only, so a non-admin box owner
  is refused with `PermissionDenied` from that capability check, even against
  a daemon that advertises `box_run_token` and although `StartBoxRun` itself
  accepts the owner. No run is started.
- `--prompt`, `--session`, `--continue`, `--name`, `--command`, `--timeout`
  and `--workdir` map to the request's fields. A `--workdir` is sent only to a
  daemon that lists `box_run_workdir`. `--approvals ask`,
  `--output-format-stream-json` and `--token-ttl` belong to the SSH path and
  are refused with this flag.
- After the start the command follows the run's log and exits non-zero when
  the run does, through the reads `code logs --follow` and `code runs` make.
- The engine, its credential source and the run user come from the box, as for
  any `StartBoxRun` call; the SSH path runs as the box's own user.

The platform MCP tool `code_run` starts its run through the same function and
takes no token parameter, so it always uses the SSH path.

## Putting a file on the box: `WriteBoxFile`

`WriteBoxFile` (`PUT /v1/containers/{username}/files`, `containarium code
put-file`) writes one file into the box user's home so a run can read it. Same
access as `StartBoxRun`.

- `path` is relative to the home directory and in canonical form: no leading
  `/`, no `..`, `.`, empty or trailing segment, no control character, and
  nothing under `.ssh` or `.containarium`. Anything else is `INVALID_ARGUMENT`,
  before the box is touched.
- `content` is at most 2 MiB. `mode` is `0600` (default) or `0400`.
- The bytes go through the container file API into a root-made staging file with
  an unguessable name, are handed to the box user, and the box user's own script
  moves them into place. The final write therefore reaches only what the box
  user could already write, whatever links the user has set up in the home.
- The file appears whole or not at all (rename), replacing an existing file. A
  symlink at the path is replaced, not written through. A directory at the path
  is `FAILED_PRECONDITION`. Parent directories are created `0700`.
- `sha256` (optional, lowercase hex) is checked over the bytes on the box before
  the rename. A mismatch leaves no file and is `DATA_LOSS`. The response carries
  the absolute path, the size and the checksum of what is on the box.

**Limits.** The 2 MiB cap applies to each call; there is no daemon-side quota
across calls (#3559). The total a caller can write is bounded by the box's own
disk limit, the same limit every write inside the box is under, and a write that
hits it fails without leaving a partial file (the bytes are staged and renamed).
A caller that writes many files bounds how many it writes itself.

**Agents.** The platform MCP tool `put_file` is a thin wrapper over the same
client function as `code put-file`, over the same REST path. Its arguments are
`box`, `path`, the bytes inline as exactly one of `content` (UTF-8 text) or
`content_base64` (standard padded base64, at most 2 MiB decoded), and optional
`mode` and `sha256` (default: the checksum of the content sent). It never reads
a file on the MCP server's host. A refusal comes back as `refused (<CODE>)`, for
example `refused (INVALID_ARGUMENT)` for an escaping path or
`refused (DATA_LOSS)` for a checksum mismatch, followed by the daemon's message.
A bad box name, a missing or doubled content argument, invalid base64, content
over the cap, or a bad mode or checksum is rejected before any request is made.
It needs the `ssh:write` scope.

The capability name is `box_files`.

### Files above 2 MiB: `WriteBoxFileStream`

`WriteBoxFileStream` (`POST /v1/box-files:stream`) is the client-streaming
form, for files up to **64 MiB**. `code put-file` uses it on its own for a file
above 2 MiB; the 2 MiB `WriteBoxFile` call is unchanged. The MCP tool keeps the
2 MiB inline cap.

- The first message is a `header`: `username`, `path`, `mode`, `sha256` (same
  rules as `WriteBoxFile`) and `size`, the total byte count (0 to 64 MiB). Every
  later message is `data`, in order; the client sends 1 MiB per message.
- Over REST the body is newline-delimited JSON: `{"header": {...}}` and then
  `{"data": "<base64>"}` objects.
- The data goes straight into the same root-made staging file as `WriteBoxFile`
  as it arrives (the daemon does not hold the whole file in memory), and the
  same box-user script checks the checksum and renames the file into place. The
  final path is touched only after every byte has arrived.
- A stream that ends before `size` bytes, carries more than `size`, sends a
  second header, or declares more than 64 MiB is `INVALID_ARGUMENT`; a checksum
  mismatch is `DATA_LOSS`; a client that cancels gets `CANCELLED`. None of them
  leaves a file at or beside the path, and the staging file is removed.
- The per-call limit is 64 MiB; as with `WriteBoxFile`, nothing bounds the total
  but the box's own disk limit.

The capability name is `box_files_stream`. A daemon without it answers
`Unimplemented` (over REST, the gateway's 404 for an unknown route); `code
put-file` then says the daemon needs an upgrade for files above 2 MiB.

## Applying a bootstrap bundle: `ApplyBoxBootstrap`

`POST /v1/containers/{name}/bootstrap:apply` with `{"bootstrap_url": ..., "box_user": ...}`
runs the bundle step of `containarium code install --bootstrap-url` from the
daemon: inside the running box, as `box_user` (default: the box owner; `root`
and the unprivileged run user are refused), it fetches the `.tar.gz`, unpacks it
and runs its `apply.sh`, then returns `bundle_revision` from the bundle's
`manifest.json` (`manifest_found` is false when the bundle has none). The URL is
treated as a single-use credential: it never appears in the daemon's logs or in
an error.

An unknown box is `NOT_FOUND`. Every other failure carries a `google.rpc.ErrorInfo`
whose `reason` is a `BoxBootstrapFailure` name and, for the bundle step, whose
`metadata.exit_code` is the script's exit code, the same one `code install` uses:

| reason | gRPC code | exit_code | URL consumed? |
| --- | --- | --- | --- |
| `BOX_NOT_RUNNING` | `FAILED_PRECONDITION` | none | no |
| `FETCH_UNREACHED` | `UNAVAILABLE` | 3 | no, retry is safe |
| `FETCH_FAILED` | `FAILED_PRECONDITION` | 6 | maybe |
| `BUNDLE_INVALID` (no `apply.sh`) | `FAILED_PRECONDITION` | 4 | yes |
| `APPLY_FAILED` | `FAILED_PRECONDITION` | 5 | yes |

A daemon that supports it lists `box_bootstrap` in `SystemInfo.capabilities`; an
older one has no route (gRPC `UNIMPLEMENTED`, or a REST 404 with no status body,
which the typed client maps to `UNIMPLEMENTED`). From the shell:
`containarium code bootstrap <box> --via-daemon --server <host> --url <url>`.

## Feature detection

The REST gateway rejects request fields it does not know, so a caller must not
send `run_name`, `structured_output`, `model`, `command` or `workdir` to a
daemon that predates them. `GetSystemInfo` (`SystemInfo.capabilities`) lists the
optional features a daemon supports: `box_run_name`, `box_run_structured_output`,
`box_run_model`, `box_run_command`, `box_run_command_policy`, `box_run_workdir`,

send `run_name`, `structured_output`, `model` or `command` to a daemon that
predates them. `GetSystemInfo` (`SystemInfo.capabilities`) lists the optional
features a daemon supports: `box_run_name`, `box_run_structured_output`,
`box_run_model`, `box_run_token`, `box_run_command`, `box_run_command_policy`,
`box_files` and `box_files_stream`. An older daemon does
not send the field at all; treat a missing name as unsupported. Names are only
added. `GetSystemInfo` requires an admin principal. A caller that cannot read it
can gate on the daemon version instead: the first release that contains these
fields (see the changelog entry).

## Answering permission requests: the `code:answer` scope

`AnswerRunInput` (`containarium code answer`, `code attach`'s inline answers,
the MCP `code_answer` tool) needs the box-run access rule (`ssh:write`, box owner
or collaborator) **and** the `code:answer` scope. `code:answer` is matched
literally: the wildcard scope `*` does not carry it, and neither does a token
with no scopes claim. An allow lets the agent run the tool call it asked for,
so the token that answers must be one the agent on the box cannot hold.

No credential the platform puts on a box carries `code:answer`: a skill or crew
run token has it stripped at mint, whatever the dispatching caller or the skill
manifest grants. The delegation exchange (`ExchangeDelegatedToken`,
`containarium token delegate`) grants `code:answer` only to a caller that holds
it literally, so a `*` token cannot be exchanged for one. Mint the answering
token where the agent cannot read it, for example on the daemon host:

```bash
TOKEN=$(containarium token generate --secret-file <jwt-secret-file> --username <you> \
  --scopes ssh:write,code:answer --expiry 24h --raw)
containarium --token "$TOKEN" --server <daemon> --http code answer <box> <request_id> allow
```

**Do not run `containarium login` inside a box an agent runs in.** It writes your
token to `~/.containarium/credentials.json` in the box, where the agent can read
it and call the API as you. A login token does not carry `code:answer`, so it
cannot answer permission requests, but it can still do everything else your
account can.

## Per-run checkouts: the sweep and `--run-checkout-max-age`

A platform-started run clones into a directory of its own directly under a box
user's `~/work`, named `<repo>-run-<8 hex>`. The run cannot remove it (`rm` is not
among the commands an unattended run may use), so the daemon removes stale ones
(#3296). It sweeps every running box that has had a platform-started run (a
recorded tool-access level or a run record) every hour, sweeps a box after
`StopBoxRun` ends a run on it, and skips stopped boxes.

In the box owner's and the run user's `~/work`, it removes an entry only when all
of these hold:

- its name matches `^[A-Za-z0-9._-]+-run-[0-9a-f]{8}$`. Nothing else is touched or
  listed. Your own checkout, `~/work/<repo>`, is never considered;
- it is a real directory. A symlink is never followed or removed, and neither is
  a `~/work` that is a symlink or lies under one;
- its newest modification (the directory or anything in it) is older than the
  daemon's `--run-checkout-max-age`;
- no process on the box has its working directory in it;
- it is not a live run's: not named by a running run's record as its working
  directory, and not modified at or after the start of a run that is still going.

Every one of these is checked again in the box right before the directory is
removed, and the removal (`rm -rf --one-file-system`) never follows a symlink or
crosses into another filesystem. Each removal is logged at info level with the
directory's name and size.

| Daemon flag | Default | Meaning |
|---|---|---|
| `--run-checkout-max-age` | `168h` (7 days) | How old a per-run checkout's newest modification must be before it is removed. `0` turns the sweep off, including `SweepBoxRunCheckouts`. |

Run the sweep once on one box, or see what it would remove:

```bash
containarium code sweep-checkouts <box> --dry-run --server <daemon>   # list exactly what would be removed
containarium code sweep-checkouts <box> --server <daemon>             # remove it
containarium code sweep-checkouts <box> --dry-run --all --server <daemon>  # also list what is kept, and why
```

The API is `SweepBoxRunCheckouts` (`POST /v1/containers/{username}/code-run-checkouts:sweep`,
body `{"dry_run": true}`), with the same access as `StopBoxRun` (`ssh:write`, box
owner or collaborator).
