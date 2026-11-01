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
- Identity and tool access are exactly an engine run's: on a box with a recorded
  tool-access level the command runs as the run user with that level's sudo
  grant and staged home; on a box with none it runs as the owner. `BUILD_TOOLS`
  is what gives it the managed toolchains.
- The working directory is the run user's home. A command that needs a checkout
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
[--timeout 15m] [--name <run>]` (the SSH path, as the box's own user).

## Feature detection

The REST gateway rejects request fields it does not know, so a caller must not
send `run_name`, `structured_output`, `model` or `command` to a daemon that
predates them. `GetSystemInfo` (`SystemInfo.capabilities`) lists the optional
features a daemon supports: `box_run_name`, `box_run_structured_output`,
`box_run_model` and `box_run_command`. An older daemon does
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
