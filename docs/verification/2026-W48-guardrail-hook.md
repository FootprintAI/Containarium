# 2026-W48 verification: coding-agent guardrail hook (#3761)

The live check of `containarium guardrail hook <event>` that CI cannot
make: what a real Claude Code session does with the handler's answers. The
steps are the four posted on #3761. The managed drop-in (#3762) is **not**
covered here; it needs a running daemon and a box, and is still open.

## Version and environment

- **Binary:** the `v0.141.3` release asset `containarium-linux-amd64`
  (tag commit `1e4dc101946ae1a4aa99997f887d47b5decff353`), sha256
  `6c1ce4cd84b45c09cbe4c437b2c3ace2fc2bc5572ee9cd0a1864506b4bf2052e`.
  `containarium version` prints `Containarium v0.141.3`. Installed at
  `/usr/local/lib/containarium-guardrail/containarium`, the path the
  daemon pins the hook binary to inside a box.
- **Agent:** Claude Code `2.1.332` (npm `@anthropic-ai/claude-code@2.1.332`),
  run headless: `claude -p "Follow the plan." --permission-mode acceptEdits
  --allowedTools "Read,Write,Bash"`, as an unprivileged user.
- **Hooks:** all six events in exec form, `onFailure: "block"`,
  `timeout: 15`, in the user's `~/.claude/settings.json`
  ([`settings.json`](2026-W48-guardrail-hook/settings.json)). No `--engine`,
  so the in-process reference rules engine ran.
- **Model:** a stub Messages endpoint on loopback
  ([`stub.py`](2026-W48-guardrail-hook/stub.py)) that scripts the tool
  calls of the four steps and logs every request body.
  `ANTHROPIC_BASE_URL` pointed at it; the API key was a dummy. No real
  account and no real model.
- **Container:** a throwaway `node:22-bookworm` container (digest
  `sha256:7c400d78…`), driven by
  [`run.sh`](2026-W48-guardrail-hook/run.sh).
- **Data:** synthetic only. `/work/.env` held
  `AWS=AKIAIOSFODNN7EXAMPLE` and `owner ann@example.com`.
- **Run:** 2026-11-28 13:42 UTC, with exactly the committed `run.sh`,
  `settings.json` and `stub.py`. 5 model requests logged.

## Results

| Step (from #3761) | Result |
|---|---|
| 1. A secret in a file reaches the model as a marker | ✅ |
| 2. `PostToolUse` sees the rewritten input | ✅ |
| 3. A failed command | ❌ raw output reached the model: the #3765 case |
| 4. A number is left a number | ✅ |

### 1. A secret in a file reaches the model as a marker

The stub scripted `Read /work/.env`. The next request's `tool_result` was:

```
1	AWS=[[AWS_ACCESS_KEY_ID:9db50ac75ee2]]
2	owner [[EMAIL:bc274978ba46]]
```

Neither `AKIAIOSFODNN7EXAMPLE` nor `ann@example.com` appears in requests 1
to 3. `findings.jsonl` has `REDACTED` rows for `AWS_ACCESS_KEY_ID` and
`EMAIL`.

### 2. `PostToolUse` sees the rewritten input

The stub scripted `Write /work/out.txt` with the content
`owner [[EMAIL:bc274978ba46]]`, the marker taken from step 1's result. The
file on disk holds `owner ann@example.com`. `findings.jsonl` has **no**
`GUARDRAIL_HOOK_OUTCOME_MARKER_IN_TOOL_INPUT` row, so `PostToolUse` received
the rewritten input and the record stands as designed.

### 3. A failed command

The stub scripted `Bash` with `cat /work/.env; false`. The next request's
`tool_result` was `is_error: true` with the **raw output**:

```
Exit code 1
AWS=AKIAIOSFODNN7EXAMPLE
owner ann@example.com
```

This is the first and only place either value appears in any request body
(request 4, carried again in request 5 as history). `PostToolBatch` saw it:
`findings.jsonl` has `UNREDACTED_AT_BATCH` rows for `AWS_ACCESS_KEY_ID` and
`EMAIL`, but recording cannot remove the result. The issue named this
outcome as the defect #3765 exists for; it is now observed on a live agent,
not inferred.

**Follow-up (#3840):** the hook now wraps a `Bash` command so a failed one
takes the redacted path, where Claude Code's settings allow all of Bash or
the session runs in `bypassPermissions`. Re-run with this harness and those
settings, the same call came back `is_error: false` as markers plus
`[exit status 1]`. Under narrower rules the wrapper is not applied and this
step still fails; see "What the hooks do not cover" in
`docs/architecture/guardrail.md`.

### 4. A number is left a number

The stub scripted `Bash` with `echo 42; echo 3.14`. The result came back
`is_error: false` with `42` and `3.14`; no shape error.

### Also observed

- `SessionStart`: the first request carries the added context beginning
  "A guardrail is active in this environment. Text of the form
  `[[TYPE:0123456789ab]]` is a marker…".
- The state directory was created `0700`, with `marker.key`,
  `markers.jsonl` and `findings.jsonl` at `0600`, and a `stamps/` entry.
- `UserPromptSubmit` let the prompt `Follow the plan.` through (no finding).

## Not verified here

- #3762, the daemon-installed managed drop-in: `dropin enable`, coverage,
  `NOT_COVERED_TAMPERED`, and Claude Code's side of a managed hook
  (picked up without a restart; not disabled by a user's
  `disableAllHooks`).
- A real detection engine behind `--engine`.
- `--block-on-batch-finding` (#3765 item 3).
