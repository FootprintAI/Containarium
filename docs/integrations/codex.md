# Codex CLI on Containarium

[Codex CLI](https://developers.openai.com/codex/cli) (npm package
`@openai/codex`) is OpenAI's terminal coding agent. Like
[pi](pi.md#why-pi-runs-inside-the-box), it runs *inside* the box rather than
being driven from your laptop over MCP.

```bash
containarium create alice --ssh-key ~/.ssh/id_ed25519.pub --server <backend>
containarium ssh-config sync
containarium code install alice --engine codex --credential secret \
    --secret-name CODEX_API_KEY
containarium code run alice --prompt "fix the failing test in ./api"
containarium code attach alice          # reconnect after a dropped connection
containarium code status alice          # liveness, then the exit code
```

`--engine` defaults to `claude`, so plain `containarium code install alice`
is unaffected — this is a parallel, opt-in third choice (#2273;
`docs/product/agent-router.md`'s P1 list named this exact gap: "`code
install --engine codex` stops being a rejected value for no product
reason").

## What `code install --engine codex` does

- Lands the Codex CLI at `~/.local/bin/codex` via `npm install -g
  @openai/codex` (Codex ships no `curl | bash` installer). Node ≥ 16 is
  required. **Unlike pi's install, this does NOT pass `--ignore-scripts`** —
  Codex's npm package is a thin launcher whose postinstall script fetches the
  real, platform-specific binary; skipping it leaves a binary that cannot
  run.
- Also lands `agent-box`, so `code run`/`attach`/`status`/`stop` work on the
  same box.
- Records `engine: codex` in `~/.containarium/code.json`.
- Verifies with `codex --version` plus one cheap real prompt (`codex exec
  --json "print the current working directory"`), reporting which
  credential source is present **by name only** — the same discipline `code
  install` already holds for Claude Code (#2030).

## Credential: bring your own key

`code install` never requires, reads, or stores an OpenAI/Codex credential.

- **Headless**: a tenant secret named `CODEX_API_KEY` (`containarium secrets
  set alice CODEX_API_KEY sk-... --delivery compose && containarium secrets
  refresh alice`) — `codex exec` reads it directly, no `codex login` step
  needed. `OPENAI_API_KEY` also works, but OpenAI's own docs call it
  insufficient alone for a fully headless run with no prior sign-in;
  `CODEX_API_KEY` is documented to work standalone
  (`developers.openai.com/codex/environment-variables`; already established
  in this codebase for the unrelated agent-router path by #2256).
- **Interactive**: `containarium connect alice`, then `codex login
  --device-auth` (prints a short code + URL to approve from any browser — no
  direct network path needed between box and browser) or plain `codex
  login`. Either caches `~/.codex/auth.json` on the box.

As with pi, `--delivery env` secrets do not reach an SSH shell session (see
[pi.md](pi.md#why-not-env-delivery)) — use `compose` or `file` delivery.

## Not supported yet

- **`--credential gateway`** — rejected, naming the fix. Routing codex
  through the model gateway with no provider key on the box is contingent on
  the gateway's provider generalization (tracked as #1369/#1374 on
  Containarium-cloud); #2273 scoped it out rather than shipping it
  unverified.
- **Automatic session-id discovery** for `code status`'s `session_id` field.
  Codex's on-disk session-file layout was not independently confirmed, so
  it's left undiscovered rather than guessed (see
  `internal/coderun/engine/session_discovery.go`). `code run --continue` /
  `--session <id>` still work — only the automatic lookup is missing.

## What was actually verified

The CLI invocation this engine builds — `codex exec [resume
[<id>|--last]] [--json] [--model <m>] "<prompt>"` — and the install/auth
facts above were checked against `developers.openai.com/codex/cli/reference`,
`developers.openai.com/codex/auth`,
`developers.openai.com/codex/environment-variables`, and
`npmjs.com/package/@openai/codex`, not carried over unverified from Claude
Code or pi's shape. Not independently re-derived: exact flag ordering when
`--json` and `--model` are both combined with `resume` — the documented
examples never show all three together. See
`internal/coderun/engine/codex.go`'s doc comment for the full list.
