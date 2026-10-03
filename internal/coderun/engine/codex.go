package engine

import (
	"strings"
)

// codexEngine is OpenAI's Codex CLI (https://developers.openai.com/codex/cli,
// npm package @openai/codex) — a terminal coding agent that, like pi, runs
// INSIDE the box rather than being driven from a laptop over MCP.
//
// #2273 (split out of Containarium-cloud#2108; the gap is named in
// docs/product/agent-router.md's P1 list: "code install --engine codex stops
// being a rejected value for no product reason") adds this as a THIRD typed
// choice, parallel to claude and pi. It is a DIFFERENT vocabulary from
// pkg/pb's AGENT_ENGINE_CODEX / internal/agentengine (which routes an
// already-running in-box SKILL to the model gateway's "openai" provider):
// this package only ever lands a CLI toolchain on a box for `code
// run`/`attach`/`status`/`stop` to drive, same as it does for claude and pi.
//
// Facts pinned here were checked against OpenAI's own docs
// (developers.openai.com/codex/cli/reference, developers.openai.com/codex/auth,
// developers.openai.com/codex/environment-variables, npmjs.com/package/@openai/codex)
// rather than assumed from Claude/pi's shape:
//
//   - Install: `npm install -g @openai/codex` is the official line (OpenAI's
//     own install announcement and npmjs.com both name the scoped package;
//     the UNSCOPED `codex` on npm is an unrelated 2012 documentation
//     generator). UNLIKE pi, the postinstall script is REQUIRED — it
//     downloads the platform-specific Rust binary, so this install does NOT
//     pass --ignore-scripts (pi's flag would leave codex with no working
//     binary; see TestInstallScript_CodexIsNpmInstalledWithScriptsEnabled).
//   - engines.node is ">=16" (npmjs.com) — lower than pi's floor, checked
//     with its own constant rather than reusing PiNodeMinVersion.
//   - Non-interactive run: `codex exec [FLAGS] "<prompt>"` — the prompt is
//     POSITIONAL, unlike claude/pi's -p flag. `--json` emits
//     newline-delimited JSON events; `--model`/`-m` pins a model; `codex exec
//     resume [SESSION_ID]` or `codex exec resume --last` is codex's ONLY
//     continuation mechanism (no bare --continue), so continueSession maps
//     to `resume --last` and sessionID to `resume <id>` — the same two
//     concepts claude's --continue/--resume and pi's -c/--session express.
//   - Credential: `codex exec` reads CODEX_API_KEY (preferred) or
//     OPENAI_API_KEY directly from the environment with no `codex login`
//     step first (developers.openai.com/codex/environment-variables — and
//     already independently established in this codebase by #2256, see
//     CHANGELOG.md's 0.98.0 entry, for the unrelated agent-router path).
//     Interactive sign-in is `codex login` (browser) or `codex login
//     --device-auth` (the SSH-friendly device-code path,
//     developers.openai.com/codex/auth) and caches `~/.codex/auth.json`.
//
// What was NOT independently re-derived: exact flag ordering when --json and
// --model are BOTH combined with `resume` in one invocation. The documented
// examples never show all three together; RunCommand's ordering (resume,
// then --json, then --model, then the prompt) follows the flags-before-
// positional shape every example DOES show. If OpenAI's parser disagrees,
// TestRunCommand pins the exact string this engine emits today and will
// catch a future change.
//
// Also NOT implemented here: a `--credential gateway` path. #2273's own text
// treats that as contingent on the model gateway's provider generalization
// (#1369/#1374) landing; internal/cmd/code_engine.go's resolveCodeInstallPlan
// rejects `--engine codex --credential gateway` with a message naming this,
// rather than shipping an unverified one. The gateway-shaped methods below
// still exist (GatewayEnvPath, the gateway branches in VerifyScript/
// RunCommand) because the Engine interface requires them and they are cheap,
// pure, and already table-tested — wiring them up at the cmd layer is the
// follow-up, not a redesign.
type codexEngine struct {
	opts Options
}

// CodexPackage is Codex CLI's npm package — the scoped name. Installing the
// unscoped `codex` on npm silently gets a different, unrelated tool.
const CodexPackage = "@openai/codex"

// CodexNodeMinVersion is Codex CLI's own engines.node floor (npmjs.com,
// @openai/codex: ">=16"). Deliberately its own constant — bumping pi's floor
// must never silently change codex's.
const CodexNodeMinVersion = "16"

// codexHome is Codex CLI's own config/state directory. Confirmed by its own
// docs (`codex login` caches `~/.codex/auth.json`) and already read
// elsewhere in this repo: internal/cmd/quickstart.go's codexAppendMCP writes
// `~/.codex/config.toml` for the laptop-side MCP wiring.
const codexHome = "$HOME/.codex"

// codexBin is where the install lands codex. $HOME/.local/bin, matching
// ~/.local/bin/claude and ~/.local/bin/pi, so the whole command stays
// user-level with no sudo anywhere.
const codexBin = "$HOME/.local/bin/codex"

// codexGatewayEnvPath is the 0600 file `code run` would write a per-run
// gateway token to before process_start, beside codex's own state —
// matching ~/.claude/gateway.env and ~/.pi/gateway.env. Not yet wired up at
// the cmd layer (see the type doc comment above).
const codexGatewayEnvPath = codexHome + "/gateway.env"

func (codexEngine) Name() Name                     { return NameCodex }
func (e codexEngine) Credential() CredentialSource { return e.opts.Credential }
func (codexEngine) GatewayEnvPath() string         { return codexGatewayEnvPath }

// InstallScript installs Codex CLI at a pinned version — or, when Version is
// empty, whatever npm considers current, the same fallback Claude's own
// installer uses. Codex ships no `curl | bash` one-liner, so this is the
// documented `npm install -g @openai/codex` line, not a reimplementation of
// one.
//
// No --ignore-scripts: codex's postinstall script fetches the
// platform-specific binary (the npm package is a thin launcher around it),
// so skipping it — pi's own flag, needed there for the opposite reason —
// would leave codexBin unable to run.
func (codexEngine) InstallScript(o InstallOptions) string {
	pkg := CodexPackage
	if v := strings.TrimSpace(o.Version); v != "" {
		pkg += "@" + v
	}
	return `set -e
# codex needs Node >= ` + CodexNodeMinVersion + ` (its own engines.node). Check it here so a
# box without it says so, instead of failing inside npm's EBADENGINE output.
if ! command -v node >/dev/null 2>&1; then
  echo "codex needs Node >= ` + CodexNodeMinVersion + ` on the box and none is installed." >&2
  exit 5
fi
if ! node -e 'process.exit(parseInt(process.versions.node.split(".")[0], 10) >= ` + CodexNodeMinVersion + ` ? 0 : 1)'; then
  echo "codex needs Node >= ` + CodexNodeMinVersion + `; this box has $(node --version). Upgrade Node on the box, then re-run." >&2
  exit 5
fi
mkdir -p "$HOME/.local"
npm config set prefix "$HOME/.local" >/dev/null
npm install -g --no-fund --no-audit ` + shellQuoteSingle(pkg) + `
echo "codex installed at ` + codexBin + `"`
}

// VerifyScript proves the box can actually reach a model: print the
// installed binary's version, report which credential source is present
// (names only — never a value, the same rule #2030/#2036 pin for Claude),
// then run one cheap real prompt through whatever credential the box now
// has.
func (e codexEngine) VerifyScript() string {
	script := `set -e
` + codexBin + ` --version
echo "credential sources present:"
found=0`
	if e.opts.Credential != nil && e.opts.Credential.Kind() == KindGateway {
		script += `
if [ -f "` + codexGatewayEnvPath + `" ]; then
  echo "  - ` + GatewayTokenEnvVar + ` in ` + codexGatewayEnvPath + ` (containarium model gateway)"
  found=1
fi`
	} else {
		script += `
if [ -f /run/containarium/secrets.env ]; then
  echo "  - /run/containarium/secrets.env (tenant secrets, compose delivery — CODEX_API_KEY or OPENAI_API_KEY)"
  found=1
fi
if [ -d /run/secrets ]; then
  echo "  - /run/secrets/<NAME> (tenant secrets, file delivery)"
  found=1
fi
if [ -f "` + codexHome + `/auth.json" ]; then
  echo "  - ` + codexHome + `/auth.json (signed in with codex login)"
  found=1
fi`
	}
	script += `
if [ "$found" = 0 ]; then
  echo "  (none yet — sign in on the box with codex login, or place CODEX_API_KEY in its environment)"
fi
` + e.runPrefix() + codexBin + ` exec --json 'print the current working directory'`
	return script
}

// RunCommand renders the command process_start spawns.
//
// `codex exec` takes the prompt as a POSITIONAL argument after any flags —
// unlike claude/pi's -p, there is no flag name for it. resume is codex's
// only continuation mechanism: continueSession maps to `resume --last`,
// sessionID to `resume <id>`, taking priority over continueSession exactly
// as the claude/pi paths do (#2193; callers validate the two are mutually
// exclusive before calling this).
func (e codexEngine) RunCommand(prompt string, streamJSON, continueSession bool, sessionID string) string {
	cmd := e.runPrefix() + "~/.local/bin/codex exec"
	switch {
	case sessionID != "":
		cmd += " resume " + shellQuoteSingle(sessionID)
	case continueSession:
		cmd += " resume --last"
	}
	if streamJSON {
		cmd += " --json"
	}
	if m := strings.TrimSpace(e.opts.Model); m != "" {
		cmd += " --model " + shellQuoteSingle(m)
	}
	return cmd + " " + shellQuoteSingle(prompt)
}

// runPrefix is the env-loading prefix for this box's credential source,
// matching pi's shape: a gateway credential sources codex's own gateway.env
// (not yet reachable from the cmd layer — see the type doc comment); a
// tenant secret sources the daemon's generic secrets.env, which carries
// whatever --secret-name named (CODEX_API_KEY, recommended; OPENAI_API_KEY
// also works per OpenAI's own docs).
func (e codexEngine) runPrefix() string {
	if e.opts.Credential != nil && e.opts.Credential.Kind() == KindGateway {
		return sourceEnvPrefix(`"` + codexGatewayEnvPath + `"`)
	}
	return sourceEnvPrefix("/run/containarium/secrets.env")
}
