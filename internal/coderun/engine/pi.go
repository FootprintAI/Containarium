package engine

import (
	"strings"
)

// piEngine is pi (https://pi.dev, @earendil-works/pi-coding-agent) — a
// local-first coding agent that runs INSIDE the box rather than driving it from
// a laptop over MCP. docs/integrations/pi.md argues why that is the right shape
// for a Containarium box: pi has no MCP client by design, so its native
// read/write/edit/bash tools act on the box's filesystem directly and agent-box
// is redundant on this path.
//
// pi is the reason #1727 exists: it accepts a custom OpenAI-compatible provider
// in ~/.pi/agent/models.json whose apiKey is read from the environment, which is
// exactly the shape a scoped gateway token fits. A box running pi through the
// gateway holds no provider key anywhere.
type piEngine struct {
	opts Options
}

// PiVersion is the pinned pi version `code install --engine pi` installs.
//
// Pinned, not floating, for a concrete reason: models.json is a third-party
// schema we do not own, and TestPiModelsJSON pins our rendered output against a
// fixture taken from THIS version's own docs. A floating install would let pi
// rename a field and turn that fixture into a lie on the next box someone
// provisions. Bump this and the fixture together, or not at all.
const PiVersion = "0.87.1"

// PiPackage is pi's npm package. docs/integrations/pi.md names it, and it is
// also what pi.dev/install.sh itself installs.
const PiPackage = "@earendil-works/pi-coding-agent"

// PiNodeMinVersion is pi's own engines.node floor (package.json of
// @earendil-works/pi-coding-agent@0.87.1: ">=22.19.0"). Checked explicitly so a
// box without new-enough Node fails naming the fix, instead of failing inside
// npm's EBADENGINE output.
const PiNodeMinVersion = "22.19.0"

// piAgentDir is pi's user-level config directory (pi's own
// docs/configuration.md: "the agent directory, which defaults to ~/.pi/agent").
// Written absolute-from-$HOME rather than ~-relative because these strings are
// tested by the shell, not expanded by it.
const piAgentDir = "$HOME/.pi/agent"

// piModelsPath is the custom-provider config `code install` renders.
const piModelsPath = piAgentDir + "/models.json"

// piGatewayEnvPath is the 0600 file `code run` writes the per-run gateway token
// to before process_start. Contract C4 puts it at ~/.pi/gateway.env — beside
// pi's state, not inside agent/, so pi never tries to parse it as config.
const piGatewayEnvPath = "$HOME/.pi/gateway.env"

// piBin is where the install lands pi. $HOME/.local/bin, matching
// ~/.local/bin/claude and ~/.local/bin/agent-box, so the whole command stays
// user-level with no sudo anywhere.
const piBin = "$HOME/.local/bin/pi"

func (piEngine) Name() Name                     { return NamePi }
func (e piEngine) Credential() CredentialSource { return e.opts.Credential }
func (piEngine) GatewayEnvPath() string         { return piGatewayEnvPath }

// InstallScript installs pi at a pinned version and writes its
// custom-provider config.
//
// It does NOT use pi's own install.sh, and that is a deliberate deviation from
// the issue's wording. The real https://pi.dev/install.sh (a) takes no version
// argument — the version comes from release metadata it fetches, so there is
// nothing to pin — and (b) opens /dev/tty for a logo animation, `stty`, and an
// interactive "install Node for you?" prompt. `code install` execs over ssh with
// no TTY, so that installer is a hang, not a pin. The npm line below is the
// alternative docs/integrations/pi.md already documents, and it takes a version.
//
// npm's prefix is pointed at $HOME/.local so `npm i -g` needs no root, and
// --ignore-scripts is pi.md's own recommendation.
func (piEngine) InstallScript(o InstallOptions) string {
	version := strings.TrimSpace(o.Version)
	if version == "" {
		version = PiVersion
	}
	return `set -e
# pi requires Node >= ` + PiNodeMinVersion + ` (its own engines.node). Check it here so a
# box without it says so, instead of failing inside npm's EBADENGINE output.
if ! command -v node >/dev/null 2>&1; then
  echo "pi needs Node >= ` + PiNodeMinVersion + ` on the box and none is installed." >&2
  echo "Install Node on the box (docs/integrations/pi.md step 2), then re-run this command." >&2
  exit 5
fi
if ! node -e 'const [a,b,c]=process.versions.node.split(".").map(Number); process.exit(a>22||(a===22&&(b>19||(b===19&&c>=0)))?0:1)'; then
  echo "pi needs Node >= ` + PiNodeMinVersion + `; this box has $(node --version). Upgrade Node on the box, then re-run." >&2
  exit 5
fi
mkdir -p "$HOME/.local"
npm config set prefix "$HOME/.local" >/dev/null
npm install -g --ignore-scripts --no-fund --no-audit ` + shellQuoteSingle(PiPackage+"@"+version) + `
# umask before the write, not chmod after: a chmod leaves a window in which the
# file exists world-readable, and on a box the user shares with an agent that
# window is not theoretical (same argument as boxbootstrap's apply.sh).
umask 077
mkdir -p ` + piAgentDir + `
printf '%s' ` + shellQuoteSingle(o.ModelsJSON) + ` > ` + piModelsPath + `
chmod 600 ` + piModelsPath + `
echo "pi installed at ` + piBin + ` (` + version + `), provider config at ` + piModelsPath + `"`
}

// VerifyScript proves the box can actually reach a model, which is the whole
// point of verifying at install time: the alternative is the user discovering a
// misconfiguration at their first real prompt.
//
// The prompt is the AC's: `pi -p "print the current working directory" --mode
// json`. It runs on whatever credential the box now has — for a gateway
// credential, a deliberately short-lived token the caller wrote to
// GatewayEnvPath just before this.
//
// As on the Claude path, the credential is reported by NAME only. Nothing here
// expands the token.
func (e piEngine) VerifyScript() string {
	script := `set -e
` + piBin + ` --version
echo "credential sources present:"
found=0`
	if e.opts.Credential != nil && e.opts.Credential.Kind() == KindGateway {
		script += `
if [ -f "` + piGatewayEnvPath + `" ]; then
  echo "  - ` + GatewayTokenEnvVar + ` in ` + piGatewayEnvPath + ` (containarium model gateway)"
  found=1
fi`
	} else {
		script += `
if [ -f /run/containarium/secrets.env ]; then
  echo "  - /run/containarium/secrets.env (tenant secrets, compose delivery)"
  found=1
fi
if [ -d /run/secrets ]; then
  echo "  - /run/secrets/<NAME> (tenant secrets, file delivery)"
  found=1
fi
if [ -f "` + piAgentDir + `/auth.json" ]; then
  echo "  - ` + piAgentDir + `/auth.json (signed in with pi's own /login)"
  found=1
fi`
	}
	script += `
if [ "$found" = 0 ]; then
  echo "  (none yet)"
fi
` + e.runPrefix() + piBin + ` -p 'print the current working directory' --mode json`
	return script
}

// RunCommand renders the command process_start spawns.
//
// pi takes the prompt as a POSITIONAL argument after -p/--print (pi's own
// docs/cli.md: `pi --print "Summarize this repository"`), so the prompt is
// single-quoted exactly as on the Claude path. --mode json is what makes pi emit
// JSONL events on stdout, which is what --output-format-stream-json means for
// this engine; -c resumes the most recent session for the run's working
// directory.
func (e piEngine) RunCommand(prompt string, streamJSON, continueSession bool, sessionID string) string {
	cmd := e.runPrefix() + "~/.local/bin/pi -p " + shellQuoteSingle(prompt)
	if streamJSON {
		cmd += " --mode json"
	}
	switch {
	case sessionID != "":
		// pi's own --session resumes a SPECIFIC session id (docs/cli.md),
		// which is a better fit than `-c`'s "most recent" semantics and
		// takes priority over continueSession (#2193; callers must not set
		// both).
		cmd += " --session " + shellQuoteSingle(sessionID)
	case continueSession:
		cmd += " -c"
	}
	if m := strings.TrimSpace(e.opts.Model); m != "" {
		cmd += " --model " + shellQuoteSingle(m)
	}
	return cmd
}

// runPrefix is the env-loading prefix for this box's credential source.
func (e piEngine) runPrefix() string {
	if e.opts.Credential != nil && e.opts.Credential.Kind() == KindGateway {
		return sourceEnvPrefix(`"` + piGatewayEnvPath + `"`)
	}
	return sourceEnvPrefix("/run/containarium/secrets.env")
}
