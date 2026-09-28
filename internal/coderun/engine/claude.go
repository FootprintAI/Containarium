package engine

import (
	"strings"

	"github.com/footprintai/containarium/internal/coderun"
)

// claudeEngine is Claude Code — the engine `containarium code` has installed
// since #1673.
//
// Everything here is a MOVE of already-shipped behaviour behind the Engine
// interface, not a reimplementation. In particular RunCommand on a
// SecretCredential delegates to coderun.BuildClaudeRunCommand, so the command
// dispatched to every existing box stays byte-identical
// (TestClaudeSecretRunCommandIsByteIdenticalToTheShippedBuilder pins that).
//
// Note what is NOT here: any credential precheck. #2036 removed the
// CLAUDE_CODE_OAUTH_TOKEN tenant-secret precheck deliberately — Claude Code's
// terms (https://code.claude.com/docs/en/legal-and-compliance, "Authentication
// and credential use") forbid a platform collecting, storing, or intermediating
// a Claude.ai credential. #1727 does not reintroduce it: the install script and
// verify script below are #2036's, unchanged.
type claudeEngine struct {
	opts Options
}

// ClaudeInstallScript is Anthropic's own native installer, run verbatim. It
// writes to ~/.local/bin/claude — user-level, no root — which is why `code
// install` needs no daemon-side privileged exec path.
const ClaudeInstallScript = "curl -fsSL https://claude.ai/install.sh | bash"

// ClaudeInstallStateFile carries one bit from the install step to the verify
// step: whether ~/.claude/.credentials.json already existed. A user who signed
// in through Anthropic's flow legitimately has one, so the assertion that has to
// hold is "the install did not create it", not "there is none".
const ClaudeInstallStateFile = "$HOME/.cache/containarium/code-install-state"

// claudeGatewayEnvPath is where a gateway-credentialled Claude box keeps its
// 0600 token file. Under ~/.claude so it sits with the rest of Claude Code's
// own state and is removed with it.
const claudeGatewayEnvPath = "$HOME/.claude/gateway.env"

func (claudeEngine) Name() Name                     { return NameClaude }
func (e claudeEngine) Credential() CredentialSource { return e.opts.Credential }
func (claudeEngine) GatewayEnvPath() string         { return claudeGatewayEnvPath }

// InstallScript runs Anthropic's installer unmodified. The only addition is the
// one bit VerifyScript needs, so "the install created a credentials file" can be
// told apart from "the user signed in earlier", which is the supported path.
//
// Version, when set, is passed to the installer as its argument — the
// installer's own documented way to pin a version. The command line is
// otherwise unchanged.
func (claudeEngine) InstallScript(o InstallOptions) string {
	installer := ClaudeInstallScript
	if v := strings.TrimSpace(o.Version); v != "" {
		installer += " -s " + shellQuoteSingle(v)
	}
	return `set -e
mkdir -p "$(dirname "` + ClaudeInstallStateFile + `")"
if [ -f "$HOME/.claude/.credentials.json" ]; then
  echo present > "` + ClaudeInstallStateFile + `"
else
  echo absent > "` + ClaudeInstallStateFile + `"
fi
` + installer
}

// VerifyScript is #2036's verification, unchanged: print the installed binary's
// version, assert the install created no ~/.claude/.credentials.json, and report
// which credential SOURCE the box has.
//
// That last part is deliberately NAMES ONLY — every branch tests for presence
// and echoes a literal, because expanding any of these would put a live
// credential into the CLI's output and the user's scrollback.
func (e claudeEngine) VerifyScript() string {
	script := `set -e
"$HOME/.local/bin/claude" --version
creds="$HOME/.claude/.credentials.json"
before=absent
if [ -f "` + ClaudeInstallStateFile + `" ]; then
  before="$(cat "` + ClaudeInstallStateFile + `")"
  rm -f "` + ClaudeInstallStateFile + `"
fi
if [ "$before" = absent ] && [ -f "$creds" ]; then
  echo "the install created $creds — containarium never mints or stores a Claude.ai credential" >&2
  exit 3
fi
echo "credential sources present:"
found=0
if [ -f "$creds" ]; then
  echo "  - $creds (signed in through Anthropic's own flow)"
  found=1
fi
settings="$HOME/.claude/settings.json"
for key in ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN; do
  if [ -f "$settings" ] && grep -q "\"$key\"" "$settings"; then
    echo "  - $key in the env block of $settings"
    found=1
  fi
done
providers="$(env | sed -n 's/^\(CLAUDE_CODE_USE_[A-Z0-9_]*\)=.*/\1/p')"
if [ -n "$providers" ]; then
  for p in $providers; do echo "  - $p (3P inference provider)"; done
  found=1
fi`
	// A gateway-credentialled box has a fourth source, and it is the one the
	// install just wrote — so report it by name too, for the same reason the
	// other three are reported: so the operator can see the box is wired
	// without anything printing a value.
	if e.opts.Credential != nil && e.opts.Credential.Kind() == KindGateway {
		script += `
if [ -f "` + claudeGatewayEnvPath + `" ]; then
  echo "  - ` + GatewayTokenEnvVar + ` in ` + claudeGatewayEnvPath + ` (containarium model gateway)"
  found=1
fi`
	}
	script += `
if [ "$found" = 0 ]; then
  echo "  (none yet — sign in on the box, or place your own key in $settings)"
fi`
	return script
}

// RunCommand renders the command process_start spawns.
//
// For a tenant secret this is coderun.BuildClaudeRunCommand verbatim — the
// shipped path, unchanged. For a gateway credential only the sourced env file
// differs: the box has a scoped gateway token instead of a provider key, and
// Claude Code reads ANTHROPIC_BASE_URL / ANTHROPIC_AUTH_TOKEN out of its
// environment either way.
func (e claudeEngine) RunCommand(prompt string, streamJSON, continueSession bool) string {
	var cmd string
	if e.opts.Credential != nil && e.opts.Credential.Kind() == KindGateway {
		cmd = sourceEnvPrefix(`"`+claudeGatewayEnvPath+`"`) + claudeRunBody(prompt)
		if streamJSON {
			cmd += " --output-format stream-json"
		}
	} else {
		cmd = coderun.BuildClaudeRunCommand(prompt, streamJSON)
	}
	if continueSession {
		cmd += " --continue"
	}
	return cmd
}

// claudeRunBody is everything after the env prefix in a Claude run: the
// conditional --mcp-config dance plus the non-interactive invocation. Shared by
// both credential sources so the two cannot drift.
//
// --mcp-config is conditional because claude treats a config path that does not
// exist as a hard startup error, and most boxes have no such file.
func claudeRunBody(prompt string) string {
	return "mcpcfg=; [ -f \"" + coderun.ContainariumMCPConfigPath + "\" ] && mcpcfg=\"--mcp-config " +
		coderun.ContainariumMCPConfigPath + "\"; " +
		// $mcpcfg is deliberately unquoted: it has to split into the flag and
		// its value, and is empty when the file is absent.
		"~/.local/bin/claude $mcpcfg -p " + shellQuoteSingle(prompt)
}
