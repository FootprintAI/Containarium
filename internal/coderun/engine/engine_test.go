package engine

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/coderun"
)

// TestRunCommand is the #1727 AC's table: every (engine × streamJSON ×
// continue × credential) combination, with the exact command string pinned.
//
// Pinning the whole string rather than substring-matching is deliberate. The
// command is assembled by string concatenation and then handed to `/bin/sh
// -c` on a box, so the two things that can go wrong are a missing flag and a
// quoting slip — and only an exact comparison catches the second.
func TestRunCommand(t *testing.T) {
	const prompt = "fix the bug"

	// The three prefixes, written out once so a test failure shows which
	// credential source produced the wrong one.
	const secretPrefix = `set -a; [ -f /run/containarium/secrets.env ] && . /run/containarium/secrets.env; set +a; `
	const claudeGatewayPrefix = `set -a; [ -f "$HOME/.claude/gateway.env" ] && . "$HOME/.claude/gateway.env"; set +a; `
	const piGatewayPrefix = `set -a; [ -f "$HOME/.pi/gateway.env" ] && . "$HOME/.pi/gateway.env"; set +a; `
	const codexGatewayPrefix = `set -a; [ -f "$HOME/.codex/gateway.env" ] && . "$HOME/.codex/gateway.env"; set +a; `

	// Claude's own body is unchanged from BuildClaudeRunCommand — the
	// conditional --mcp-config dance included.
	const claudeBody = `mcpcfg=; [ -f "$HOME/.claude/containarium-mcp.json" ] && mcpcfg="--mcp-config $HOME/.claude/containarium-mcp.json"; ~/.local/bin/claude $mcpcfg -p 'fix the bug'`

	tests := []struct {
		name       string
		engine     Name
		credential CredentialSource
		model      string
		streamJSON bool
		continues  bool
		sessionID  string
		want       string
	}{
		// ---- claude × secret (today's shipped behaviour) ----
		{
			name:       "claude/secret/plain",
			engine:     NameClaude,
			credential: SecretCredential{},
			want:       secretPrefix + claudeBody,
		},
		{
			name:       "claude/secret/streamJSON",
			engine:     NameClaude,
			credential: SecretCredential{},
			streamJSON: true,
			want:       secretPrefix + claudeBody + ` --output-format stream-json`,
		},
		{
			name:       "claude/secret/continue",
			engine:     NameClaude,
			credential: SecretCredential{},
			continues:  true,
			want:       secretPrefix + claudeBody + ` --continue`,
		},
		{
			name:       "claude/secret/streamJSON+continue",
			engine:     NameClaude,
			credential: SecretCredential{},
			streamJSON: true,
			continues:  true,
			want:       secretPrefix + claudeBody + ` --output-format stream-json --continue`,
		},

		// ---- claude × gateway ----
		{
			name:       "claude/gateway/plain",
			engine:     NameClaude,
			credential: GatewayCredential{Provider: "anthropic"},
			want:       claudeGatewayPrefix + claudeBody,
		},
		{
			name:       "claude/gateway/streamJSON+continue",
			engine:     NameClaude,
			credential: GatewayCredential{Provider: "anthropic"},
			streamJSON: true,
			continues:  true,
			want:       claudeGatewayPrefix + claudeBody + ` --output-format stream-json --continue`,
		},

		// ---- pi × gateway (the #1727 headline path) ----
		{
			name:       "pi/gateway/plain",
			engine:     NamePi,
			credential: GatewayCredential{Provider: "kafeido"},
			want:       piGatewayPrefix + `~/.local/bin/pi -p 'fix the bug'`,
		},
		{
			name:       "pi/gateway/streamJSON",
			engine:     NamePi,
			credential: GatewayCredential{Provider: "kafeido"},
			streamJSON: true,
			want:       piGatewayPrefix + `~/.local/bin/pi -p 'fix the bug' --mode json`,
		},
		{
			// --continue maps to `pi -c`, per the AC.
			name:       "pi/gateway/continue",
			engine:     NamePi,
			credential: GatewayCredential{Provider: "kafeido"},
			continues:  true,
			want:       piGatewayPrefix + `~/.local/bin/pi -p 'fix the bug' -c`,
		},
		{
			name:       "pi/gateway/streamJSON+continue",
			engine:     NamePi,
			credential: GatewayCredential{Provider: "kafeido"},
			streamJSON: true,
			continues:  true,
			want:       piGatewayPrefix + `~/.local/bin/pi -p 'fix the bug' --mode json -c`,
		},
		{
			// The model from code.json becomes pi's --model, so a run cannot
			// silently drift off the model the gateway token allows.
			name:       "pi/gateway/model",
			engine:     NamePi,
			credential: GatewayCredential{Provider: "kafeido"},
			model:      "kafeido-coder",
			want:       piGatewayPrefix + `~/.local/bin/pi -p 'fix the bug' --model 'kafeido-coder'`,
		},

		// ---- pi × secret ----
		{
			name:       "pi/secret/plain",
			engine:     NamePi,
			credential: SecretCredential{Name: "ANTHROPIC_API_KEY"},
			want:       secretPrefix + `~/.local/bin/pi -p 'fix the bug'`,
		},
		{
			name:       "pi/secret/streamJSON+continue+model",
			engine:     NamePi,
			credential: SecretCredential{Name: "ANTHROPIC_API_KEY"},
			model:      "claude-sonnet-5",
			streamJSON: true,
			continues:  true,
			want:       secretPrefix + `~/.local/bin/pi -p 'fix the bug' --mode json -c --model 'claude-sonnet-5'`,
		},

		// ---- #2193: --session / session_id resume ----
		{
			name:       "claude/secret/session",
			engine:     NameClaude,
			credential: SecretCredential{},
			sessionID:  "abc-123",
			want:       secretPrefix + claudeBody + ` --resume 'abc-123'`,
		},
		{
			name:       "claude/secret/session takes priority over continue",
			engine:     NameClaude,
			credential: SecretCredential{},
			sessionID:  "abc-123",
			continues:  true,
			want:       secretPrefix + claudeBody + ` --resume 'abc-123'`,
		},
		{
			name:       "claude/gateway/session",
			engine:     NameClaude,
			credential: GatewayCredential{Provider: "anthropic"},
			sessionID:  "abc-123",
			streamJSON: true,
			want:       claudeGatewayPrefix + claudeBody + ` --output-format stream-json --resume 'abc-123'`,
		},
		{
			// The quote-breaking id is the injection half of "quoting
			// pinned": a session id that tries to terminate the quoted
			// string early must come back single-quoted just like a prompt.
			name:       "claude/secret/session with a single quote",
			engine:     NameClaude,
			credential: SecretCredential{},
			sessionID:  "'; touch /tmp/pwned; echo '",
			want:       secretPrefix + claudeBody + ` --resume ''\''; touch /tmp/pwned; echo '\'''`,
		},
		{
			name:       "pi/secret/session",
			engine:     NamePi,
			credential: SecretCredential{Name: "ANTHROPIC_API_KEY"},
			sessionID:  "sess-9",
			want:       secretPrefix + `~/.local/bin/pi -p 'fix the bug' --session 'sess-9'`,
		},
		{
			name:       "pi/gateway/session takes priority over continue, before --model",
			engine:     NamePi,
			credential: GatewayCredential{Provider: "kafeido"},
			sessionID:  "sess-9",
			continues:  true,
			model:      "kafeido-coder",
			want:       piGatewayPrefix + `~/.local/bin/pi -p 'fix the bug' --session 'sess-9' --model 'kafeido-coder'`,
		},

		// ---- #2273: codex, the third engine. `codex exec` takes the prompt
		// POSITIONAL (no -p), resume is its only continuation mechanism (no
		// bare --continue), and --json/--model come before the prompt — see
		// codex.go's doc comment for the docs these are checked against.
		{
			name:       "codex/secret/plain",
			engine:     NameCodex,
			credential: SecretCredential{Name: "CODEX_API_KEY"},
			want:       secretPrefix + `~/.local/bin/codex exec 'fix the bug'`,
		},
		{
			name:       "codex/secret/streamJSON+continue+model",
			engine:     NameCodex,
			credential: SecretCredential{Name: "CODEX_API_KEY"},
			model:      "gpt-5-codex",
			streamJSON: true,
			continues:  true,
			want:       secretPrefix + `~/.local/bin/codex exec resume --last --json --model 'gpt-5-codex' 'fix the bug'`,
		},
		{
			name:       "codex/gateway/plain",
			engine:     NameCodex,
			credential: GatewayCredential{Provider: "openai"},
			want:       codexGatewayPrefix + `~/.local/bin/codex exec 'fix the bug'`,
		},
		{
			// Same priority rule as claude/pi: a specific session id wins over
			// --continue, and both flags land before the prompt.
			name:       "codex/gateway/session takes priority over continue, before --json and --model",
			engine:     NameCodex,
			credential: GatewayCredential{Provider: "openai"},
			sessionID:  "sess-9",
			continues:  true,
			streamJSON: true,
			model:      "gpt-5-codex",
			want:       codexGatewayPrefix + `~/.local/bin/codex exec resume 'sess-9' --json --model 'gpt-5-codex' 'fix the bug'`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e, err := For(tc.engine, Options{Credential: tc.credential, Model: tc.model})
			if err != nil {
				t.Fatalf("For(%q): %v", tc.engine, err)
			}
			got := e.RunCommand(prompt, tc.streamJSON, tc.continues, tc.sessionID)
			if got != tc.want {
				t.Errorf("RunCommand mismatch\n got: %s\nwant: %s", got, tc.want)
			}
		})
	}
}

// TestRunCommand_PromptQuotingSurvivesARealShell is the injection half of the
// AC's "shell quoting pinned". The prompt is the one caller-supplied value in
// the command, and it lands inside `/bin/sh -c` on the box — so it must come
// back out of a real shell byte-for-byte for BOTH engines, including for the
// shapes that try to terminate the quoted string early.
func TestRunCommand_PromptQuotingSurvivesARealShell(t *testing.T) {
	prompts := []string{
		"plain text",
		"it's got an apostrophe",
		"'; touch /tmp/pwned; echo '",
		"$(rm -rf /) and `also this`",
		`back\slash and "double" quotes`,
	}

	for _, name := range []Name{NameClaude, NamePi, NameCodex} {
		for _, prompt := range prompts {
			t.Run(string(name)+"/"+prompt, func(t *testing.T) {
				e, err := For(name, Options{Credential: SecretCredential{}})
				if err != nil {
					t.Fatalf("For(%q): %v", name, err)
				}
				cmd := e.RunCommand(prompt, false, false, "")

				// The quoted prompt must appear verbatim in the command...
				quoted := coderun.ShellQuoteSingle(prompt)
				if !strings.Contains(cmd, quoted) {
					t.Fatalf("command does not carry the quoted prompt %s:\n%s", quoted, cmd)
				}
				// ...and a real shell must hand it back unchanged.
				// #nosec G204 -- fixed "sh -c" with one literal-quoted
				// argument produced by the quoter under test; this IS the
				// injection check, not a caller-reachable path.
				out, err := exec.Command("/bin/sh", "-c", "printf '%s' "+quoted).Output()
				if err != nil {
					t.Fatalf("shell rejected %q (quoted %s): %v", prompt, quoted, err)
				}
				if string(out) != prompt {
					t.Errorf("round-trip = %q, want %q", out, prompt)
				}
			})
		}
	}
}

// TestClaudeSecretRunCommand_IsByteIdenticalToTheShippedBuilder is the
// regression guard for the refactor itself: introducing the Engine seam must
// not change one byte of what the Claude + tenant-secret path has been
// dispatching since #1674. If this fails, existing boxes changed behaviour.
func TestClaudeSecretRunCommand_IsByteIdenticalToTheShippedBuilder(t *testing.T) {
	for _, streamJSON := range []bool{false, true} {
		e, err := For(NameClaude, Options{Credential: SecretCredential{}})
		if err != nil {
			t.Fatalf("For(claude): %v", err)
		}
		got := e.RunCommand("do the thing", streamJSON, false, "")
		want := coderun.BuildClaudeRunCommand("do the thing", streamJSON)
		if got != want {
			t.Errorf("streamJSON=%v: engine seam changed the shipped command\n got: %s\nwant: %s",
				streamJSON, got, want)
		}
	}
}

// TestParseName_DefaultsAndRejections pins the vocabulary of --engine. An
// unknown value must name the valid ones rather than silently falling back to
// a default, which would run the wrong agent on someone's box.
func TestParseName(t *testing.T) {
	for _, in := range []string{"claude", "CLAUDE", " claude ", "Claude"} {
		got, err := ParseName(in)
		if err != nil || got != NameClaude {
			t.Errorf("ParseName(%q) = %q, %v; want claude, nil", in, got, err)
		}
	}
	for _, in := range []string{"pi", "PI", " pi "} {
		got, err := ParseName(in)
		if err != nil || got != NamePi {
			t.Errorf("ParseName(%q) = %q, %v; want pi, nil", in, got, err)
		}
	}
	// #2273: codex is now a real, accepted engine — parallel to claude and pi,
	// not the rejected value docs/product/agent-router.md's P1 list named.
	for _, in := range []string{"codex", "CODEX", " codex "} {
		got, err := ParseName(in)
		if err != nil || got != NameCodex {
			t.Errorf("ParseName(%q) = %q, %v; want codex, nil", in, got, err)
		}
	}
	for _, in := range []string{"", "codexx", "cluade", "claude-code"} {
		_, err := ParseName(in)
		if err == nil {
			t.Errorf("ParseName(%q) should be an error, not a silent default", in)
		}
		if err != nil && !strings.Contains(err.Error(), "claude") {
			t.Errorf("ParseName(%q) error should list the valid engines, got: %v", in, err)
		}
	}
}

func TestParseCredentialSourceKind(t *testing.T) {
	for _, in := range []string{"secret", "SECRET", " secret "} {
		got, err := ParseCredentialKind(in)
		if err != nil || got != KindSecret {
			t.Errorf("ParseCredentialKind(%q) = %q, %v; want secret", in, got, err)
		}
	}
	for _, in := range []string{"gateway", "GATEWAY"} {
		got, err := ParseCredentialKind(in)
		if err != nil || got != KindGateway {
			t.Errorf("ParseCredentialKind(%q) = %q, %v; want gateway", in, got, err)
		}
	}
	for _, in := range []string{"", "token", "oauth"} {
		if _, err := ParseCredentialKind(in); err == nil {
			t.Errorf("ParseCredentialKind(%q) should be an error", in)
		}
	}
}

// TestPreflight pins which install-time check each credential source demands.
// The cmd layer switches on this, so getting it wrong means install validates
// the wrong thing (or nothing).
func TestPreflight(t *testing.T) {
	if got := (SecretCredential{Name: "X"}).Preflight(); got != PreflightSecretMetadata {
		t.Errorf("secret source Preflight = %v, want PreflightSecretMetadata", got)
	}
	if got := (GatewayCredential{Provider: "kafeido"}).Preflight(); got != PreflightGatewayDryRun {
		t.Errorf("gateway source Preflight = %v, want PreflightGatewayDryRun", got)
	}
}

// TestGatewayEnvPath pins the 0600 file each engine's run sources, because the
// CLI writes that exact path over SSH before process_start — a mismatch is a
// run with no credential at all.
func TestGatewayEnvPath(t *testing.T) {
	tests := []struct {
		engine Name
		want   string
	}{
		{NamePi, "$HOME/.pi/gateway.env"},
		{NameClaude, "$HOME/.claude/gateway.env"},
		{NameCodex, "$HOME/.codex/gateway.env"},
	}
	for _, tc := range tests {
		e, err := For(tc.engine, Options{Credential: GatewayCredential{Provider: "kafeido"}})
		if err != nil {
			t.Fatalf("For(%q): %v", tc.engine, err)
		}
		if got := e.GatewayEnvPath(); got != tc.want {
			t.Errorf("%s GatewayEnvPath = %q, want %q", tc.engine, got, tc.want)
		}
	}
}

// TestInstallScript_PiIsVersionPinnedAndNonInteractive is the gap-2 decision
// made testable: pi's own install.sh takes no version argument and needs a
// TTY, so install goes through npm with an explicit version. The install runs
// over `ssh` with no TTY, so anything interactive here is a hang on a box.
func TestInstallScript_PiIsVersionPinnedAndNonInteractive(t *testing.T) {
	e, err := For(NamePi, Options{Credential: GatewayCredential{Provider: "kafeido"}})
	if err != nil {
		t.Fatalf("For(pi): %v", err)
	}
	script := e.InstallScript(InstallOptions{Version: "0.87.1", ModelsJSON: `{"providers":{}}`})

	for _, want := range []string{
		"@earendil-works/pi-coding-agent@0.87.1", // the pin itself
		"--ignore-scripts",                       // pi.md's documented npm line
		"npm config set prefix",                  // user-level, no sudo
		"$HOME/.local",
		"umask 077",       // before the write, not chmod after
		"$HOME/.pi/agent", // the config dir docs/configuration.md pins
		"models.json",
		"22.19.0", // the Node floor npm would otherwise fail on obscurely
	} {
		if !strings.Contains(script, want) {
			t.Errorf("pi install script is missing %q:\n%s", want, script)
		}
	}
	for _, banned := range []string{
		"pi.dev/install.sh", // TTY-bound and unpinnable — gap 2
		"sudo",              // user-level install, same as the claude path
		"/dev/tty",
	} {
		if strings.Contains(script, banned) {
			t.Errorf("pi install script must not contain %q:\n%s", banned, script)
		}
	}
	// An unpinned install would make TestPiModelsJSON's fixture meaningless.
	if strings.Contains(script, "pi-coding-agent\n") || strings.Contains(script, "pi-coding-agent ") {
		t.Errorf("pi install script installs an unpinned version:\n%s", script)
	}
}

// TestVerifyScript_Pi covers the AC's verification step: `pi -p "print the
// current working directory" --mode json`, run on a short-lived token.
func TestVerifyScript_Pi(t *testing.T) {
	e, err := For(NamePi, Options{Credential: GatewayCredential{Provider: "kafeido"}})
	if err != nil {
		t.Fatalf("For(pi): %v", err)
	}
	script := e.VerifyScript()
	for _, want := range []string{
		"--version",
		"print the current working directory",
		"--mode json",
		"$HOME/.pi/gateway.env",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("pi verify script is missing %q:\n%s", want, script)
		}
	}
	// Same rule as the Claude path: presence, never a value. A verify script
	// that echoed the token would put it in the operator's scrollback.
	for _, banned := range []string{
		"$CONTAINARIUM_GATEWAY_TOKEN\"",
		"echo $CONTAINARIUM_GATEWAY_TOKEN",
		"cat \"$HOME/.pi/gateway.env\"",
	} {
		if strings.Contains(script, banned) {
			t.Errorf("pi verify script must never expand the token (%q):\n%s", banned, script)
		}
	}
}

// TestInstallScript_CodexIsNpmInstalledWithScriptsEnabled is the #2273 gap
// made testable: codex's npm package (@openai/codex) needs its postinstall
// script to fetch the platform-specific binary — the OPPOSITE of pi, whose
// --ignore-scripts this must NOT copy, or the install would leave a binary
// that cannot run.
func TestInstallScript_CodexIsNpmInstalledWithScriptsEnabled(t *testing.T) {
	e, err := For(NameCodex, Options{Credential: SecretCredential{Name: "CODEX_API_KEY"}})
	if err != nil {
		t.Fatalf("For(codex): %v", err)
	}
	script := e.InstallScript(InstallOptions{Version: "0.50.0"})

	for _, want := range []string{
		"@openai/codex@0.50.0", // the pin itself
		"npm config set prefix",
		"$HOME/.local",
		"16", // the Node floor (lower than pi's)
	} {
		if !strings.Contains(script, want) {
			t.Errorf("codex install script is missing %q:\n%s", want, script)
		}
	}
	for _, banned := range []string{
		"--ignore-scripts", // pi's flag — codex's postinstall MUST run
		"sudo",
		"/dev/tty",
	} {
		if strings.Contains(script, banned) {
			t.Errorf("codex install script must not contain %q:\n%s", banned, script)
		}
	}
}

// TestInstallScript_CodexNoVersionOmitsThePin mirrors Claude's own installer
// behaviour (empty Version = "whatever the installer considers current"),
// not pi's hard pin — codex has no models.json-shaped fixture this repo owns
// that an unpinned install could silently invalidate.
func TestInstallScript_CodexNoVersionOmitsThePin(t *testing.T) {
	e, err := For(NameCodex, Options{Credential: SecretCredential{Name: "CODEX_API_KEY"}})
	if err != nil {
		t.Fatalf("For(codex): %v", err)
	}
	script := e.InstallScript(InstallOptions{})
	if strings.Contains(script, "@openai/codex@") {
		t.Errorf("an empty Version must not pin a version:\n%s", script)
	}
	if !strings.Contains(script, "npm install -g --no-fund --no-audit '@openai/codex'") {
		t.Errorf("unpinned install should install the bare package name:\n%s", script)
	}
}

// TestVerifyScript_Codex covers the #2273 AC's verification step: `codex
// exec --json "print the current working directory"`, run on whatever
// credential the box now has, never expanding it.
func TestVerifyScript_Codex(t *testing.T) {
	e, err := For(NameCodex, Options{Credential: GatewayCredential{Provider: "openai"}})
	if err != nil {
		t.Fatalf("For(codex): %v", err)
	}
	script := e.VerifyScript()
	for _, want := range []string{
		"--version",
		"codex exec --json",
		"print the current working directory",
		"$HOME/.codex/gateway.env",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("codex verify script is missing %q:\n%s", want, script)
		}
	}
	for _, banned := range []string{
		"$CONTAINARIUM_GATEWAY_TOKEN\"",
		"echo $CONTAINARIUM_GATEWAY_TOKEN",
		"cat \"$HOME/.codex/gateway.env\"",
	} {
		if strings.Contains(script, banned) {
			t.Errorf("codex verify script must never expand the token (%q):\n%s", banned, script)
		}
	}
}

// TestVerifyScript_Codex_SecretReportsSourcesByNameOnly pins the secret-path
// branch: the delivery files and codex's own auth.json are reported by NAME,
// matching the "report credential source by name only, never a value" rule
// #2273 carries over from the Claude path (#2030).
func TestVerifyScript_Codex_SecretReportsSourcesByNameOnly(t *testing.T) {
	e, err := For(NameCodex, Options{Credential: SecretCredential{Name: "CODEX_API_KEY"}})
	if err != nil {
		t.Fatalf("For(codex): %v", err)
	}
	script := e.VerifyScript()
	for _, want := range []string{"secrets.env", "/run/secrets", "auth.json", "codex login"} {
		if !strings.Contains(script, want) {
			t.Errorf("codex verify script (secret) missing %q:\n%s", want, script)
		}
	}
	if strings.Contains(script, "$CODEX_API_KEY") || strings.Contains(script, "$OPENAI_API_KEY") {
		t.Errorf("codex verify script must never expand a key value:\n%s", script)
	}
}
