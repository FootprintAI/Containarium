package cmd

import (
	"github.com/footprintai/containarium/internal/coderun"
	"os/exec"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestShellQuoteSingle_RoundTripsThroughARealShell(t *testing.T) {
	cases := []string{
		"plain text",
		"it's got an apostrophe",
		"multiple ''' quotes '' in a row",
		"",
		"$(rm -rf /) and `also this`",
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			quoted := coderun.ShellQuoteSingle(in)
			// #nosec G204 -- fixed "sh -c" with a single literal-quoted
			// argument built by the function under test; this is the
			// injection check itself, not a caller-reachable path.
			out, err := exec.Command("/bin/sh", "-c", "printf '%s' "+quoted).Output()
			if err != nil {
				t.Fatalf("shell rejected %q (quoted as %q): %v", in, quoted, err)
			}
			if string(out) != in {
				t.Errorf("round-trip = %q, want %q (quoted form was %q)", out, in, quoted)
			}
		})
	}
}

func TestShellQuoteSingle_NeverEscapesOutOfTheQuotedString(t *testing.T) {
	// The classic injection shape: a naive quoter that doesn't handle
	// embedded quotes lets this argument terminate early and run a second
	// command.
	malicious := "'; touch /tmp/pwned; echo '"
	quoted := coderun.ShellQuoteSingle(malicious)
	// #nosec G204 -- see above.
	out, err := exec.Command("/bin/sh", "-c", "echo "+quoted).Output()
	if err != nil {
		t.Fatalf("shell rejected quoted input: %v", err)
	}
	got := strings.TrimSuffix(string(out), "\n")
	if got != malicious {
		t.Errorf("got %q, want the argument echoed back verbatim (%q) — the shell ran something other than plain echo", got, malicious)
	}
}

func TestBuildClaudeRunCommand(t *testing.T) {
	cmd := coderun.BuildClaudeRunCommand("fix the bug", false)
	for _, want := range []string{"secrets.env", "~/.local/bin/claude", "-p", coderun.ShellQuoteSingle("fix the bug")} {
		if !strings.Contains(cmd, want) {
			t.Errorf("command missing %q:\n%s", want, cmd)
		}
	}
	if strings.Contains(cmd, "stream-json") {
		t.Errorf("combined-mode command should not request stream-json:\n%s", cmd)
	}
}

func TestBuildClaudeRunCommand_StreamJSON(t *testing.T) {
	cmd := coderun.BuildClaudeRunCommand("fix the bug", true)
	if !strings.Contains(cmd, "--output-format stream-json") {
		t.Errorf("expected --output-format stream-json in:\n%s", cmd)
	}
}

func TestRunOutcomeLine(t *testing.T) {
	listing := "Found 2 process(es):\n\n" +
		"🟢 code  (pid 111, running)\n" +
		"   Command:    sleep 5\n" +
		"   Started at: 2026-09-02T12:00:00Z\n" +
		"   Log path:   /tmp/agent-box/code.log\n\n" +
		"⚪ old-task  (pid 222, exited)\n" +
		"   Command:    true\n" +
		"   Exit code:  0\n" +
		"   Log path:   /tmp/agent-box/old-task.log\n\n"

	line, running := coderun.RunOutcomeLine(listing, "code")
	if !running {
		t.Errorf("code should be reported running, line=%q", line)
	}
	if !strings.Contains(line, "code") || !strings.Contains(line, "running") {
		t.Errorf("line = %q", line)
	}

	line, running = coderun.RunOutcomeLine(listing, "old-task")
	if running {
		t.Errorf("old-task should not be reported running, line=%q", line)
	}
	if !strings.Contains(line, "old-task") {
		t.Errorf("line = %q", line)
	}

	line, running = coderun.RunOutcomeLine(listing, "does-not-exist")
	if running || line != "" {
		t.Errorf("unknown name should report not-running/empty line, got running=%v line=%q", running, line)
	}
}

func TestLogPathFromListing(t *testing.T) {
	listing := "Found 1 process(es):\n\n" +
		"🟢 code  (pid 111, running)\n" +
		"   Command:    claude -p hi\n" +
		"   Started at: 2026-09-02T12:00:00Z\n" +
		"   Log path:   /tmp/agent-box/code.log\n\n"

	got, err := coderun.LogPathFromListing(listing, "code")
	if err != nil {
		t.Fatalf("logPathFromListing: %v", err)
	}
	if got != "/tmp/agent-box/code.log" {
		t.Errorf("got %q, want /tmp/agent-box/code.log", got)
	}

	if _, err := coderun.LogPathFromListing(listing, "nope"); err == nil {
		t.Error("expected an error for a name not in the listing")
	}
}

func TestFindSecret(t *testing.T) {
	secrets := []*pb.SecretMetadata{
		{Name: "OPENAI_API_KEY"},
		{Name: claudeOAuthTokenSecretName, DeliveryMode: pb.SecretDelivery_SECRET_DELIVERY_COMPOSE},
	}
	got, found := findSecret(secrets, claudeOAuthTokenSecretName)
	if !found {
		t.Fatal("findSecret: found = false, want true")
	}
	if got.Name != claudeOAuthTokenSecretName {
		t.Errorf("findSecret returned %+v", got)
	}

	if _, found := findSecret(secrets, "NOT_PRESENT"); found {
		t.Error("findSecret: found = true for an absent name")
	}
}

// TestCheckClaudeCredential_MissingNamesSecretsSet is the #1673 AC:
// "Installing with no credential set fails naming the `secrets set`
// command, rather than hanging on a login prompt."
func TestCheckClaudeCredential_MissingNamesSecretsSet(t *testing.T) {
	err := checkClaudeCredential(nil, "mybox")
	if err == nil {
		t.Fatal("expected an error when no CLAUDE_CODE_OAUTH_TOKEN secret exists")
	}
	if !strings.Contains(err.Error(), "secrets set mybox "+claudeOAuthTokenSecretName) {
		t.Errorf("error does not name the secrets set command: %v", err)
	}
	if !strings.Contains(err.Error(), "claude setup-token") {
		t.Errorf("error does not mention how to mint the token: %v", err)
	}
}

// TestCheckClaudeCredential_EnvDeliveryIsRejected covers the footgun found
// in docs/integrations/pi.md: the default "env" delivery is stamped on the
// LXC's container-start environment, which an SSH shell session (where
// claude actually runs) never inherits. Accepting it here would let the
// AC's "fails naming the command" promise slip into a much more confusing
// failure later (a hang on claude's own login prompt).
func TestCheckClaudeCredential_EnvDeliveryIsRejected(t *testing.T) {
	cases := []pb.SecretDelivery{
		pb.SecretDelivery_SECRET_DELIVERY_ENV,
		pb.SecretDelivery_SECRET_DELIVERY_UNSPECIFIED,
	}
	for _, mode := range cases {
		t.Run(mode.String(), func(t *testing.T) {
			secrets := []*pb.SecretMetadata{{Name: claudeOAuthTokenSecretName, DeliveryMode: mode}}
			err := checkClaudeCredential(secrets, "mybox")
			if err == nil {
				t.Fatalf("expected an error for delivery mode %v", mode)
			}
			if !strings.Contains(err.Error(), "--delivery compose") {
				t.Errorf("error does not suggest --delivery compose: %v", err)
			}
		})
	}
}

func TestCheckClaudeCredential_ComposeOrFileDeliveryPasses(t *testing.T) {
	cases := []pb.SecretDelivery{
		pb.SecretDelivery_SECRET_DELIVERY_COMPOSE,
		pb.SecretDelivery_SECRET_DELIVERY_FILE,
	}
	for _, mode := range cases {
		t.Run(mode.String(), func(t *testing.T) {
			secrets := []*pb.SecretMetadata{{Name: claudeOAuthTokenSecretName, DeliveryMode: mode}}
			if err := checkClaudeCredential(secrets, "mybox"); err != nil {
				t.Errorf("delivery mode %v should pass, got %v", mode, err)
			}
		})
	}
}

// TestClaudeVerifyScript_AssertsAnthropicVarsUnset is the #1673 AC: "The
// install asserts ANTHROPIC_API_KEY and ANTHROPIC_AUTH_TOKEN are unset on
// the box — both outrank CLAUDE_CODE_OAUTH_TOKEN in Claude Code's auth
// precedence and would silently win."
func TestClaudeVerifyScript_AssertsAnthropicVarsUnset(t *testing.T) {
	script := claudeVerifyScript()
	for _, want := range []string{"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "exit"} {
		if !strings.Contains(script, want) {
			t.Errorf("verify script missing %q:\n%s", want, script)
		}
	}
}

func TestClaudeVerifyScript_SourcesComposeAndFileDelivery(t *testing.T) {
	script := claudeVerifyScript()
	if !strings.Contains(script, "/run/containarium/secrets.env") {
		t.Errorf("verify script does not source the compose secrets file:\n%s", script)
	}
	if !strings.Contains(script, "/run/secrets/"+claudeOAuthTokenSecretName) {
		t.Errorf("verify script does not fall back to file delivery:\n%s", script)
	}
}

// TestClaudeVerifyScript_NoBareMode is the #1673 AC: "--bare is not used
// anywhere on this path; bare mode does not read CLAUDE_CODE_OAUTH_TOKEN."
func TestClaudeVerifyScript_NoBareMode(t *testing.T) {
	if strings.Contains(claudeVerifyScript(), "--bare") {
		t.Error("verify script must never pass --bare")
	}
	if strings.Contains(claudeInstallScript, "--bare") {
		t.Error("install script must never pass --bare")
	}
}

// TestClaudeVerifyScript_RunsClaudeNonInteractively covers "claude -p ...
// on the box returns a non-empty response with no interactive prompt and
// no TTY attached" — the -p flag and the absence of any -t/--tty flag
// anywhere in this codepath (ssh args are asserted separately) is the
// mechanism; this pins the -p flag stays on the script side.
func TestClaudeVerifyScript_RunsClaudeNonInteractively(t *testing.T) {
	script := claudeVerifyScript()
	if !strings.Contains(script, "claude -p ") {
		t.Errorf("verify script must invoke claude with -p (print, no interactive prompt):\n%s", script)
	}
}
