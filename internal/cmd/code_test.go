package cmd

import (
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

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
