package cmd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/coderun/engine"
	"github.com/footprintai/containarium/internal/connectcore"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// `code install --engine` tests (#1727).
//
// These drive runCodeInstall through the same sshExec / resolveCodeTargetFn seams
// #2030's tests use, plus two new ones (mintGatewayTokenFn, listSecretsFn), so no
// box, daemon, or ssh binary is involved.

// installEnv holds the flag state and fakes for one install run.
type installEnv struct {
	scripts  []string
	mintReqs []*pb.MintGatewayTokenRequest
	stdout   string
	stderr   string
}

// mintResult is what the fake mint RPC returns.
type mintResult struct {
	resp *pb.MintGatewayTokenResponse
	err  error
}

// runInstallEngine drives runCodeInstall with the #1727 flags set.
func runInstallEngine(t *testing.T, box string, flags map[string]string,
	mint mintResult, secrets []*pb.SecretMetadata, secretsErr error) (*installEnv, error) {
	t.Helper()

	origSSH, origResolve := sshExec, resolveCodeTargetFn
	origMint, origSecrets := mintGatewayTokenFn, listSecretsFn
	origFlags := []*string{
		&codeEngine, &codeCredential, &codeProvider, &codeSecretName,
		&codeProviderBaseURL, &codeModel, &codePiVersion, &codeCodexVersion,
		&codeBootstrapURL, &codeRelease, &codeClaudeCodeVersion,
	}
	saved := make([]string, len(origFlags))
	for i, p := range origFlags {
		saved[i] = *p
	}
	origServer := serverAddr
	t.Cleanup(func() {
		sshExec, resolveCodeTargetFn = origSSH, origResolve
		mintGatewayTokenFn, listSecretsFn = origMint, origSecrets
		for i, p := range origFlags {
			*p = saved[i]
		}
		serverAddr = origServer
	})

	// Defaults, exactly as cobra would leave them when no flag is passed.
	codeEngine = string(engine.DefaultName)
	codeCredential = string(engine.DefaultKind)
	codeProvider, codeSecretName, codeProviderBaseURL, codeModel = "", "", "", ""
	codePiVersion = engine.PiVersion
	codeCodexVersion = ""
	codeBootstrapURL, codeRelease, codeClaudeCodeVersion = "", "", ""
	serverAddr = "daemon.example.test:9090"

	for k, v := range flags {
		switch k {
		case "engine":
			codeEngine = v
		case "credential":
			codeCredential = v
		case "provider":
			codeProvider = v
		case "secret-name":
			codeSecretName = v
		case "provider-base-url":
			codeProviderBaseURL = v
		case "model":
			codeModel = v
		case "pi-version":
			codePiVersion = v
		case "codex-version":
			codeCodexVersion = v
		case "release":
			codeRelease = v
		case "claude-code-version":
			codeClaudeCodeVersion = v
		case "server":
			serverAddr = v
		default:
			t.Fatalf("runInstallEngine: unknown flag %q", k)
		}
	}

	env := &installEnv{}
	resolveCodeTargetFn = func(context.Context, string, io.Writer) (connectcore.Target, string, error) {
		return connectcore.Target{User: "alice", Host: "box.example.test", Port: 22}, "/dev/null", nil
	}
	sshExec = func(_ io.Writer, args []string) (string, error) {
		script := ""
		if len(args) > 0 {
			script = args[len(args)-1]
		}
		env.scripts = append(env.scripts, script)
		return "1.2.3\ncredential sources present:\n  (none)", nil
	}
	mintGatewayTokenFn = func(_ context.Context, req *pb.MintGatewayTokenRequest) (*pb.MintGatewayTokenResponse, error) {
		env.mintReqs = append(env.mintReqs, req)
		return mint.resp, mint.err
	}
	listSecretsFn = func(string) ([]*pb.SecretMetadata, error) { return secrets, secretsErr }

	cmd := &cobra.Command{}
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetContext(context.Background())
	err := runCodeInstall(cmd, []string{box})
	env.stdout, env.stderr = out.String(), errBuf.String()
	return env, err
}

func (e *installEnv) allScripts() string { return strings.Join(e.scripts, "\n") }

func okMint() mintResult {
	return mintResult{resp: &pb.MintGatewayTokenResponse{
		Token:     "gw-token-xyz",
		BaseUrl:   "http://10.0.0.1:8866/v1/model/kafeido",
		KeyOwner:  "org:acme",
		TokenId:   "jti-1",
		ExpiresAt: timestamppb.Now(),
	}}
}

// ===========================================================================
// The regression guard: --engine defaults to claude.
// ===========================================================================

// TestCodeInstall_EngineDefaultsToClaude is #1727's headline compatibility
// requirement: "--engine defaults to claude: no behaviour change for existing
// users."
//
// It asserts the DEFAULT install still does exactly what it did before #1727 —
// Anthropic's installer verbatim, Claude's verify script — and that none of the
// new machinery activates: no mint RPC, no secrets read, no pi, no models.json.
func TestCodeInstall_EngineDefaultsToClaude(t *testing.T) {
	env, err := runInstallEngine(t, "alice", nil, mintResult{}, nil, nil)
	if err != nil {
		t.Fatalf("default install failed: %v", err)
	}
	scripts := env.allScripts()

	// Claude Code's own installer, unchanged.
	if !strings.Contains(scripts, "curl -fsSL https://claude.ai/install.sh | bash") {
		t.Errorf("the default install no longer runs Anthropic's installer verbatim:\n%s", scripts)
	}
	// Claude's verify script, unchanged.
	for _, want := range []string{"$HOME/.local/bin/claude", "--version", ".credentials.json", "CLAUDE_CODE_USE_"} {
		if !strings.Contains(scripts, want) {
			t.Errorf("the default install's verify step lost %q:\n%s", want, scripts)
		}
	}
	// None of pi's machinery.
	for _, banned := range []string{"pi-coding-agent", "models.json", ".pi/", "npm install"} {
		if strings.Contains(scripts, banned) {
			t.Errorf("the DEFAULT install (no --engine) ran pi machinery %q:\n%s", banned, scripts)
		}
	}
	// No gateway token was minted, and no secret was read: the default
	// credential source is the shipped one, whose preflight with no
	// --secret-name checks nothing (see #2036).
	if len(env.mintReqs) != 0 {
		t.Errorf("the default install minted %d gateway token(s); it must mint none", len(env.mintReqs))
	}
	// And the record it leaves says claude/secret.
	if !strings.Contains(scripts, `"engine": "claude"`) || !strings.Contains(scripts, `"credential": "secret"`) {
		t.Errorf("code.json should record engine=claude credential=secret:\n%s", scripts)
	}
	// The sign-in help #2036 added is still what the user is told.
	if !strings.Contains(env.stdout, "not signed in") {
		t.Errorf("the default install lost #2036's sign-in help:\n%s", env.stdout)
	}
}

// TestCodeInstall_DefaultNeedsNoServer pins the other half of #2036 that #1727
// must not undo: the default install reaches the box over SSH only, so it must
// still work with no --server. #1727 adds daemon calls, and they must stay on
// the paths that asked for them.
func TestCodeInstall_DefaultNeedsNoServer(t *testing.T) {
	env, err := runInstallEngine(t, "alice", map[string]string{"server": ""}, mintResult{}, nil, nil)
	if err != nil {
		t.Fatalf("default install must not require --server: %v", err)
	}
	if len(env.scripts) == 0 {
		t.Fatal("no remote command ran")
	}
}

// TestCodeInstall_DefaultEngineConstantIsClaude guards the constant itself, so
// flipping the default becomes a deliberate, visible test change rather than a
// one-word edit that silently re-points every existing user's boxes.
func TestCodeInstall_DefaultEngineConstantIsClaude(t *testing.T) {
	if engine.DefaultName != engine.NameClaude {
		t.Errorf("engine.DefaultName = %q, want claude — changing this breaks every box installed before #1727", engine.DefaultName)
	}
	if engine.DefaultKind != engine.KindSecret {
		t.Errorf("engine.DefaultKind = %q, want secret", engine.DefaultKind)
	}
	// And the flag's registered default must match the constant, since that is
	// what users actually get.
	f := codeInstallCmd.Flags().Lookup("engine")
	if f == nil {
		t.Fatal("--engine is not registered on `code install`")
	}
	if f.DefValue != string(engine.NameClaude) {
		t.Errorf("--engine default = %q, want claude", f.DefValue)
	}
}

// ===========================================================================
// --engine pi
// ===========================================================================

// TestCodeInstall_PiGateway covers the AC's main path: install pi on the
// gateway credential, dry-run first, render models.json, record code.json, and
// verify on a short-lived token.
func TestCodeInstall_PiGateway(t *testing.T) {
	env, err := runInstallEngine(t, "alice", map[string]string{
		"engine": "pi", "credential": "gateway", "provider": "kafeido", "model": "kafeido-coder",
	}, okMint(), nil, nil)
	if err != nil {
		t.Fatalf("install: %v\nstderr: %s", err, env.stderr)
	}
	scripts := env.allScripts()

	// pi, pinned, via npm and not the TTY-bound installer.
	if !strings.Contains(scripts, "@earendil-works/pi-coding-agent@"+engine.PiVersion) {
		t.Errorf("pi was not installed at the pinned version:\n%s", scripts)
	}
	if strings.Contains(scripts, "pi.dev/install.sh") {
		t.Errorf("the TTY-bound native installer must not be used:\n%s", scripts)
	}
	// models.json, at pi's documented path, pointing at the gateway with the
	// /v1 the OpenAI SDK needs.
	for _, want := range []string{
		"$HOME/.pi/agent/models.json",
		`"api": "openai-completions"`,
		"/v1/model/kafeido/v1",
		"$CONTAINARIUM_GATEWAY_TOKEN",
	} {
		if !strings.Contains(scripts, want) {
			t.Errorf("install scripts missing %q:\n%s", want, scripts)
		}
	}
	// code.json, recording every choice so `code run` never re-asks.
	for _, want := range []string{`"engine": "pi"`, `"credential": "gateway"`, `"provider": "kafeido"`, `"model": "kafeido-coder"`} {
		if !strings.Contains(scripts, want) {
			t.Errorf("code.json missing %q:\n%s", want, scripts)
		}
	}
	// Two mints: the dry run, then the short-lived verify token.
	if len(env.mintReqs) != 2 {
		t.Fatalf("expected 2 mint calls (dry run + verify token), got %d", len(env.mintReqs))
	}
	if !env.mintReqs[0].GetDryRun() {
		t.Error("the FIRST mint must be a dry run — it validates before anything is installed")
	}
	if env.mintReqs[1].GetDryRun() {
		t.Error("the verify mint must issue a real token")
	}
	if got := env.mintReqs[1].GetTtl().AsDuration(); got != codeVerifyTokenTTL {
		t.Errorf("verify token TTL = %v, want %v (short-lived: it only proves reachability once)", got, codeVerifyTokenTTL)
	}
	if got := env.mintReqs[1].GetAllowedModels(); len(got) != 1 || got[0] != "kafeido-coder" {
		t.Errorf("verify token allowed_models = %v, want [kafeido-coder]", got)
	}
	// gateway.env, 0600, umask before the write.
	if !strings.Contains(scripts, "$HOME/.pi/gateway.env") {
		t.Errorf("gateway.env was not written:\n%s", scripts)
	}
	if !strings.Contains(scripts, "umask 077") {
		t.Errorf("gateway.env must be written under umask 077, not chmod-after:\n%s", scripts)
	}
	// And the verification the AC names.
	if !strings.Contains(scripts, "print the current working directory") || !strings.Contains(scripts, "--mode json") {
		t.Errorf("pi verification step missing:\n%s", scripts)
	}
}

// TestCodeInstall_PiGatewayNoKeyNamesTheFix is the AC: "Install with --credential
// gateway and no key for the owner fails naming the fix (dry-run
// FailedPrecondition)."
func TestCodeInstall_PiGatewayNoKeyNamesTheFix(t *testing.T) {
	env, err := runInstallEngine(t, "alice", map[string]string{
		"engine": "pi", "credential": "gateway", "provider": "kafeido", "model": "kafeido-coder",
	}, mintResult{err: status.Error(codes.FailedPrecondition, "no key registered for key owner org:acme")}, nil, nil)

	if err == nil {
		t.Fatal("install succeeded with no inference key registered")
	}
	msg := err.Error()
	// It has to name the fix, not just relay a gRPC status.
	for _, want := range []string{"Settings", "Inference key", "gateway key set", "kafeido"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error should name the fix (missing %q): %v", want, msg)
		}
	}
	// And nothing may have been installed: the dry run is the FIRST thing.
	if len(env.scripts) != 0 {
		t.Errorf("a failed preflight still ran %d remote script(s):\n%s", len(env.scripts), env.allScripts())
	}
}

// TestCodeInstall_SecretEnvDeliveryNamesTheFix is the AC's other failure path:
// "with --credential secret and an env-delivered secret fails the same way".
//
// The reason is the one docs/integrations/pi.md documents: env delivery stamps
// the variable on the LXC, which an SSH shell session — where these engines run —
// does not inherit.
func TestCodeInstall_SecretEnvDeliveryNamesTheFix(t *testing.T) {
	secrets := []*pb.SecretMetadata{
		{Name: "ANTHROPIC_API_KEY", DeliveryMode: pb.SecretDelivery_SECRET_DELIVERY_ENV},
	}
	env, err := runInstallEngine(t, "alice", map[string]string{
		"engine": "pi", "credential": "secret", "secret-name": "ANTHROPIC_API_KEY",
		"model": "claude-sonnet-5", "provider-base-url": "https://api.anthropic.com",
	}, mintResult{}, secrets, nil)

	if err == nil {
		t.Fatal("install succeeded with an env-delivered secret")
	}
	msg := err.Error()
	for _, want := range []string{"ANTHROPIC_API_KEY", "--delivery compose", "secrets refresh", "SSH shell session"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error should name the fix (missing %q): %v", want, msg)
		}
	}
	if len(env.scripts) != 0 {
		t.Errorf("a failed preflight still ran remote scripts:\n%s", env.allScripts())
	}
}

// TestCodeInstall_PiSecretModelsJSONReferencesTheDeliveredSecret: on the secret
// path the run sources /run/containarium/secrets.env, which carries the variable
// --secret-name named. models.json's apiKey has to reference THAT variable.
//
// Referencing $CONTAINARIUM_GATEWAY_TOKEN here — which only the gateway path ever
// writes — leaves pi unable to resolve any credential at all, and the symptom is
// an auth failure at the first model call rather than anything pointing at the
// config.
func TestCodeInstall_PiSecretModelsJSONReferencesTheDeliveredSecret(t *testing.T) {
	secrets := []*pb.SecretMetadata{
		{Name: "OPENAI_API_KEY", DeliveryMode: pb.SecretDelivery_SECRET_DELIVERY_COMPOSE},
	}
	env, err := runInstallEngine(t, "alice", map[string]string{
		"engine": "pi", "credential": "secret", "secret-name": "OPENAI_API_KEY",
		"model": "gpt-5", "provider-base-url": "https://api.openai.com/v1",
	}, mintResult{}, secrets, nil)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	scripts := env.allScripts()

	if !strings.Contains(scripts, `"apiKey": "$OPENAI_API_KEY"`) {
		t.Errorf("models.json should reference $OPENAI_API_KEY (the delivered secret):\n%s", scripts)
	}
	if strings.Contains(scripts, "CONTAINARIUM_GATEWAY_TOKEN") {
		t.Errorf("the secret path must not reference the gateway token variable — nothing writes it here:\n%s", scripts)
	}
	// And the run command sources the file that variable actually arrives in.
	piSecret := mustEngine(t, engine.NamePi, engine.SecretCredential{Name: "OPENAI_API_KEY"})
	if !strings.Contains(piSecret.RunCommand("hi", false, false, ""), "/run/containarium/secrets.env") {
		t.Error("the pi secret run command should source /run/containarium/secrets.env")
	}
}

func TestCodeInstall_SecretComposeDeliveryIsAccepted(t *testing.T) {
	for _, mode := range []pb.SecretDelivery{
		pb.SecretDelivery_SECRET_DELIVERY_COMPOSE,
		pb.SecretDelivery_SECRET_DELIVERY_FILE,
	} {
		t.Run(mode.String(), func(t *testing.T) {
			secrets := []*pb.SecretMetadata{{Name: "OPENAI_API_KEY", DeliveryMode: mode}}
			_, err := runInstallEngine(t, "alice", map[string]string{
				"engine": "pi", "credential": "secret", "secret-name": "OPENAI_API_KEY",
				"model": "gpt-5", "provider-base-url": "https://api.openai.com/v1",
			}, mintResult{}, secrets, nil)
			if err != nil {
				t.Errorf("%s delivery should be accepted: %v", mode, err)
			}
		})
	}
}

func TestCodeInstall_SecretMissingNamesTheFix(t *testing.T) {
	_, err := runInstallEngine(t, "alice", map[string]string{
		"engine": "pi", "credential": "secret", "secret-name": "OPENAI_API_KEY",
		"model": "gpt-5", "provider-base-url": "https://api.openai.com/v1",
	}, mintResult{}, nil, nil)
	if err == nil {
		t.Fatal("install succeeded with no such secret set")
	}
	if !strings.Contains(err.Error(), "secrets set") {
		t.Errorf("error should name `secrets set`: %v", err)
	}
}

// ===========================================================================
// Flag validation
// ===========================================================================

func TestCodeInstall_FlagValidation(t *testing.T) {
	tests := []struct {
		name  string
		flags map[string]string
		want  string
	}{
		{
			name:  "gateway without a provider",
			flags: map[string]string{"engine": "pi", "credential": "gateway", "model": "m"},
			want:  "--provider",
		},
		{
			name:  "pi without a model",
			flags: map[string]string{"engine": "pi", "credential": "gateway", "provider": "kafeido"},
			want:  "--model",
		},
		{
			// #2273: codex is now a real engine (see the dedicated codex
			// tests below) — "unknown" needs a genuinely invalid value.
			name:  "unknown engine",
			flags: map[string]string{"engine": "gronk"},
			want:  "gronk",
		},
		{
			name:  "unknown credential source",
			flags: map[string]string{"engine": "pi", "credential": "oauth", "model": "m"},
			want:  "oauth",
		},
		{
			name:  "unknown provider",
			flags: map[string]string{"engine": "pi", "credential": "gateway", "provider": "bedrock", "model": "m"},
			want:  "bedrock",
		},
		{
			name:  "secret-name with the gateway credential",
			flags: map[string]string{"engine": "pi", "credential": "gateway", "provider": "kafeido", "model": "m", "secret-name": "X"},
			want:  "--secret-name",
		},
		{
			name:  "provider with the secret credential",
			flags: map[string]string{"engine": "pi", "credential": "secret", "provider": "kafeido", "model": "m"},
			want:  "--provider",
		},
		{
			// pi on a tenant secret has no gateway to derive an endpoint from,
			// so the missing flag has to be named BEFORE the secrets RPC —
			// otherwise a lookup failure masks the real, local mistake.
			name:  "pi on a secret without an endpoint",
			flags: map[string]string{"engine": "pi", "credential": "secret", "secret-name": "OPENAI_API_KEY", "model": "m"},
			want:  "--provider-base-url",
		},
		{
			// models.json's apiKey is a "$VAR" reference, so there must be a
			// variable to name. Defaulting to the gateway's variable would point
			// pi at a value this path never writes.
			name:  "pi on a secret without a secret name",
			flags: map[string]string{"engine": "pi", "credential": "secret", "model": "m", "provider-base-url": "https://api.openai.com/v1"},
			want:  "--secret-name",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// A deliberately failing secrets RPC: a flag mistake must be reported
			// as itself, not masked by a lookup that should never have happened.
			secretsErr := errors.New("secrets RPC must not be reached for a flag error")
			env, err := runInstallEngine(t, "alice", tc.flags, okMint(), nil, secretsErr)
			if err == nil {
				t.Fatalf("expected a rejection for %v", tc.flags)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error should mention %q: %v", tc.want, err)
			}
			if strings.Contains(err.Error(), "must not be reached") {
				t.Errorf("a flag error was masked by a secrets RPC failure: %v", err)
			}
			if len(env.scripts) != 0 {
				t.Errorf("flags were rejected but %d remote script(s) still ran", len(env.scripts))
			}
		})
	}
}

// TestCodeInstall_GatewayEnvNeverLeaksTheTokenIntoAnArgument: the install path
// writes gateway.env over ssh, so the token IS in a script — but it must be
// single-quoted and reach the box as a heredoc-style redirect, never as an
// unquoted word a shell could re-split or a `ps` could show mid-pipeline.
func TestCodeInstall_GatewayTokenIsShellQuoted(t *testing.T) {
	mint := okMint()
	mint.resp.Token = "gw-token with spaces and 'quotes'"
	env, err := runInstallEngine(t, "alice", map[string]string{
		"engine": "pi", "credential": "gateway", "provider": "kafeido", "model": "kafeido-coder",
	}, mint, nil, nil)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	scripts := env.allScripts()
	// The raw token must never appear unquoted.
	if strings.Contains(scripts, "=gw-token with spaces") {
		t.Errorf("token was interpolated unquoted:\n%s", scripts)
	}
	// It must appear in its shell-quoted form.
	if !strings.Contains(scripts, `'gw-token with spaces and '\''quotes'\'''`) {
		t.Errorf("token is not shell-quoted:\n%s", scripts)
	}
}

// TestCodeInstall_ProviderBaseURLOverride: --provider-base-url replaces the base
// entirely, and no per-provider suffix is appended to an operator's complete URL.
func TestCodeInstall_ProviderBaseURLOverride(t *testing.T) {
	env, err := runInstallEngine(t, "alice", map[string]string{
		"engine": "pi", "credential": "gateway", "provider": "kafeido", "model": "m",
		"provider-base-url": "https://inference.example.test/v1",
	}, okMint(), nil, nil)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	scripts := env.allScripts()
	if !strings.Contains(scripts, "https://inference.example.test/v1") {
		t.Errorf("--provider-base-url not honoured:\n%s", scripts)
	}
	if strings.Contains(scripts, "/v1/model/kafeido/v1") {
		t.Errorf("the gateway base should have been replaced, not appended to:\n%s", scripts)
	}
}

// ===========================================================================
// --engine codex (#2273)
// ===========================================================================

// TestCodeInstall_CodexSecret covers the AC's main path: install codex on
// the secret credential, record code.json, and verify with `codex exec
// --json`. No daemon calls at all — codex's preflight is identical to
// Claude's and pi's secret path (metadata-only, and only when --secret-name
// is given).
func TestCodeInstall_CodexSecret(t *testing.T) {
	secrets := []*pb.SecretMetadata{
		{Name: "CODEX_API_KEY", DeliveryMode: pb.SecretDelivery_SECRET_DELIVERY_COMPOSE},
	}
	env, err := runInstallEngine(t, "alice", map[string]string{
		"engine": "codex", "credential": "secret", "secret-name": "CODEX_API_KEY",
	}, mintResult{}, secrets, nil)
	if err != nil {
		t.Fatalf("install: %v\nstderr: %s", err, env.stderr)
	}
	scripts := env.allScripts()

	// codex, via npm, with its postinstall script left enabled.
	if !strings.Contains(scripts, "@openai/codex") {
		t.Errorf("codex was not installed via npm:\n%s", scripts)
	}
	if strings.Contains(scripts, "--ignore-scripts") {
		t.Errorf("codex's install must not skip npm scripts (it needs the postinstall binary fetch):\n%s", scripts)
	}
	// No gateway token minted: this is the secret path.
	if len(env.mintReqs) != 0 {
		t.Errorf("the secret path minted %d gateway token(s); it must mint none", len(env.mintReqs))
	}
	// code.json records the choice.
	for _, want := range []string{`"engine": "codex"`, `"credential": "secret"`, `"secret_name": "CODEX_API_KEY"`} {
		if !strings.Contains(scripts, want) {
			t.Errorf("code.json missing %q:\n%s", want, scripts)
		}
	}
	// Verification the AC names.
	if !strings.Contains(scripts, "codex exec --json") || !strings.Contains(scripts, "print the current working directory") {
		t.Errorf("codex verification step missing:\n%s", scripts)
	}
	// Next-steps help names codex's OWN sign-in command, not pi's leftover
	// "/login" text.
	if !strings.Contains(env.stdout, "codex login") {
		t.Errorf("next-steps help should name codex's own sign-in command:\n%s", env.stdout)
	}
	if strings.Contains(env.stdout, "# then /login") {
		t.Errorf("next-steps help must not print pi's /login text for codex:\n%s", env.stdout)
	}
}

// TestCodeInstall_CodexVersionPin covers --codex-version.
func TestCodeInstall_CodexVersionPin(t *testing.T) {
	env, err := runInstallEngine(t, "alice", map[string]string{
		"engine": "codex", "credential": "secret", "codex-version": "0.50.0",
	}, mintResult{}, nil, nil)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if !strings.Contains(env.allScripts(), "@openai/codex@0.50.0") {
		t.Errorf("--codex-version was not honoured:\n%s", env.allScripts())
	}
}

// TestCodeInstall_CodexGatewayNotYetSupported pins the #2273 scoping
// decision: --engine codex --credential gateway is rejected, naming the fix,
// rather than shipping an unverified path. Nothing runs on the box.
func TestCodeInstall_CodexGatewayNotYetSupported(t *testing.T) {
	env, err := runInstallEngine(t, "alice", map[string]string{
		"engine": "codex", "credential": "gateway", "provider": "openai", "model": "gpt-5-codex",
	}, okMint(), nil, nil)
	if err == nil {
		t.Fatal("install succeeded with --engine codex --credential gateway, which is not supported yet")
	}
	msg := err.Error()
	for _, want := range []string{"not supported", "CODEX_API_KEY", "secret"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error should name the fix (missing %q): %v", want, msg)
		}
	}
	if len(env.scripts) != 0 {
		t.Errorf("a rejected flag combination still ran %d remote script(s):\n%s", len(env.scripts), env.allScripts())
	}
	if len(env.mintReqs) != 0 {
		t.Errorf("a rejected flag combination still minted a gateway token")
	}
}
