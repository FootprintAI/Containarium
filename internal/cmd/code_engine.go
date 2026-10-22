package cmd

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/internal/coderun"
	"github.com/footprintai/containarium/internal/coderun/engine"
	"github.com/footprintai/containarium/internal/gatewayprovider"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

// The engine + credential wiring for `containarium code` (#1727).
//
// This file is the cmd-layer half of the seam: internal/coderun/engine decides
// WHAT to run (pure, shell-rendering, table-tested), and this decides WHEN —
// which preflight to run, when to mint, where to write. The split is what keeps
// the engine table unit-testable without a daemon.
//
// It consumes #1726's ModelGatewayService and does not modify it.

// codeVerifyTokenTTL is the lifetime of the token `code install` mints purely to
// verify the box can reach a model. Short on purpose: it proves reachability
// once and then stops being useful. Every real run mints its own.
const codeVerifyTokenTTL = 5 * time.Minute

// codeRunTokenTTLDefault is the default lifetime of a per-run gateway token.
//
// A run is the natural lease (design doc's token-lifetime table): a leaked token
// is then one box, one model, one run, and at most a day — and revocable by its
// jti before that. Capped server-side regardless of what is asked for here.
const codeRunTokenTTLDefault = 24 * time.Hour

// codeInstallPlan is everything the flags resolved to, validated together.
// Built once so no later step re-derives a choice and disagrees.
type codeInstallPlan struct {
	engine     engine.Engine
	credential engine.CredentialSource
	config     engine.CodeConfig
	// provider is the gateway provider enum, unset for a secret credential.
	provider pb.GatewayProvider
	// baseURLOverride is --provider-base-url, verbatim.
	baseURLOverride string
	// version is the engine version pin (--claude-code-version / --pi-version).
	version string
}

// resolveCodeInstallPlan validates the engine/credential flag combination.
//
// Every rejection here names the fix. The combinations are cheap to get wrong
// (--credential gateway without --provider, --engine pi without --model) and
// expensive to discover on a box.
func resolveCodeInstallPlan(box string) (*codeInstallPlan, error) {
	name, err := engine.ParseName(codeEngine)
	if err != nil {
		return nil, err
	}
	kind, err := engine.ParseCredentialKind(codeCredential)
	if err != nil {
		return nil, err
	}

	// #2273: codex's gateway path depends on the model gateway's provider
	// generalization (#1369/#1374 on Containarium-cloud), which this change
	// does not assume has landed. Rejecting here — before any preflight —
	// means a user who tries it gets the fix named instead of an untested
	// path reaching a box. Tracked as a follow-up, not a redesign: the
	// gateway-shaped methods already exist on codexEngine (codex.go).
	if name == engine.NameCodex && kind == engine.KindGateway {
		return nil, fmt.Errorf(
			"--engine codex --credential gateway is not supported yet (tracked as a follow-up to #2273) — " +
				"use --credential secret --secret-name CODEX_API_KEY (or OPENAI_API_KEY)")
	}

	plan := &codeInstallPlan{baseURLOverride: strings.TrimSpace(codeProviderBaseURL)}

	switch kind {
	case engine.KindGateway:
		if strings.TrimSpace(codeProvider) == "" {
			return nil, fmt.Errorf(
				"--credential gateway needs --provider (one of: %s)", strings.Join(gatewayprovider.Names(), ", "))
		}
		provider, err := gatewayprovider.FromName(codeProvider)
		if err != nil {
			return nil, err
		}
		if s := strings.TrimSpace(codeSecretName); s != "" {
			return nil, fmt.Errorf("--secret-name is for --credential secret; --credential gateway mints a token instead")
		}
		providerName, err := gatewayprovider.Name(provider)
		if err != nil {
			return nil, err
		}
		plan.provider = provider
		plan.credential = engine.GatewayCredential{Provider: providerName}
	case engine.KindSecret:
		if strings.TrimSpace(codeProvider) != "" {
			return nil, fmt.Errorf("--provider is for --credential gateway; --credential secret reads a tenant secret instead")
		}
		plan.credential = engine.SecretCredential{Name: strings.TrimSpace(codeSecretName)}
	}

	// pi renders a custom-provider config that names exactly one model, and a
	// gateway token's allowed_models ceiling is that same model — so there is
	// nothing sensible to default it to.
	model := strings.TrimSpace(codeModel)
	if name == engine.NamePi && model == "" {
		return nil, fmt.Errorf(
			"--engine pi needs --model (the model id runs are pinned to; `containarium gateway models --provider %s --box %s` lists what your key can reach)",
			strings.TrimSpace(codeProvider), box)
	}

	// pi on a tenant secret has no gateway to derive an endpoint from, so the
	// endpoint must come from the operator. Rejected HERE, before the preflight,
	// rather than when models.json is rendered: the secret preflight does a
	// secrets RPC in between, and a lookup failure there would mask this purely
	// local mistake with a network error.
	if name == engine.NamePi && kind == engine.KindSecret {
		if plan.baseURLOverride == "" {
			return nil, fmt.Errorf(
				"--engine pi --credential secret needs --provider-base-url (the complete endpoint URL pi should call, e.g. https://api.openai.com/v1) — " +
					"only --credential gateway can derive one on its own")
		}
		// models.json's apiKey is an environment-variable REFERENCE, so there has
		// to be a variable to name. Without --secret-name there is nothing to
		// write, and defaulting to the gateway's variable would point pi at a
		// value this path never sets.
		if strings.TrimSpace(codeSecretName) == "" {
			return nil, fmt.Errorf(
				"--engine pi --credential secret needs --secret-name (the variable pi reads its key from, e.g. OPENAI_API_KEY) — " +
					"it becomes models.json's apiKey reference and is delivered by `containarium secrets set ... --delivery compose`")
		}
	}

	plan.version = strings.TrimSpace(codeClaudeCodeVersion)
	switch name {
	case engine.NamePi:
		plan.version = strings.TrimSpace(codePiVersion)
	case engine.NameCodex:
		plan.version = strings.TrimSpace(codeCodexVersion)
	}

	eng, err := engine.For(name, engine.Options{Credential: plan.credential, Model: model})
	if err != nil {
		return nil, err
	}
	plan.engine = eng

	plan.config = engine.CodeConfig{
		Version:    engine.CodeConfigVersion,
		Engine:     name,
		Credential: plan.credential.Kind(),
		Model:      model,
	}
	if gw, ok := plan.credential.(engine.GatewayCredential); ok {
		plan.config.Provider = gw.Provider
	}
	if sec, ok := plan.credential.(engine.SecretCredential); ok {
		plan.config.SecretName = sec.Name
	}
	return plan, nil
}

// installOptions builds the engine's InstallScript inputs. mint is the dry-run
// mint response for a gateway credential (nil otherwise) — it carries the base
// URL models.json has to point at, which is why rendering happens after the
// preflight rather than before it.
func (p *codeInstallPlan) installOptions(mint *pb.MintGatewayTokenResponse) (engine.InstallOptions, error) {
	opts := engine.InstallOptions{Version: p.version}
	if p.engine.Name() != engine.NamePi {
		return opts, nil
	}

	base := ""
	if mint != nil {
		base = mint.GetBaseUrl()
	}
	// With --provider-base-url the operator supplied a complete URL, so the
	// gateway base is not needed; RenderPiModelsJSON uses the override as-is.
	if base == "" && p.baseURLOverride == "" {
		return opts, fmt.Errorf("no gateway base URL resolved for --engine pi; pass --provider-base-url or use --credential gateway")
	}
	// The variable pi interpolates its apiKey from has to be the one the box
	// will actually have at run time, and that differs per credential source:
	// the gateway path writes CONTAINARIUM_GATEWAY_TOKEN to gateway.env, while
	// the secret path gets --secret-name's own variable out of
	// /run/containarium/secrets.env. Naming the wrong one leaves pi unable to
	// resolve any credential, surfacing as an auth failure at the first model
	// call rather than as anything pointing back here.
	tokenEnvVar := engine.GatewayTokenEnvVar
	if p.credential.Kind() == engine.KindSecret {
		tokenEnvVar = p.config.SecretName
	}

	blob, err := engine.RenderPiModelsJSON(engine.PiModelsParams{
		Provider:        p.provider,
		GatewayBase:     base,
		BaseURLOverride: p.baseURLOverride,
		TokenEnvVar:     tokenEnvVar,
		Model:           p.config.Model,
	})
	if err != nil {
		return opts, err
	}
	opts.ModelsJSON = string(blob)
	return opts, nil
}

// codeInstallPreflight runs the credential source's install-time check.
//
// For a gateway credential this is MintGatewayToken{dry_run:true}, which
// validates box ownership, the provider, and that the resolved key owner
// actually has a key — and issues nothing. That is how a misconfiguration gets
// named at install time instead of at the first model call.
//
// It returns the dry-run response (gateway only) because its base_url is what
// models.json must point at.
func codeInstallPreflight(ctx context.Context, box string, plan *codeInstallPlan, diag io.Writer) (*pb.MintGatewayTokenResponse, error) {
	switch plan.credential.Preflight() {
	case engine.PreflightGatewayDryRun:
		resp, err := mintGatewayTokenFn(ctx, &pb.MintGatewayTokenRequest{
			Box:      box,
			Provider: plan.provider,
			DryRun:   true,
		})
		if err != nil {
			return nil, gatewayPreflightError(box, plan, err)
		}
		fmt.Fprintf(diag, "✓ gateway key present for %s (provider %s, dry run — no token issued)\n",
			resp.GetKeyOwner(), plan.config.Provider)
		return resp, nil

	case engine.PreflightSecretMetadata:
		if err := checkCodeSecretCredential(box, plan); err != nil {
			return nil, err
		}
		if name := plan.config.SecretName; name != "" {
			fmt.Fprintf(diag, "✓ %s present on %s with a shell-visible delivery mode\n", name, box)
		}
		return nil, nil
	}
	return nil, fmt.Errorf("unknown preflight %v", plan.credential.Preflight())
}

// gatewayPreflightError turns the dry run's failure into an instruction.
//
// FailedPrecondition specifically means "the resolved key owner has no key for
// this provider" — the server refuses rather than letting the call silently bill
// the operator (#1726). That is the single most likely reason this command fails
// for a new org, so it gets the concrete fix rather than a wrapped gRPC status.
func gatewayPreflightError(box string, plan *codeInstallPlan, err error) error {
	if st, ok := status.FromError(err); ok && st.Code() == codes.FailedPrecondition {
		return fmt.Errorf(
			"no inference key is registered for the owner of box %q, so a gateway token cannot be minted for provider %s.\n"+
				"Set one, then re-run this command:\n"+
				"  Containarium Cloud: Settings → Inference key\n"+
				"  self-hosted:        containarium gateway key set <key-owner> --provider %s --key-file <path>\n"+
				"(server said: %s)",
			box, plan.config.Provider, plan.config.Provider, st.Message())
	}
	return fmt.Errorf("gateway preflight for %q failed: %w", box, err)
}

// checkCodeSecretCredential is the metadata-only check for the `secret`
// credential source.
//
// It reads the secret's METADATA — name and delivery mode — and never its value,
// which is the whole reason it can exist at all.
//
// Scope note: this check runs ONLY when --secret-name names a provider key (the
// user's own OPENAI_API_KEY / ANTHROPIC_API_KEY). It deliberately does NOT
// reintroduce the CLAUDE_CODE_OAUTH_TOKEN precheck #2036 removed: Claude Code's
// terms forbid a platform intermediating a Claude.ai credential, so with no
// --secret-name there is nothing here to check and nothing is checked.
//
// The delivery-mode rule is the one docs/integrations/pi.md §"Why not env
// delivery" documents: `env` delivery stamps the variable on the LXC, which
// reaches container-start processes but NOT an SSH shell session — and an SSH
// shell session is exactly where these engines run. So env delivery is a
// configuration that looks right and silently does not work.
func checkCodeSecretCredential(box string, plan *codeInstallPlan) error {
	name := strings.TrimSpace(plan.config.SecretName)
	if name == "" {
		return nil
	}
	secrets, err := listSecretsFn(box)
	if err != nil {
		return fmt.Errorf("check %s on %q: %w", name, box, err)
	}
	var found *pb.SecretMetadata
	for _, s := range secrets {
		if s.GetName() == name {
			found = s
			break
		}
	}
	if found == nil {
		return fmt.Errorf(
			"no %s secret set for %q — set it, then re-run:\n  containarium secrets set %s %s <value> --delivery compose\n  containarium secrets refresh %s",
			name, box, box, name, box)
	}
	switch found.GetDeliveryMode() {
	case pb.SecretDelivery_SECRET_DELIVERY_COMPOSE, pb.SecretDelivery_SECRET_DELIVERY_FILE:
		return nil
	default:
		return fmt.Errorf(
			"%s for %q is delivered as %q, which an SSH shell session does not inherit — "+
				"the login path rebuilds the environment and `su -` drops inherited variables "+
				"(docs/integrations/pi.md, \"Why not env delivery\"). Re-set it with:\n"+
				"  containarium secrets set %s %s <value> --delivery compose\n  containarium secrets refresh %s",
			name, box, found.GetDeliveryMode(), box, name, box)
	}
}

// mintAndWriteVerifyToken mints the short-lived token `code install` verifies
// with and writes it to the engine's gateway.env.
//
// Written over SSH with `umask 077` before the redirect rather than a chmod
// after it: a chmod leaves a window in which the file exists world-readable, and
// on a box a user shares with an agent that window is not theoretical (the same
// argument boxbootstrap's apply.sh makes).
func mintAndWriteVerifyToken(ctx context.Context, box string, plan *codeInstallPlan,
	run func(string) (string, error), diag io.Writer) error {

	req := &pb.MintGatewayTokenRequest{
		Box:      box,
		Provider: plan.provider,
		RunId:    "code-install-verify",
		Ttl:      durationpb.New(codeVerifyTokenTTL),
	}
	if m := plan.config.Model; m != "" {
		req.AllowedModels = []string{m}
	}
	resp, err := mintGatewayTokenFn(ctx, req)
	if err != nil {
		return gatewayPreflightError(box, plan, err)
	}
	if _, err := run(writeGatewayEnvScript(plan.engine.GatewayEnvPath(), resp)); err != nil {
		return fmt.Errorf("write %s on %q: %w", plan.engine.GatewayEnvPath(), box, err)
	}
	fmt.Fprintf(diag, "✓ wrote %s on %s (0600, expires %s)\n",
		plan.engine.GatewayEnvPath(), box, resp.GetExpiresAt().AsTime().Format(time.RFC3339))
	return nil
}

// writeGatewayEnvScript renders the shell script that writes a box's
// gateway.env.
//
// The two exported variables are NOT a new contract: they are exactly what
// `containarium gateway mint --env` prints and what the daemon's own
// gatewayEnvScript writes, so a box seeded by any of the three is readable by
// the others.
func writeGatewayEnvScript(path string, resp *pb.MintGatewayTokenResponse) string {
	return `set -e
umask 077
mkdir -p "$(dirname "` + path + `")"
{
  printf 'export ` + engine.GatewayURLEnvVar + `=%s\n' ` + coderun.ShellQuoteSingle(resp.GetBaseUrl()) + `
  printf 'export ` + engine.GatewayTokenEnvVar + `=%s\n' ` + coderun.ShellQuoteSingle(resp.GetToken()) + `
} > "` + path + `"
chmod 600 "` + path + `"`
}

// writeCodeConfigScript renders the shell script that writes code.json (0600).
func writeCodeConfigScript(cfg engine.CodeConfig) string {
	blob, err := cfg.Marshal()
	if err != nil {
		// Marshalling a struct of strings and an int cannot fail; a script that
		// fails loudly on the box beats silently writing nothing.
		return `echo "containarium: could not render code.json: ` + err.Error() + `" >&2; exit 1`
	}
	return `set -e
umask 077
mkdir -p "$(dirname "` + engine.CodeConfigPath + `")"
printf '%s' ` + coderun.ShellQuoteSingle(string(blob)) + ` > "` + engine.CodeConfigPath + `"
chmod 600 "` + engine.CodeConfigPath + `"`
}

// codeNextStepsHelp tells the user what is left to do, which depends entirely on
// the credential source.
//
// The Claude + secret path keeps #2036's sign-in help verbatim: that text exists
// because the platform may not hold a Claude.ai credential, and #1727 does not
// change that. A gateway box needs nothing further — which is the point of the
// gateway, and worth saying.
func codeNextStepsHelp(box string, plan *codeInstallPlan) string {
	if plan.credential.Kind() == engine.KindGateway {
		return fmt.Sprintf(`
%s is installed and wired to the containarium model gateway. No provider key
is stored on the box: each run mints its own scoped, short-lived token.

Next: containarium code run %s --prompt "..."
`, plan.engine.Name(), box)
	}
	if plan.engine.Name() == engine.NameClaude {
		return codeSignInHelp(box)
	}
	name := plan.config.SecretName
	if name == "" {
		name = "<PROVIDER>_API_KEY"
	}
	return fmt.Sprintf(`
%s is installed. It reads its provider key from the box's environment, so give
it one of:

  tenant secret (recommended — never in your shell history):
      containarium secrets set %s %s <value> --delivery compose
      containarium secrets refresh %s

  %s's own interactive sign-in, inside the box:
      containarium connect %s
      %s

Then: containarium code run %s --prompt "..."
`, plan.engine.Name(), box, name, box, plan.engine.Name(), box, engineLoginCommand(plan.engine.Name()), box)
}

// engineLoginCommand is the interactive, inside-the-box sign-in command for
// an engine on the secret credential path — the thing codeNextStepsHelp
// tells the user to run after `containarium connect <box>`.
//
// #2273: this used to be hardcoded to pi's own "pi   # then /login" inline,
// which was correct only because pi was the only non-Claude engine. Adding
// codex, whose sign-in command is different (codex login --device-auth,
// developers.openai.com/codex/auth — not a slash command inside a REPL),
// would have silently printed nonsense for it. Any FUTURE non-Claude engine
// needs a case here too, rather than falling into a default that assumes
// pi's shape again.
func engineLoginCommand(n engine.Name) string {
	switch n {
	case engine.NameCodex:
		return "codex login --device-auth   # or: codex login (opens a browser)"
	default: // pi, today's only other case.
		return string(n) + "   # then /login"
	}
}

// mintGatewayTokenViaClient is the production MintGatewayToken call, dispatched
// over whichever transport the CLI is configured for — the same dual-transport
// pattern `containarium gateway mint` uses.
func mintGatewayTokenViaClient(_ context.Context, req *pb.MintGatewayTokenRequest) (*pb.MintGatewayTokenResponse, error) {
	c, err := newGatewayClient()
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	return c.MintGatewayToken(req)
}

// listSecretMetadata reads a box's secret METADATA over whichever transport the
// global flags selected — the same dual dispatch runSecretsList uses. Metadata
// only: this returns []*pb.SecretMetadata (name, version, delivery mode,
// timestamps) and there is no call here that can return a value.
func listSecretMetadata(box string) ([]*pb.SecretMetadata, error) {
	if serverAddr == "" {
		return nil, fmt.Errorf(
			"--server is required to check --secret-name %q (the daemon owns the secrets store); omit --secret-name to skip the check",
			strings.TrimSpace(codeSecretName))
	}
	if httpMode {
		h, err := client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return nil, err
		}
		defer func() { _ = h.Close() }()
		return h.ListSecrets(box)
	}
	g, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return nil, err
	}
	defer func() { _ = g.Close() }()
	return g.ListSecrets(box)
}
