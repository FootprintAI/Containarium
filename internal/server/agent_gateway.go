package server

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	appconfig "github.com/footprintai/containarium/internal/config"
	"github.com/footprintai/containarium/internal/modelgateway"
	"github.com/footprintai/containarium/internal/tokenid"
)

// Model-gateway provisioning for skill boxes (#674 design, productionization of
// the #737 prototype). When the daemon holds a provider API key, it serves the
// model-gateway (internal/modelgateway) on its HTTP port and provisions each
// skill box to route its model calls through it: the box gets a short-lived,
// per-skill *gateway token* and the SDK base-URL env, so the real key never
// lives in a box and every call is metered per tenant/skill. This is an env
// change in the box, not a code change — the agent-runtime engines already honor
// these vars (Claude/OpenAI base-URL; Gemini via CONTAINARIUM_MODEL_GATEWAY_URL).

// gatewayProvisioning is the daemon-resolved config the AgentSkillServer needs
// to mint a box's gateway token and seed its env. nil ⇒ no provider key
// configured ⇒ boxes run in direct mode (the OSS/self-hosted default).
type gatewayProvisioning struct {
	provider      string // the gateway's configured provider (anthropic|openai|gemini)
	httpPort      int    // the daemon HTTP port the box dials (resolved to the host's default-route IP in-box)
	secret        []byte // shared HMAC secret (daemon jwt.secret) — signs the gateway token
	allowedModels []string
	// egressCIDR is the host the box reaches the gateway on, as a /32 (the LXC
	// bridge gateway IP — also the daemon API + DNS). When set, the skill box's
	// egress policy allows ONLY this host (+ peers) for model calls and DROPS the
	// direct provider domains — so a box can't bypass the gateway (#674 inc 4).
	egressCIDR string
}

// gatewayProviderEnv is the per-provider env contract the agent-runtime engines
// read. urlSuffix is appended to the daemon HTTP base to form the SDK base URL;
// gemini takes the BARE base (its engine appends the /v1/model/gemini path).
type gatewayProviderEnv struct {
	urlVar    string
	tokenVar  string
	urlSuffix string
}

var gatewayProviderEnvs = map[string]gatewayProviderEnv{
	"anthropic": {urlVar: "ANTHROPIC_BASE_URL", tokenVar: "ANTHROPIC_AUTH_TOKEN", urlSuffix: "/v1/model/anthropic"},
	"openai":    {urlVar: "OPENAI_BASE_URL", tokenVar: "OPENAI_API_KEY", urlSuffix: "/v1/model/openai"},
	"gemini":    {urlVar: "CONTAINARIUM_MODEL_GATEWAY_URL", tokenVar: "CONTAINARIUM_GATEWAY_TOKEN", urlSuffix: ""},
}

// mintGatewayToken mints a per-skill gateway token bound to this box's tenant +
// skill + the configured provider, expiring with the in-box token (agentTokenTTL).
//
// runID binds the token to one skill run (#1817) and the returned MintedID is
// what lets the run's exit revoke it: without the jti the issuer would have to
// re-parse its own token to kill it.
func (g *gatewayProvisioning) mintGatewayToken(tenant, skillID, runID string) (string, tokenid.MintedID, error) {
	return modelgateway.MintTokenWithID(g.secret, modelgateway.GatewayClaims{
		Tenant:        tenant,
		SkillID:       skillID,
		Provider:      g.provider,
		AllowedModels: g.allowedModels,
		RunID:         runID,
	}, agentTokenTTL)
}

// gatewayEnvScript returns a shell snippet (run inside the box, in the same exec
// as the seed) that resolves the host's IP from the box's default route and
// writes the provider env to <seedDir>/gateway.env. The base URL is resolved
// IN-BOX (not baked at provision time) so it works regardless of the bridge
// subnet — the same default-route approach validated for the worker poll path.
// Pure: returns the script for the given provider/port/token; errors on an
// unknown provider.
func gatewayEnvScript(provider string, httpPort int, token, seedDir string) (string, error) {
	pe, ok := gatewayProviderEnvs[provider]
	if !ok {
		return "", fmt.Errorf("model-gateway: unknown provider %q", provider)
	}
	var b strings.Builder
	// Resolve the host (LXC bridge gateway) from the default route; the daemon's
	// model-gateway listens on http://<that host>:<httpPort>.
	b.WriteString("__ctn_host=\"$(ip route show default 2>/dev/null | awk '/default/ {print $3; exit}')\"\n")
	b.WriteString("if [ -z \"$__ctn_host\" ]; then echo 'model-gateway: could not resolve host from default route' >&2; fi\n")
	fmt.Fprintf(&b, "{\n")
	// URL var: double-quoted so $__ctn_host expands at write time.
	fmt.Fprintf(&b, "  printf 'export %s=%%s\\n' \"http://$__ctn_host:%d%s\"\n", pe.urlVar, httpPort, pe.urlSuffix)
	// Token var: single-quoted literal (a JWT — no shell metachars, but be safe).
	fmt.Fprintf(&b, "  printf 'export %s=%%s\\n' %s\n", pe.tokenVar, shellSingleQuote(token))
	fmt.Fprintf(&b, "} > %s/gateway.env\n", seedDir)
	fmt.Fprintf(&b, "chmod 600 %s/gateway.env\n", seedDir)
	return b.String(), nil
}

// gatewayRecipeEnvExports returns shell lines that resolve the daemon host from
// the box's default route and EXPORT the managed model-gateway contract into the
// post_start environment (not a file): CONTAINARIUM_MODEL_GATEWAY_URL, pointing
// at the gateway's per-provider base (/v1/model/<provider>), and
// CONTAINARIUM_GATEWAY_TOKEN. A recipe's post_start reads these to point its
// in-box app at the gateway, appending any upstream sub-path. The URL is
// resolved IN-BOX so it works regardless of the bridge subnet (same approach as
// gatewayEnvScript). Pure: returns the snippet for the given provider/port/token.
func gatewayRecipeEnvExports(provider string, httpPort int, token string) string {
	var b strings.Builder
	b.WriteString("__ctn_host=\"$(ip route show default 2>/dev/null | awk '/default/ {print $3; exit}')\"\n")
	b.WriteString("if [ -z \"$__ctn_host\" ]; then echo 'model-gateway: could not resolve host from default route' >&2; fi\n")
	fmt.Fprintf(&b, "export CONTAINARIUM_MODEL_GATEWAY_URL=\"http://$__ctn_host:%d/v1/model/%s\"\n", httpPort, provider)
	fmt.Fprintf(&b, "export CONTAINARIUM_GATEWAY_TOKEN=%s\n", shellSingleQuote(token))
	return b.String()
}

// gatewayProviderKeysFromEnv reads provider API keys from the daemon env, one
// per provider that has a key set. These keys are held ONLY in the daemon's
// gateway process; a box never sees them. Gemini accepts GEMINI_API_KEY or
// GOOGLE_API_KEY (mirrors the gemini engine's own lookup).
func gatewayProviderKeysFromEnv() map[string]string {
	out := map[string]string{}
	if v := strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY")); v != "" {
		out["anthropic"] = v
	}
	if v := strings.TrimSpace(os.Getenv("OPENAI_API_KEY")); v != "" {
		out["openai"] = v
	}
	if v := strings.TrimSpace(os.Getenv("GEMINI_API_KEY")); v != "" {
		out["gemini"] = v
	} else if v := strings.TrimSpace(os.Getenv("GOOGLE_API_KEY")); v != "" {
		out["gemini"] = v
	}
	// The Gemini key also backs the OpenAI-compatible Gemini provider
	// (gemini-openai), which the hosted OpenHands canvas routes through. Same
	// real key, different upstream protocol + auth header (see DefaultProviders).
	if v := out["gemini"]; v != "" {
		out["gemini-openai"] = v
	}
	return out
}

// gatewayPrimaryProvider picks the provider skill boxes are provisioned for when
// several keys are configured, by a fixed precedence — anthropic first (the
// agent-runtime default engine). "" when no key is set. Pure.
func gatewayPrimaryProvider(keys map[string]string) string {
	for _, p := range []string{"anthropic", "openai", "gemini"} {
		if keys[p] != "" {
			return p
		}
	}
	return ""
}

// sourceGatewayEnvPrefix is the shell prefix that sources <seedDir>/gateway.env
// (if present) into the environment before launching agent-runtime, so the
// engine SDK picks up the gateway base-URL + token. A no-op in direct mode
// (file absent). `set -a` exports everything the file sets.
func sourceGatewayEnvPrefix(seedDir string) string {
	return fmt.Sprintf("set -a; [ -f %s/gateway.env ] && . %s/gateway.env; set +a; ", seedDir, seedDir)
}

// gatewayPolicyFromEnv builds the gateway's enforcement config from the daemon
// env, or returns nil when the operator has configured nothing — in which case
// the gateway meters and denies nothing, exactly as it did before enforcement
// existed. Opt-in by construction: an operator upgrading the daemon must not
// discover that their agents are being throttled by numbers they never chose.
//
// Pure apart from the env reads, so the parsing is testable on its own.
func gatewayPolicyFromEnv() *modelgateway.PolicyConfig {
	var pc modelgateway.PolicyConfig

	pc.Quota.Window = envDuration(appconfig.EnvGatewayQuotaWindow, 0)
	pc.Quota.MaxCalls = envInt64(appconfig.EnvGatewayQuotaCalls)
	pc.Quota.MaxTotalTokens = envInt64(appconfig.EnvGatewayQuotaTokens)
	pc.Quota.MaxOutputTokens = envInt64(appconfig.EnvGatewayQuotaOutputTokens)
	pc.Anomaly.Enabled = os.Getenv(appconfig.EnvGatewayAnomalyEnabled) == "1"
	pc.RevokeAt = envFloat(appconfig.EnvGatewayAnomalyRevokeAt)

	// A window alone is not a configuration: it says when to measure, not how
	// much is allowed. Without a cap or the detectors, there is nothing to
	// enforce and the policy stays absent.
	if pc.Quota.IsZero() && !pc.Anomaly.Enabled {
		return nil
	}
	return &pc
}

// gatewayPolicyLogSink writes ladder transitions to the daemon log. The gateway
// keeps its own alerting dependency-free, so this is the daemon's minimum
// wiring: a state change that nobody is told about is not a response.
type gatewayPolicyLogSink struct{}

func (gatewayPolicyLogSink) PolicyTransition(ev modelgateway.PolicyEvent) {
	names := make([]string, 0, len(ev.Signals))
	for _, s := range ev.Signals {
		names = append(names, s.Name)
	}
	log.Printf("model-gateway: tenant=%s skill=%s %s -> %s reason=%q score=%.2f quota=%.0f%% signals=%v",
		ev.Tenant, ev.Skill, ev.From, ev.To, ev.Reason, ev.Score, ev.Quota*100, names)
}

func envInt64(key string) int64 {
	v, err := strconv.ParseInt(strings.TrimSpace(os.Getenv(key)), 10, 64)
	if err != nil || v < 0 {
		return 0
	}
	return v
}

func envFloat(key string) float64 {
	v, err := strconv.ParseFloat(strings.TrimSpace(os.Getenv(key)), 64)
	if err != nil || v < 0 {
		return 0
	}
	return v
}

func envDuration(key string, def time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return def
	}
	return d
}
