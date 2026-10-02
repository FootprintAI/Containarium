package server

import (
	"context"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/agentengine"
	"github.com/footprintai/containarium/internal/auth"
	appconfig "github.com/footprintai/containarium/internal/config"
	"github.com/footprintai/containarium/internal/modelgateway"
	"github.com/footprintai/containarium/internal/tokenid"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
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
	// engines is the engine-resolution view of the gateway (#2222): the
	// default provider, which providers the daemon holds a global key for,
	// and how to check a per-owner key. provisionSkillBoxWith calls
	// agentengine.Resolve(ctx, skill.GetEngine(), keyOwner, &engines) once per
	// run — this is the ONLY thing that decides which provider a run's
	// gateway token is bound to; nothing else in this file picks a provider.
	engines  agentengine.Gateway
	httpPort int    // the daemon HTTP port the box dials (resolved to the host's default-route IP in-box)
	secret   []byte // shared HMAC secret (daemon jwt.secret) — signs the gateway token

	// models reads a provider's upstream model list (#2229), on the SAME key
	// a run's gateway token would spend. nil in direct mode and on any daemon
	// built before this field — provisionSkillBoxWith treats that as "can't
	// check" exactly like an unsupported provider, never as a refusal.
	// *modelgateway.Gateway satisfies this; a narrow interface (not the
	// concrete type) so a test can fake it with a call recorder instead of
	// standing up a real Gateway.
	models modelLister

	// egressCIDR is the host the box reaches the gateway on, as a /32 (the LXC
	// bridge gateway IP — also the daemon API + DNS). When set, the skill box's
	// egress policy allows ONLY this host (+ peers) for model calls and DROPS the
	// direct provider domains — so a box can't bypass the gateway (#674 inc 4).
	egressCIDR string
}

// modelLister is the one method RunAgentSkill's model-ceiling check (#2229)
// needs from the model gateway — see gatewayProvisioning.models.
type modelLister interface {
	ListModels(ctx context.Context, keyOwner, provider string) ([]string, error)
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
// skill + provider, expiring with the in-box token (agentTokenTTL). provider
// is the run's RESOLVED provider (#2222, agentengine.Resolve's output) — a
// crew whose members resolve to two different engines mints two tokens here,
// each bound to its own member's provider, never the daemon's single default.
//
// runID binds the token to one skill run (#1817) and the returned MintedID is
// what lets the run's exit revoke it: without the jti the issuer would have to
// re-parse its own token to kill it.
//
// keyOwner is stamped as the token's key_owner claim (#2134) so the gateway
// spends that owner's registered key; "" mints no claim and the token resolves
// through the daemon-global key exactly as before. Callers resolve it with
// runKeyOwner, which only ever returns a validated owner or "".
//
// model (#2229) is the skill manifest's own pinned model, already confirmed
// (by the caller, before this mint) to be one the resolved provider actually
// serves when a check was possible. Empty means the skill pins none — the
// token carries no AllowedModels ceiling, the gateway's own default applies,
// unchanged pre-#2229 behavior. A skill with one DOES get a real ceiling: the
// token can spend on exactly that model and no other, enforced at the
// gateway (internal/modelgateway/gateway.go), not just advisory.
func (g *gatewayProvisioning) mintGatewayToken(tenant, skillID, runID, keyOwner, provider, model string) (string, tokenid.MintedID, error) {
	var allowedModels []string
	if model != "" {
		allowedModels = []string{model}
	}
	return modelgateway.MintTokenWithID(g.secret, modelgateway.GatewayClaims{
		Tenant:        tenant,
		SkillID:       skillID,
		Provider:      provider,
		AllowedModels: allowedModels,
		RunID:         runID,
		KeyOwner:      keyOwner,
	}, agentTokenTTL)
}

// runKeyOwner resolves whose provider key a skill/crew run's model calls spend
// (#2134), the way MintGatewayToken resolves it for a named box
// (resolveBoxKeyOwner): the box's cloud_org_id attribution label when the
// cloud stamped one -> org:<org_id>, else the run's owning username. A skill
// box is named agent-<skill> and shared by every caller of that skill, so the
// box name is not an owner; the run belongs to whoever dispatched it — the
// authenticated subject, the same identity the run's platform token records as
// its act claim (mintedAgentAct).
//
// Returns "" — no key_owner claim, the daemon-global key, as before #2134 —
// when there is no attributable owner (a system-started run with no subject;
// decided on FootprintAI/Containarium-cloud#1917, 2026-09-29) or when the
// resolved owner does not pass modelgateway.ValidateKeyOwner. A malformed
// owner is never stamped and never degrades to a different owner: a stamped
// but malformed attribution must not fall through to the caller's username,
// since that would bill someone the cloud did not attribute the box to.
func runKeyOwner(ctx context.Context, box *pb.Container) string {
	var owner string
	if orgID := strings.TrimSpace(box.GetLabels()[cloudOrgIDLabel]); orgID != "" {
		owner = modelgateway.OrgKeyOwner(orgID)
	} else if username, _, ok := auth.SubjectFromGRPCContext(ctx); ok && username != "" {
		owner = modelgateway.UserKeyOwner(username)
	} else {
		return ""
	}
	if err := modelgateway.ValidateKeyOwner(owner); err != nil {
		log.Printf("[agent-skill] run key owner %q is not a valid key_owner (%v); minting with no key_owner claim", owner, err)
		return ""
	}
	return owner
}

// mintRunGatewayToken mints the gateway token for one skill/crew run on the box
// `name`, carrying the run's key_owner (runKeyOwner) and bound to provider —
// the run's RESOLVED provider (#2222), not necessarily the daemon's default.
// Every run path — a push run, a crew member, a queue worker — reaches it
// through provisionSkillBoxWith, which resolves provider once per run via
// agentengine.Resolve before calling here.
//
// An owner with no registered key is still minted a key_owner token: the
// gateway falls back to the daemon-global key for it and logs that call as
// billed to the operator (modelgateway resolveKey, case 3). That differs on
// purpose from MintGatewayToken, which refuses such a mint up front — a caller
// asking for a token can fix its config and retry, whereas a run that fails
// outright is worse than one that runs and is logged (#2134). This path never
// reaches here for a provider agentengine.Resolve already refused: that
// refusal happens in provisionSkillBoxWith before any mint is attempted.
//
// A run with no attributable owner mints no claim, and is logged here, once
// per run, rather than per model call.
//
// model (#2229) is the skill manifest's own pinned model — see
// gatewayProvisioning.mintGatewayToken's doc for what it does to the token.
func (s *AgentSkillServer) mintRunGatewayToken(ctx context.Context, name, skillID, runID, provider, model string, box *pb.Container) (string, tokenid.MintedID, error) {
	keyOwner := runKeyOwner(ctx, box)
	if keyOwner == "" {
		log.Printf("[agent-skill] run %s on %s has no attributable key owner; its model calls are billed to the daemon-global key", runID, name)
	}
	return s.gateway.mintGatewayToken(name, skillID, runID, keyOwner, provider, model)
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

// gatewayRegistryFromEnv builds the provider registry the daemon serves and the
// daemon-global keys it holds:
//
//   - providers: the compiled-in set (modelgateway.DefaultProviders) plus every
//     OpenAI-compatible upstream an operator registered by setting
//     <PROVIDER>_UPSTREAM_URL. Nothing is compiled in for those, which is why a
//     brokered vendor's hostname lives in the deployment's environment and not
//     in this repo.
//   - keys: the daemon-global fallback key per provider — the built-ins as
//     before, plus <PROVIDER>_API_KEY for each registered provider that has one.
//   - registered: the names that came from the environment, so the caller can
//     tell "an operator configured an upstream" from "an operator configured a
//     key". A registered provider with no global key is the normal multi-owner
//     shape: its keys arrive per owner (modelgateway.KeyResolver), not from env.
//
// A malformed <PROVIDER>_UPSTREAM_URL comes back as an error; the caller logs it
// and carries on with the built-ins rather than failing the daemon's start.
func gatewayRegistryFromEnv() (map[string]*modelgateway.Provider, map[string]string, []string, error) {
	providers := modelgateway.DefaultProviders()
	keys := gatewayProviderKeysFromEnv()

	envProviders, err := modelgateway.ProvidersFromEnv(os.Environ())
	if err != nil {
		return providers, keys, nil, err
	}
	registered := make([]string, 0, len(envProviders))
	for name, p := range envProviders {
		providers[name] = p
		registered = append(registered, name)
		if v := strings.TrimSpace(os.Getenv(p.KeyEnv)); v != "" {
			keys[name] = v
		}
	}
	sort.Strings(registered)
	return providers, keys, registered, nil
}

// gatewayEnabled reports whether the daemon should serve the model gateway at
// all. Historically that was "it holds at least one provider key"; an
// operator-registered OpenAI-compatible upstream now also counts, because on a
// multi-owner deployment the keys arrive per owner over RPC and the daemon may
// legitimately hold none of its own. With neither, the gateway stays inert and
// boxes run in direct mode, exactly as before.
func gatewayEnabled(keys map[string]string, registered []string) bool {
	return len(keys) > 0 || len(registered) > 0
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
