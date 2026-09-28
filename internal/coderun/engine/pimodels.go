package engine

import (
	"encoding/json"
	"fmt"
	"strings"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// pi's ~/.pi/agent/models.json, rendered from typed Go structs.
//
// This is a THIRD-PARTY schema we do not own, so every field below is sourced
// rather than invented — from @earendil-works/pi-coding-agent@0.87.1 (the
// version pi.go pins):
//
//   - docs/models.md, "Configure a compatible endpoint", which gives the
//     worked example this shape follows;
//   - docs/configuration.md, whose agent-directory table places models.json at
//     <agent-dir>/models.json with <agent-dir> defaulting to ~/.pi/agent;
//   - dist/core/model-config.d.ts, pi's own TypeBox schema, whose exported
//     types are literally ModelsJsonProvider / ModelsJsonModel. The provider
//     object there is {name?, baseUrl?, apiKey?, api?, oauth?, headers?,
//     compat?, authHeader?, models?} and a models entry is {id, name?, api?,
//     baseUrl?, …}.
//
// TestPiModelsJSON pins the rendered bytes against a fixture, so a pi release
// that renames a field fails on a laptop instead of on a customer's box.

// defaultPiAPI is the protocol assumed when no gateway provider names one: the
// OpenAI chat-completions shape. Specified rather than guessed — the PRD's
// Story 2 AC calls for "one custom OpenAI-compatible provider", and it is the
// shape Ollama, LM Studio, vLLM, SGLang and most proxies speak (pi's own
// docs/models.md, "Configure a compatible endpoint").
const defaultPiAPI = "openai-completions"

// PiProviderID is the key our provider takes in models.json's providers map.
// "containarium" rather than the upstream vendor's name on purpose: from pi's
// point of view the endpoint IS containarium's gateway, and naming it after the
// real upstream would imply the box is talking to that vendor directly.
const PiProviderID = "containarium"

// piModelsConfig is the top level of models.json.
//
// providers is a MAP keyed by provider id, not a list — pi's docs and TypeBox
// schema both agree, and the distinction matters because a map is what lets our
// entry replace itself idempotently on re-install.
type piModelsConfig struct {
	Providers map[string]piProviderConfig `json:"providers"`
}

// piProviderConfig is pi's ModelsJsonProvider, narrowed to the fields we set.
// Omitting the rest is safe — every field in pi's schema except the provider key
// itself is optional — and narrow is better than complete here: a field we do
// not set is a field pi's defaults own.
type piProviderConfig struct {
	Name    string          `json:"name"`
	BaseURL string          `json:"baseUrl"`
	API     string          `json:"api"`
	APIKey  string          `json:"apiKey"`
	Models  []piModelConfig `json:"models"`
}

// piModelConfig is pi's ModelsJsonModel, narrowed to the one required field.
type piModelConfig struct {
	ID string `json:"id"`
}

// PiShape is how one gateway provider is expressed to pi: which of pi's API
// protocols it speaks, and what has to be appended to the gateway's
// per-provider base URL to reach it.
type PiShape struct {
	// API is a value from pi-ai's KnownApi union.
	API string
	// BaseURLSuffix is appended to MintGatewayTokenResponse.base_url.
	//
	// It is not cosmetic. The gateway forwards everything after
	// /v1/model/<provider> VERBATIM to the upstream's root
	// (internal/modelgateway.Gateway.handleModel), and each of pi's API
	// protocols uses its vendor's own SDK, which appends its own path. So an
	// OpenAI-shaped upstream needs the base to carry the upstream's own /v1 —
	// the exact rule pkg/core/recipes/recipes.yaml already spells out for
	// LibreChat and mem0 — while Anthropic's and Google's SDKs append a path
	// that already includes their version segment and must get a bare base.
	BaseURLSuffix string
}

// piProviderShapes maps the GatewayProvider enum to pi's protocol vocabulary.
//
// Keyed on the ENUM rather than on a provider name string so that adding a
// GatewayProvider value without deciding its pi shape is a test failure
// (TestPiProviderMappingEveryGatewayProviderIsMapped) rather than a 404 on a
// box. This mirrors internal/server/agent_gateway.go's gatewayProviderEnvs,
// which does the same job for the agent-runtime engines.
var piProviderShapes = map[pb.GatewayProvider]PiShape{
	// Anthropic's SDK appends /v1/messages, so the base stays bare.
	pb.GatewayProvider_GATEWAY_PROVIDER_ANTHROPIC: {API: "anthropic-messages", BaseURLSuffix: ""},
	// The OpenAI SDK appends /chat/completions, so the base carries /v1.
	pb.GatewayProvider_GATEWAY_PROVIDER_OPENAI: {API: "openai-completions", BaseURLSuffix: "/v1"},
	// Google's GenAI SDK appends /v1beta/models/..., so the base stays bare.
	pb.GatewayProvider_GATEWAY_PROVIDER_GEMINI: {API: "google-generative-ai", BaseURLSuffix: ""},
	// Gemini's OpenAI-compatible surface lives under /v1beta/openai — pinned by
	// internal/modelgateway/gateway_test.go's proxy tests, not guessed.
	pb.GatewayProvider_GATEWAY_PROVIDER_GEMINI_OPENAI: {API: "openai-completions", BaseURLSuffix: "/v1beta/openai"},
	// kafeido is OpenAI-shaped (see the enum's own comment in the proto).
	pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO: {API: "openai-completions", BaseURLSuffix: "/v1"},
}

// PiProviderShape returns how provider is expressed to pi.
func PiProviderShape(provider pb.GatewayProvider) (PiShape, error) {
	if provider == pb.GatewayProvider_GATEWAY_PROVIDER_UNSPECIFIED {
		return PiShape{}, fmt.Errorf("provider is required")
	}
	shape, ok := piProviderShapes[provider]
	if !ok {
		return PiShape{}, fmt.Errorf(
			"gateway provider %s has no pi API mapping — add one to piProviderShapes", provider)
	}
	return shape, nil
}

// PiModelsParams are the inputs to one rendered models.json.
type PiModelsParams struct {
	// Provider is the gateway provider the box's token is scoped to.
	Provider pb.GatewayProvider
	// GatewayBase is MintGatewayTokenResponse.base_url, unmodified. The
	// provider's own suffix is appended here, not by the caller.
	GatewayBase string
	// BaseURLOverride, when set, replaces the computed base entirely
	// (`--provider-base-url`): the operator gave a complete URL for an endpoint
	// they are pointing pi at directly, so no suffix is guessed onto it.
	BaseURLOverride string
	// TokenEnvVar is the environment variable pi interpolates the credential
	// from at request time.
	TokenEnvVar string
	// Model is the one model this box is set up for.
	Model string
	// Token exists ONLY so that callers holding a live token cannot
	// accidentally be the reason one is written to disk: this field is
	// deliberately never rendered. models.json carries $VAR, never a value —
	// TestPiModelsJSONNeverCarriesTheToken is the assertion.
	Token string
}

// RenderPiModelsJSON renders ~/.pi/agent/models.json for one box.
//
// The credential is emitted as a "$VAR" reference, never a value. pi documents
// that apiKey "can use $NAME or ${NAME} environment interpolation" and resolves
// it at request time, so the token stays in ~/.pi/gateway.env (0600) and
// models.json itself is credential-free. That is what makes the AC's
// `grep -r sk- ~/.pi` check pass, and it also means a per-run token rotation
// never has to rewrite this file.
func RenderPiModelsJSON(p PiModelsParams) ([]byte, error) {
	override := strings.TrimSpace(p.BaseURLOverride)

	// With no gateway provider there is no enum to read a protocol off, which is
	// the `--credential secret` case: the box holds the user's own provider key
	// and `--provider-base-url` names the endpoint. The protocol is then
	// OpenAI-compatible by specification, not by guess — the PRD's Story 2 AC is
	// "one custom OpenAI-compatible provider at the gateway (or the given base
	// URL)", and docs/integrations/pi.md notes models.json takes custom providers
	// speaking the OpenAI shape. A complete base URL is required in that case,
	// because without a provider there is also no base to append a suffix to.
	shape := PiShape{API: defaultPiAPI}
	if p.Provider != pb.GatewayProvider_GATEWAY_PROVIDER_UNSPECIFIED {
		var err error
		if shape, err = PiProviderShape(p.Provider); err != nil {
			return nil, err
		}
	} else if override == "" {
		return nil, fmt.Errorf(
			"rendering %s needs either a gateway provider or a complete --provider-base-url", piModelsPath)
	}

	model := strings.TrimSpace(p.Model)
	if model == "" {
		return nil, fmt.Errorf("a model is required to render %s (pass --model)", piModelsPath)
	}
	tokenVar := strings.TrimSpace(p.TokenEnvVar)
	if tokenVar == "" {
		tokenVar = GatewayTokenEnvVar
	}

	baseURL := override
	if baseURL == "" {
		base := strings.TrimRight(strings.TrimSpace(p.GatewayBase), "/")
		if base == "" {
			return nil, fmt.Errorf("a gateway base URL is required to render %s", piModelsPath)
		}
		baseURL = base + shape.BaseURLSuffix
	}

	cfg := piModelsConfig{
		Providers: map[string]piProviderConfig{
			PiProviderID: {
				Name:    gatewayProviderDisplayName(p.Provider),
				BaseURL: baseURL,
				API:     shape.API,
				APIKey:  "$" + tokenVar,
				Models:  []piModelConfig{{ID: model}},
			},
		},
	}
	blob, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("render %s: %w", piModelsPath, err)
	}
	return append(blob, '\n'), nil
}

// gatewayProviderDisplayName is the human-facing label pi shows in its /model
// picker. It names the gateway first so a user looking at pi's own UI can tell
// the call is brokered rather than direct.
//
// With no provider — the `--credential secret` + `--provider-base-url` case —
// the call is NOT brokered, and the label says so rather than claiming a gateway
// that is not in the path.
func gatewayProviderDisplayName(provider pb.GatewayProvider) string {
	if provider == pb.GatewayProvider_GATEWAY_PROVIDER_UNSPECIFIED {
		return "Containarium (custom endpoint)"
	}
	name := strings.ToLower(strings.ReplaceAll(
		strings.TrimPrefix(provider.String(), "GATEWAY_PROVIDER_"), "_", "-"))
	return "Containarium Model Gateway (" + name + ")"
}
