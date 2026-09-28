package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// TestPiModelsJSON pins the rendered ~/.pi/agent/models.json against a fixture
// taken from pi's OWN documented custom-provider shape.
//
// The shape is not ours, so this test is the drift alarm the design doc asks
// for: it is sourced from @earendil-works/pi-coding-agent@0.87.1 —
// docs/models.md ("Configure a compatible endpoint"), docs/configuration.md
// (the agent directory table), and dist/core/model-config.d.ts, whose exported
// types are literally ModelsJsonProvider / ModelsJsonModel. A pi release that
// renames a field fails HERE, on a laptop, instead of on a customer's box.
func TestPiModelsJSON(t *testing.T) {
	got, err := RenderPiModelsJSON(PiModelsParams{
		Provider:    pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO,
		GatewayBase: "http://10.0.0.1:8866/v1/model/kafeido",
		TokenEnvVar: GatewayTokenEnvVar,
		Model:       "kafeido-coder",
	})
	if err != nil {
		t.Fatalf("RenderPiModelsJSON: %v", err)
	}

	wantPath := filepath.Join("testdata", "pi_models_kafeido.json")
	want, err := os.ReadFile(wantPath) // #nosec G304 -- fixed in-package testdata path
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("rendered models.json does not match %s\n got:\n%s\nwant:\n%s", wantPath, got, want)
	}

	// It must also be valid JSON of exactly the documented shape, so a fixture
	// updated carelessly alongside a bug can't make both sides wrong together.
	var parsed struct {
		Providers map[string]struct {
			Name    string `json:"name"`
			BaseURL string `json:"baseUrl"`
			API     string `json:"api"`
			APIKey  string `json:"apiKey"`
			Models  []struct {
				ID string `json:"id"`
			} `json:"models"`
		} `json:"providers"`
	}
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("rendered models.json is not valid JSON: %v", err)
	}
	p, ok := parsed.Providers[PiProviderID]
	if !ok {
		t.Fatalf("no %q provider in providers map; got keys %v", PiProviderID, parsed.Providers)
	}
	if p.BaseURL != "http://10.0.0.1:8866/v1/model/kafeido/v1" {
		t.Errorf("baseUrl = %q; kafeido is OpenAI-shaped, so the base must carry the upstream's own /v1", p.BaseURL)
	}
	if p.API != "openai-completions" {
		t.Errorf("api = %q, want openai-completions", p.API)
	}
	if len(p.Models) != 1 || p.Models[0].ID != "kafeido-coder" {
		t.Errorf("models = %+v, want exactly [{kafeido-coder}]", p.Models)
	}
}

// TestPiModelsJSON_NeverCarriesTheToken is the AC's "no provider key present
// anywhere on the box" check, asserted at the point the file is produced.
//
// pi's docs state apiKey supports "$NAME or ${NAME} environment
// interpolation", so the reference — not the secret — is what lands in
// models.json. The token only ever reaches ~/.pi/gateway.env (0600).
func TestPiModelsJSON_NeverCarriesTheToken(t *testing.T) {
	const secret = "sk-super-secret-token-value"
	got, err := RenderPiModelsJSON(PiModelsParams{
		Provider:    pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO,
		GatewayBase: "http://10.0.0.1:8866/v1/model/kafeido",
		TokenEnvVar: GatewayTokenEnvVar,
		Model:       "kafeido-coder",
		// Even if a caller mistakenly passes one, nothing must render it.
		Token: secret,
	})
	if err != nil {
		t.Fatalf("RenderPiModelsJSON: %v", err)
	}
	if strings.Contains(string(got), secret) {
		t.Fatalf("models.json carries a live token:\n%s", got)
	}
	if !strings.Contains(string(got), "$"+GatewayTokenEnvVar) {
		t.Errorf("models.json should reference $%s, not a literal key:\n%s", GatewayTokenEnvVar, got)
	}
	if strings.Contains(string(got), "sk-") {
		t.Errorf("models.json contains an sk- prefixed value:\n%s", got)
	}
}

// TestPiProviderMapping_EveryGatewayProviderIsMapped is the "enums over magic
// strings" payoff: a new GatewayProvider enum value cannot ship without
// someone deciding which pi api it speaks and what its base URL suffix is.
// Without this test that decision would be made at runtime, on a box, as a 404.
func TestPiProviderMapping_EveryGatewayProviderIsMapped(t *testing.T) {
	for value, name := range pb.GatewayProvider_name {
		p := pb.GatewayProvider(value)
		if p == pb.GatewayProvider_GATEWAY_PROVIDER_UNSPECIFIED {
			// UNSPECIFIED is an error everywhere else too; assert that.
			if _, err := PiProviderShape(p); err == nil {
				t.Error("UNSPECIFIED must not resolve to a pi provider shape")
			}
			continue
		}
		shape, err := PiProviderShape(p)
		if err != nil {
			t.Errorf("%s has no pi provider shape: %v", name, err)
			continue
		}
		if shape.API == "" {
			t.Errorf("%s maps to an empty pi api", name)
		}
		if !knownPiAPIs[shape.API] {
			t.Errorf("%s maps to api %q, which is not in pi-ai's KnownApi union", name, shape.API)
		}
	}
}

// TestPiProviderShape pins each provider's api + base-URL suffix. These are
// not guesses:
//   - the /v1 rule for OpenAI-shaped upstreams is spelled out in
//     pkg/core/recipes/recipes.yaml ("the base must carry the upstream's own
//     /v1");
//   - gemini-openai's /v1beta/openai is pinned by
//     internal/modelgateway/gateway_test.go's proxy tests;
//   - anthropic and gemini take a bare base because their own SDKs append
//     /v1/messages and /v1beta/models respectively.
func TestPiProviderShape(t *testing.T) {
	tests := []struct {
		provider   pb.GatewayProvider
		wantAPI    string
		wantSuffix string
	}{
		{pb.GatewayProvider_GATEWAY_PROVIDER_ANTHROPIC, "anthropic-messages", ""},
		{pb.GatewayProvider_GATEWAY_PROVIDER_OPENAI, "openai-completions", "/v1"},
		{pb.GatewayProvider_GATEWAY_PROVIDER_GEMINI, "google-generative-ai", ""},
		{pb.GatewayProvider_GATEWAY_PROVIDER_GEMINI_OPENAI, "openai-completions", "/v1beta/openai"},
		{pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO, "openai-completions", "/v1"},
	}
	for _, tc := range tests {
		t.Run(tc.provider.String(), func(t *testing.T) {
			shape, err := PiProviderShape(tc.provider)
			if err != nil {
				t.Fatalf("PiProviderShape: %v", err)
			}
			if shape.API != tc.wantAPI {
				t.Errorf("api = %q, want %q", shape.API, tc.wantAPI)
			}
			if shape.BaseURLSuffix != tc.wantSuffix {
				t.Errorf("suffix = %q, want %q", shape.BaseURLSuffix, tc.wantSuffix)
			}
		})
	}
}

// TestRenderPiModelsJSON_RequiresAModel: pi's /model picker only lists models
// it can resolve, and the gateway token's allowed_models ceiling is
// [model] — so an empty model would mint a token for nothing.
func TestRenderPiModelsJSON_Rejections(t *testing.T) {
	base := PiModelsParams{
		Provider:    pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO,
		GatewayBase: "http://10.0.0.1:8866/v1/model/kafeido",
		TokenEnvVar: GatewayTokenEnvVar,
		Model:       "kafeido-coder",
	}

	noModel := base
	noModel.Model = ""
	if _, err := RenderPiModelsJSON(noModel); err == nil {
		t.Error("an empty model should be rejected")
	}

	noBase := base
	noBase.GatewayBase = ""
	if _, err := RenderPiModelsJSON(noBase); err == nil {
		t.Error("an empty gateway base should be rejected")
	}

	unspecified := base
	unspecified.Provider = pb.GatewayProvider_GATEWAY_PROVIDER_UNSPECIFIED
	if _, err := RenderPiModelsJSON(unspecified); err == nil {
		t.Error("an unspecified provider should be rejected")
	}
}

// TestRenderPiModelsJSON_ProviderBaseURLOverride covers --provider-base-url:
// an operator pointing pi at an endpoint directly instead of at the gateway.
// The override replaces the whole base, suffix included, because the operator
// gave a complete URL.
func TestRenderPiModelsJSON_ProviderBaseURLOverride(t *testing.T) {
	got, err := RenderPiModelsJSON(PiModelsParams{
		Provider:        pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO,
		GatewayBase:     "http://10.0.0.1:8866/v1/model/kafeido",
		BaseURLOverride: "https://api.example.test/v1",
		TokenEnvVar:     GatewayTokenEnvVar,
		Model:           "kafeido-coder",
	})
	if err != nil {
		t.Fatalf("RenderPiModelsJSON: %v", err)
	}
	if !strings.Contains(string(got), `"baseUrl": "https://api.example.test/v1"`) {
		t.Errorf("--provider-base-url override not honoured:\n%s", got)
	}
	if strings.Contains(string(got), "10.0.0.1") {
		t.Errorf("override should replace the gateway base entirely:\n%s", got)
	}
}

// knownPiAPIs is pi-ai's KnownApi union (@earendil-works/pi-ai@0.87.1,
// dist/types.d.ts). Kept in the test rather than in production code: it exists
// to catch us inventing an api value, not to validate operator input.
var knownPiAPIs = map[string]bool{
	"openai-completions":      true,
	"mistral-conversations":   true,
	"openai-responses":        true,
	"azure-openai-responses":  true,
	"openai-codex-responses":  true,
	"anthropic-messages":      true,
	"bedrock-converse-stream": true,
	"google-generative-ai":    true,
	"google-vertex":           true,
	"pi-messages":             true,
}
