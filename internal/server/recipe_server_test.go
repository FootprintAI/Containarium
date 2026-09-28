package server

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/modelgateway"
	"github.com/footprintai/containarium/pkg/core/recipes"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// newTestRecipeServer builds a RecipeServer over the embedded catalog. The
// container/network deps are nil; the tests below exercise only the
// validation/gating paths that run before any backend call.
func newTestRecipeServer() *RecipeServer {
	return &RecipeServer{catalog: recipes.GetDefault()}
}

func TestRecipeServer_DeployRecipe_RejectsMissingScope(t *testing.T) {
	srv := newTestRecipeServer()
	ctx := tenantWithScopes("alice", auth.ScopeContainersRead) // read-only
	_, err := srv.DeployRecipe(ctx, &pb.DeployRecipeRequest{RecipeId: "ollama", Name: "alice"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

func TestRecipeServer_ListRecipes_RejectsMissingScope(t *testing.T) {
	srv := newTestRecipeServer()
	ctx := tenantWithScopes("alice", auth.ScopeSecretsRead) // present but wrong scope
	if _, err := srv.ListRecipes(ctx, &pb.ListRecipesRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v want PermissionDenied", err)
	}
}

func TestRecipeServer_DeployRecipe_UnknownRecipe(t *testing.T) {
	srv := newTestRecipeServer()
	ctx := tenantWithScopes("alice", auth.ScopeContainersWrite)
	_, err := srv.DeployRecipe(ctx, &pb.DeployRecipeRequest{RecipeId: "nope", Name: "alice"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("got %v want NotFound", err)
	}
}

func TestRecipeServer_DeployRecipe_RequiresGPU(t *testing.T) {
	srv := newTestRecipeServer()
	ctx := tenantWithScopes("alice", auth.ScopeContainersWrite)
	// ollama requires_gpu and its only param has a default, so the GPU gate
	// is the first failure when --gpu is omitted.
	_, err := srv.DeployRecipe(ctx, &pb.DeployRecipeRequest{RecipeId: "ollama", Name: "alice"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("got %v want InvalidArgument", err)
	}
}

func TestRecipeServer_DeployRecipe_RequiredParamMissing(t *testing.T) {
	srv := newTestRecipeServer()
	ctx := tenantWithScopes("alice", auth.ScopeContainersWrite)
	// llamacpp's hf_repo is required; parameter resolution runs before the
	// GPU gate, so the missing-param error fires even without --gpu.
	_, err := srv.DeployRecipe(ctx, &pb.DeployRecipeRequest{
		RecipeId:   "llamacpp",
		Name:       "alice",
		Parameters: map[string]string{"hf_repo": ""},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("got %v want InvalidArgument", err)
	}
}

func TestRecipeServer_DeployRecipe_PoolUnsupported(t *testing.T) {
	srv := newTestRecipeServer()
	ctx := tenantWithScopes("alice", auth.ScopeContainersWrite)
	_, err := srv.DeployRecipe(ctx, &pb.DeployRecipeRequest{
		RecipeId: "ollama", Name: "alice", Gpu: "0", Pool: "lab",
	})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("got %v want Unimplemented", err)
	}
}

func TestRecipeServer_DeployRecipe_RemoteBackendUnsupported(t *testing.T) {
	srv := newTestRecipeServer()
	srv.containers = &ContainerServer{peerPool: NewPeerPool("local-test", "", nil, "")}
	ctx := tenantWithScopes("alice", auth.ScopeContainersWrite)
	_, err := srv.DeployRecipe(ctx, &pb.DeployRecipeRequest{
		RecipeId: "ollama", Name: "alice", Gpu: "0", BackendId: "remote-gpu",
	})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("got %v want Unimplemented", err)
	}
}

// A recipe that doesn't opt into the gateway (or whose provider the daemon
// can't broker) seeds no gateway env — the box runs unmanaged.
func TestRecipeServer_GatewayEnv_OptOutAndUnavailable(t *testing.T) {
	s := newTestRecipeServer()
	// No gateway configured at all.
	if got := s.gatewayEnvForRecipe(&pb.Recipe{Id: "r"}, "box1", "gemini-openai", ""); got != "" {
		t.Fatalf("no gateway set: want empty, got %q", got)
	}
	// Gateway set, but recipe doesn't opt in (empty provider).
	s.SetGatewayProvisioning(8080, []byte("secret"), []string{"gemini-openai"})
	if got := s.gatewayEnvForRecipe(&pb.Recipe{Id: "r"}, "box1", "", ""); got != "" {
		t.Fatalf("recipe opted out: want empty, got %q", got)
	}
	// Gateway set, recipe opts into a provider the daemon doesn't broker.
	if got := s.gatewayEnvForRecipe(&pb.Recipe{Id: "r"}, "box1", "anthropic", ""); got != "" {
		t.Fatalf("provider unavailable: want empty, got %q", got)
	}
}

// An opted-in recipe whose provider the daemon brokers gets a gateway env that
// exports the per-provider base URL + a valid scoped token, and that env is
// prepended into the post_start script.
func TestRecipeServer_GatewayEnv_SeedsTokenAndURL(t *testing.T) {
	s := newTestRecipeServer()
	secret := []byte("secret")
	s.SetGatewayProvisioning(8080, secret, []string{"gemini", "gemini-openai"})

	recipe := &pb.Recipe{Id: "agent-workspace", ModelGatewayProvider: "gemini-openai"}
	env := s.gatewayEnvForRecipe(recipe, "box1", "gemini-openai", "")
	if env == "" {
		t.Fatal("want gateway env, got empty")
	}
	if !strings.Contains(env, "/v1/model/gemini-openai") {
		t.Errorf("env missing per-provider base URL: %q", env)
	}
	if !strings.Contains(env, "CONTAINARIUM_MODEL_GATEWAY_URL=") ||
		!strings.Contains(env, "CONTAINARIUM_GATEWAY_TOKEN=") {
		t.Errorf("env missing gateway contract vars: %q", env)
	}
	// The exported token must verify against the gateway secret, scoped to the
	// box + provider.
	tok := extractExport(env, "CONTAINARIUM_GATEWAY_TOKEN")
	claims, err := modelgateway.VerifyToken(secret, tok)
	if err != nil {
		t.Fatalf("seeded token does not verify: %v", err)
	}
	if claims.Provider != "gemini-openai" || claims.Tenant != "box1" {
		t.Errorf("token claims wrong: provider=%q tenant=%q", claims.Provider, claims.Tenant)
	}
	// No inference_provider override was involved, so the claim carries no
	// key_owner — bit-for-bit the pre-#1728 shape (GatewayClaims.KeyOwner doc).
	if claims.KeyOwner != "" {
		t.Errorf("token claims: want no key_owner on the default path, got %q", claims.KeyOwner)
	}

	// The env is prepended into the post_start script.
	script := buildPostStartScript(recipe, map[string]string{}, env)
	if !strings.Contains(script, "CONTAINARIUM_MODEL_GATEWAY_URL=") {
		t.Errorf("post_start script missing gateway env:\n%s", script)
	}
}

// TestResolveRecipeGatewayProvider_EmptyKeepsDefault: an empty (or absent)
// inference_provider parameter keeps the recipe's baked-in ModelGatewayProvider
// and carries no key_owner — the #1728 override is opt-in only.
func TestResolveRecipeGatewayProvider_EmptyKeepsDefault(t *testing.T) {
	recipe := &pb.Recipe{Id: "librechat", ModelGatewayProvider: "gemini-openai"}
	labels := map[string]string{"cloud_org_id": "org-123"}

	for _, params := range []map[string]string{
		nil,
		{},
		{"inference_provider": ""},
	} {
		provider, keyOwner := resolveRecipeGatewayProvider(recipe, "alice", params, labels)
		if provider != "gemini-openai" {
			t.Errorf("params=%v: provider = %q, want recipe default %q", params, provider, "gemini-openai")
		}
		if keyOwner != "" {
			t.Errorf("params=%v: keyOwner = %q, want empty (no override)", params, keyOwner)
		}
	}
}

// TestResolveRecipeGatewayProvider_OverrideCarriesOrgKeyOwner: a non-empty
// inference_provider overrides the recipe's default provider, and when the
// box carries the cloud's cloud_org_id attribution label, the mint's key_owner
// is org:<id> — the "workspace on your own inference key" design's
// "Resolution at mint time".
func TestResolveRecipeGatewayProvider_OverrideCarriesOrgKeyOwner(t *testing.T) {
	recipe := &pb.Recipe{Id: "librechat", ModelGatewayProvider: "gemini-openai"}
	labels := map[string]string{"cloud_org_id": "acme-corp-1"}

	provider, keyOwner := resolveRecipeGatewayProvider(recipe, "alice", map[string]string{"inference_provider": "openai"}, labels)
	if provider != "openai" {
		t.Errorf("provider = %q, want override %q", provider, "openai")
	}
	if want := modelgateway.OrgKeyOwner("acme-corp-1"); keyOwner != want {
		t.Errorf("keyOwner = %q, want %q", keyOwner, want)
	}
}

// TestResolveRecipeGatewayProvider_OverrideFallsBackToUserKeyOwner: without a
// cloud_org_id attribution label (self-hosted daemon), an inference_provider
// override still resolves a key_owner — namespaced to the box's username.
func TestResolveRecipeGatewayProvider_OverrideFallsBackToUserKeyOwner(t *testing.T) {
	recipe := &pb.Recipe{Id: "librechat", ModelGatewayProvider: "gemini-openai"}

	provider, keyOwner := resolveRecipeGatewayProvider(recipe, "alice", map[string]string{"inference_provider": "openai"}, nil)
	if provider != "openai" {
		t.Errorf("provider = %q, want override %q", provider, "openai")
	}
	if want := modelgateway.UserKeyOwner("alice"); keyOwner != want {
		t.Errorf("keyOwner = %q, want %q", keyOwner, want)
	}
}

// TestRecipeServer_GatewayEnv_InferenceProviderOverride_MintsWithKeyOwner:
// end-to-end through gatewayEnvForRecipe — an override to a provider the
// daemon brokers mints a token carrying both the overridden provider and the
// resolved key_owner.
func TestRecipeServer_GatewayEnv_InferenceProviderOverride_MintsWithKeyOwner(t *testing.T) {
	s := newTestRecipeServer()
	secret := []byte("secret")
	s.SetGatewayProvisioning(8080, secret, []string{"gemini-openai", "openai"})

	recipe := &pb.Recipe{Id: "librechat", ModelGatewayProvider: "gemini-openai"}
	labels := map[string]string{"cloud_org_id": "org-42"}
	provider, keyOwner := resolveRecipeGatewayProvider(recipe, "alice", map[string]string{"inference_provider": "openai"}, labels)

	env := s.gatewayEnvForRecipe(recipe, "alice", provider, keyOwner)
	if env == "" {
		t.Fatal("want gateway env, got empty")
	}
	if !strings.Contains(env, "/v1/model/openai") {
		t.Errorf("env missing overridden provider's base URL: %q", env)
	}
	tok := extractExport(env, "CONTAINARIUM_GATEWAY_TOKEN")
	claims, err := modelgateway.VerifyToken(secret, tok)
	if err != nil {
		t.Fatalf("seeded token does not verify: %v", err)
	}
	if claims.Provider != "openai" {
		t.Errorf("claims.Provider = %q, want %q", claims.Provider, "openai")
	}
	if want := modelgateway.OrgKeyOwner("org-42"); claims.KeyOwner != want {
		t.Errorf("claims.KeyOwner = %q, want %q", claims.KeyOwner, want)
	}
}

// TestRecipeServer_GatewayEnv_InferenceProviderOverride_NoKeyDegrades: the
// no-key-for-this-provider degrade path (#1728 acceptance criterion) — an
// override naming a provider the daemon does NOT broker (no key registered for
// it, exactly the pre-existing gate in gatewayEnvForRecipe) produces no gateway
// env at all: the box comes up unconfigured, never with a real key, and the
// daemon logs why.
func TestRecipeServer_GatewayEnv_InferenceProviderOverride_NoKeyDegrades(t *testing.T) {
	s := newTestRecipeServer()
	s.SetGatewayProvisioning(8080, []byte("secret"), []string{"gemini-openai"}) // no "kafeido"

	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	recipe := &pb.Recipe{Id: "librechat", ModelGatewayProvider: "gemini-openai"}
	labels := map[string]string{"cloud_org_id": "org-42"}
	provider, keyOwner := resolveRecipeGatewayProvider(recipe, "alice", map[string]string{"inference_provider": "kafeido"}, labels)

	env := s.gatewayEnvForRecipe(recipe, "alice", provider, keyOwner)
	if env != "" {
		t.Fatalf("want empty gateway env (no key for this provider), got %q", env)
	}
	if !strings.Contains(buf.String(), "kafeido") {
		t.Errorf("want the degrade logged naming the provider, got log: %q", buf.String())
	}

	// The post_start script then carries no gateway env at all, so post_start's
	// own "no gateway seeded" fallback runs — never a real provider key.
	script := buildPostStartScript(recipe, map[string]string{}, env)
	if strings.Contains(script, "CONTAINARIUM_MODEL_GATEWAY_URL") || strings.Contains(script, "CONTAINARIUM_GATEWAY_TOKEN") {
		t.Errorf("post_start script should carry no gateway env on the degrade path:\n%s", script)
	}
}

// TestRecipeServer_DeployRecipe_InvalidInferenceProvider: a deploy-time
// inference_provider value that names no known model-gateway provider is
// rejected with InvalidArgument before any container is provisioned.
func TestRecipeServer_DeployRecipe_InvalidInferenceProvider(t *testing.T) {
	srv := newTestRecipeServer()
	ctx := tenantWithScopes("alice", auth.ScopeContainersWrite)
	_, err := srv.DeployRecipe(ctx, &pb.DeployRecipeRequest{
		RecipeId:   "librechat",
		Name:       "alice",
		Parameters: map[string]string{"inference_provider": "not-a-real-provider"},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("got %v want InvalidArgument", err)
	}
}

// TestRecipeServer_ValidateInferenceProvider: table-driven over the
// known-provider surface validateInferenceProvider checks against — built-ins
// always valid, an operator-registered gateway provider valid once the
// gateway is configured for it, and anything else rejected.
func TestRecipeServer_ValidateInferenceProvider(t *testing.T) {
	cases := []struct {
		name        string
		provider    string
		gatewayUp   bool
		gatewayProv []string
		wantErr     bool
	}{
		{name: "empty always valid, no gateway", provider: "", gatewayUp: false, wantErr: false},
		{name: "built-in valid, no gateway configured", provider: "gemini-openai", gatewayUp: false, wantErr: false},
		{name: "built-in valid, gateway configured for something else", provider: "openai", gatewayUp: true, gatewayProv: []string{"gemini-openai"}, wantErr: false},
		{name: "operator-registered provider valid when the gateway brokers it", provider: "kafeido", gatewayUp: true, gatewayProv: []string{"gemini-openai", "kafeido"}, wantErr: false},
		{name: "operator-registered provider rejected when the gateway doesn't broker it", provider: "kafeido", gatewayUp: true, gatewayProv: []string{"gemini-openai"}, wantErr: true},
		{name: "garbage string rejected", provider: "not-a-real-provider", gatewayUp: false, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestRecipeServer()
			if tc.gatewayUp {
				s.SetGatewayProvisioning(8080, []byte("secret"), tc.gatewayProv)
			}
			err := s.validateInferenceProvider(tc.provider)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateInferenceProvider(%q) error = %v, wantErr %v", tc.provider, err, tc.wantErr)
			}
		})
	}
}

// extractExport pulls the value of `export NAME=<value>` from a shell snippet,
// stripping one layer of single quotes.
func extractExport(script, name string) string {
	for _, line := range strings.Split(script, "\n") {
		prefix := "export " + name + "="
		if strings.HasPrefix(line, prefix) {
			v := strings.TrimPrefix(line, prefix)
			v = strings.TrimSuffix(strings.TrimPrefix(v, "'"), "'")
			return v
		}
	}
	return ""
}
