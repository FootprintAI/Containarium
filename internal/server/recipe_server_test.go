package server

import (
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
	if got := s.gatewayEnvForRecipe(&pb.Recipe{Id: "r", ModelGatewayProvider: "gemini-openai"}, "box1"); got != "" {
		t.Fatalf("no gateway set: want empty, got %q", got)
	}
	// Gateway set, but recipe doesn't opt in.
	s.SetGatewayProvisioning(8080, []byte("secret"), []string{"gemini-openai"})
	if got := s.gatewayEnvForRecipe(&pb.Recipe{Id: "r"}, "box1"); got != "" {
		t.Fatalf("recipe opted out: want empty, got %q", got)
	}
	// Gateway set, recipe opts into a provider the daemon doesn't broker.
	if got := s.gatewayEnvForRecipe(&pb.Recipe{Id: "r", ModelGatewayProvider: "anthropic"}, "box1"); got != "" {
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
	env := s.gatewayEnvForRecipe(recipe, "box1")
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

	// The env is prepended into the post_start script.
	script := buildPostStartScript(recipe, map[string]string{}, env)
	if !strings.Contains(script, "CONTAINARIUM_MODEL_GATEWAY_URL=") {
		t.Errorf("post_start script missing gateway env:\n%s", script)
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
