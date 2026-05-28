package server

import (
	"testing"

	"github.com/footprintai/containarium/internal/auth"
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
