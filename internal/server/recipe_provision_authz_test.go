package server

import (
	"context"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// #2504: agents:run "provisions a skill's box and runs a task" (scopes.go),
// but the recipe path's inner create went through the public CreateContainer
// RPC, which re-checked the CALLER for containers:write — so a token holding
// only its documented scope failed the first run of every skill on a daemon.
// The inner create now runs under the daemon's own authority once the entry
// point has authorised the caller; the public RPC and DeployRecipe's own
// entry check are unchanged, and deploy refuses an unauthenticated context.
//
// Same posture as scope_gate_test.go: servers are built with nil deps, so a
// call that clears the gate panics further down — mustPassScope treats that
// as proof the gate is structural.

// agentsRunOnly is the shape of a tracker-dispatch or skill-run credential:
// admin role (AuthorizeTenant on the box name passes), a scopes claim
// present, agents:run and nothing about containers.
func agentsRunOnly(name string) context.Context {
	return auth.ContextWithTestSubjectScopes(context.Background(), name,
		[]string{"admin"}, []string{auth.ScopeAgentsRun})
}

// The seam deploy provisions through must not repeat the caller's scope
// check. Before the fix this returned PermissionDenied "scope required:
// containers:write".
func TestRecipeInnerCreate_DoesNotRecheckCallerForContainersWrite(t *testing.T) {
	boxes := containerServerBoxes{&ContainerServer{}}
	mustPassScope(t, "inner create with agents:run only", func() error {
		_, err := boxes.CreateContainer(agentsRunOnly("cloud-org-dogfood"), &pb.CreateContainerRequest{
			Username: "agent-issue-implementer",
			Image:    recipeBaseImage,
		})
		return err
	})
}

// The wire-facing RPC keeps its gate: agents:run buys nothing there.
func TestCreateContainer_StillRequiresContainersWrite(t *testing.T) {
	srv := &ContainerServer{}
	_, err := srv.CreateContainer(agentsRunOnly("alice"), &pb.CreateContainerRequest{Username: "alice"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("CreateContainer with agents:run only: want PermissionDenied, got %v", err)
	}
}

// DeployRecipe authorises at its own entry, and still with containers:write.
func TestDeployRecipe_StillRequiresContainersWrite(t *testing.T) {
	srv := &RecipeServer{}
	_, err := srv.DeployRecipe(agentsRunOnly("alice"), &pb.DeployRecipeRequest{RecipeId: "some-recipe", Name: "alice"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("DeployRecipe with agents:run only: want PermissionDenied, got %v", err)
	}
}

// With the inner create no longer checking the caller, deploy itself is the
// last line: a context with no authenticated subject must not provision.
func TestRecipeDeploy_RefusesUnauthenticatedContext(t *testing.T) {
	srv := &RecipeServer{}
	_, err := srv.deploy(context.Background(), &pb.DeployRecipeRequest{RecipeId: "some-recipe", Name: "alice"})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("deploy with no subject: want Unauthenticated, got %v", err)
	}
}
