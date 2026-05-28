package server

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/recipes"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// recipeBaseImage is the LXC image a recipe's dedicated container is built
// from. The recipe's own image runs *inside* it via Podman (post_start),
// mirroring how the kubeflow stack runs k3s inside an LXC.
const recipeBaseImage = "images:ubuntu/24.04"

// RecipeServer implements the gRPC RecipeService. It is pure orchestration:
// DeployRecipe composes the existing CreateContainer + in-container exec +
// route-expose primitives. It lives in package server so it can reuse the
// already-wired ContainerServer (manager, peer pool) and NetworkServer.
type RecipeServer struct {
	pb.UnimplementedRecipeServiceServer
	catalog    *recipes.Manager
	containers *ContainerServer
	network    *NetworkServer // may be nil when app hosting / routing is off
}

// NewRecipeServer wires the recipe service to the existing container and
// network servers. network may be nil; expose then degrades to a warning.
func NewRecipeServer(containers *ContainerServer, network *NetworkServer) *RecipeServer {
	return &RecipeServer{
		catalog:    recipes.GetDefault(),
		containers: containers,
		network:    network,
	}
}

// ListRecipes returns all built-in recipes.
func (s *RecipeServer) ListRecipes(ctx context.Context, _ *pb.ListRecipesRequest) (*pb.ListRecipesResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeContainersRead); err != nil {
		return nil, err
	}
	return &pb.ListRecipesResponse{Recipes: s.catalog.List()}, nil
}

// GetRecipe returns a single recipe by ID.
func (s *RecipeServer) GetRecipe(ctx context.Context, req *pb.GetRecipeRequest) (*pb.GetRecipeResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeContainersRead); err != nil {
		return nil, err
	}
	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	r, err := s.catalog.Get(req.Id)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	return &pb.GetRecipeResponse{Recipe: r}, nil
}

// DeployRecipe provisions a new dedicated container from a recipe, runs the
// recipe's image inside it, and exposes the configured ports.
//
// v1 deploys against the backend that receives the request (the local
// backend). Placing a recipe on a *remote* backend is rejected with a clear
// message rather than silently running post_start against the wrong host —
// to deploy on a GPU node, point --server at that node's daemon. Cross-backend
// orchestration is a deliberate follow-up (the generic peer ForwardRequest has
// a 30s timeout that does not fit long image/model pulls).
func (s *RecipeServer) DeployRecipe(ctx context.Context, req *pb.DeployRecipeRequest) (*pb.DeployRecipeResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeContainersWrite); err != nil {
		return nil, err
	}
	if req.RecipeId == "" {
		return nil, status.Error(codes.InvalidArgument, "recipe_id is required")
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if err := auth.AuthorizeTenant(ctx, req.Name); err != nil {
		return nil, err
	}

	recipe, err := s.catalog.Get(req.RecipeId)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}

	// Resolve + validate parameters (enforces required ones).
	params, err := recipes.ResolveParameters(recipe, req.Parameters)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	// GPU gate: requires_gpu recipes need an explicit device in v1.
	if recipe.RequiresGpu && req.Gpu == "" {
		return nil, status.Errorf(codes.InvalidArgument,
			"recipe %q requires a GPU; pass --gpu (e.g. --gpu 0), deploying against the GPU backend's daemon",
			recipe.Id)
	}

	// v1: reject remote placement rather than running post_start on the wrong host.
	if req.Pool != "" {
		return nil, status.Error(codes.Unimplemented,
			"recipe deploy to a pool is not supported yet; point --server at the target backend's daemon")
	}
	if req.BackendId != "" && s.containers.peerPool != nil &&
		req.BackendId != s.containers.peerPool.LocalBackendID() {
		return nil, status.Errorf(codes.Unimplemented,
			"recipe deploy to remote backend %q is not supported yet; point --server at that backend's daemon",
			req.BackendId)
	}

	// 1. Provision the dedicated container locally (reuses all of
	//    CreateContainer's validation, image allowlist, GPU wiring, etc.).
	createReq := &pb.CreateContainerRequest{
		Username:     req.Name,
		Image:        recipeBaseImage,
		EnablePodman: true,
		Gpu:          req.Gpu,
		Resources:    resourceLimits(recipe, req.ResourceOverrides),
	}
	if _, err := s.containers.CreateContainer(ctx, createReq); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to provision container: %v", err)
	}

	containerName := req.Name + "-container"

	// 2. Run the recipe's post_start commands inside the container, with env
	//    and parameters exported. Same trust level as a stack's post_install.
	if len(recipe.PostStart) > 0 {
		script := buildPostStartScript(recipe, params)
		if err := s.containers.manager.Exec(containerName, []string{"bash", "-c", script}); err != nil {
			return nil, status.Errorf(codes.Internal, "post_start failed on %s: %v", containerName, err)
		}
	}

	// 3. Expose configured ports (best-effort: a routing failure leaves the
	//    workload running and reachable on the LAN; surface it as a warning).
	url, warnings := s.exposePorts(ctx, recipe, req.Name)

	msg := fmt.Sprintf("Recipe %q deployed as %s", recipe.Id, containerName)
	if len(warnings) > 0 {
		msg += "; warnings: " + strings.Join(warnings, "; ")
	}

	info, _ := s.containers.manager.Get(req.Name)
	var container *pb.Container
	if info != nil {
		container = toProtoContainer(info)
	}
	return &pb.DeployRecipeResponse{Container: container, Url: url, Message: msg}, nil
}

// resourceLimits merges the recipe's defaults with deploy-time overrides.
func resourceLimits(recipe *pb.Recipe, override *pb.RecipeResources) *pb.ResourceLimits {
	out := &pb.ResourceLimits{}
	if recipe.Resources != nil {
		out.Cpu = recipe.Resources.Cpu
		out.Memory = recipe.Resources.Memory
		out.Disk = recipe.Resources.Disk
	}
	if override != nil {
		if override.Cpu != "" {
			out.Cpu = override.Cpu
		}
		if override.Memory != "" {
			out.Memory = override.Memory
		}
		if override.Disk != "" {
			out.Disk = override.Disk
		}
	}
	return out
}

// buildPostStartScript assembles a single bash script that exports the
// recipe's static env and resolved parameters, then runs each post_start line.
// Values are single-quote escaped to prevent shell injection from parameters.
func buildPostStartScript(recipe *pb.Recipe, params map[string]string) string {
	var b strings.Builder
	b.WriteString("set -euo pipefail\n")
	for k, v := range recipe.Env {
		fmt.Fprintf(&b, "export %s=%s\n", k, shellSingleQuote(v))
	}
	for name, v := range params {
		fmt.Fprintf(&b, "export %s=%s\n", recipes.ParamEnvName(name), shellSingleQuote(v))
	}
	for _, line := range recipe.PostStart {
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

// shellSingleQuote wraps s in single quotes, escaping embedded single quotes
// the standard POSIX way ('\'' closes, escapes, reopens).
func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// exposePorts registers a route per recipe port and returns the first public
// URL plus any warnings. Routing is best-effort.
func (s *RecipeServer) exposePorts(ctx context.Context, recipe *pb.Recipe, name string) (string, []string) {
	var warnings []string
	if len(recipe.Ports) == 0 {
		return "", nil
	}
	if s.network == nil {
		return "", []string{"routing is not enabled on this daemon; expose ports manually with 'containarium route add'"}
	}
	info, err := s.containers.manager.Get(name)
	if err != nil || info == nil || info.IPAddress == "" {
		return "", []string{fmt.Sprintf("could not resolve container IP to expose ports: %v", err)}
	}

	var url string
	for _, p := range recipe.Ports {
		subdomain := name + "-" + p.Subdomain
		_, err := s.network.AddRoute(ctx, &pb.AddRouteRequest{
			Domain:        subdomain,
			TargetIp:      info.IPAddress,
			TargetPort:    p.ContainerPort,
			ContainerName: info.Name,
			Description:   "recipe:" + recipe.Id,
		})
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("failed to expose port %d: %v", p.ContainerPort, err))
			continue
		}
		if url == "" {
			url = "https://" + resolveFullDomain(subdomain, s.network.baseDomain)
		}
	}
	return url, warnings
}
