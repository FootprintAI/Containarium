package server

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/modelgateway"
	boxlxc "github.com/footprintai/containarium/pkg/core/box/lxc"
	"github.com/footprintai/containarium/pkg/core/recipes"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// recipeBaseImage is the LXC image a recipe's dedicated container is built
// from. The recipe's own image runs *inside* it via Podman (post_start),
// mirroring how the kubeflow stack runs k3s inside an LXC.
const recipeBaseImage = "images:ubuntu/24.04"

// recipeGatewayTokenTTL bounds a workspace recipe's gateway token. Unlike a
// skill run (minutes), a recipe box like agent-workspace is long-lived, so the
// token must outlive a session — here a year. The kill-switch is revocation
// (#752), not expiry; refreshing a live box's token is a follow-up.
const recipeGatewayTokenTTL = 365 * 24 * time.Hour

// recipeGateway is what RecipeServer needs to broker a recipe's model calls
// through the daemon's model-gateway: the daemon HTTP port the box dials, the
// HMAC secret that signs the scoped token, and the set of providers the gateway
// actually brokers (has a key for). nil ⇒ no gateway ⇒ recipes run unmanaged.
type recipeGateway struct {
	httpPort  int
	secret    []byte
	providers map[string]bool
}

// RecipeServer implements the gRPC RecipeService. It is pure orchestration:
// DeployRecipe composes the existing CreateContainer + in-container exec +
// route-expose primitives. It lives in package server so it can reuse the
// already-wired ContainerServer (manager, peer pool) and NetworkServer.
type RecipeServer struct {
	pb.UnimplementedRecipeServiceServer
	catalog    *recipes.Manager
	containers *ContainerServer
	network    *NetworkServer // may be nil when app hosting / routing is off
	gateway    *recipeGateway // nil unless the daemon serves the model-gateway
}

// SetGatewayProvisioning enables managed model-gateway seeding for recipes that
// opt in (recipe.ModelGatewayProvider). Called by the daemon when it holds a
// provider key; mirrors AgentSkillServer.SetGatewayProvisioning for the skill
// path. providers is the set the gateway brokers.
func (s *RecipeServer) SetGatewayProvisioning(httpPort int, secret []byte, providers []string) {
	set := make(map[string]bool, len(providers))
	for _, p := range providers {
		set[p] = true
	}
	s.gateway = &recipeGateway{httpPort: httpPort, secret: secret, providers: set}
}

// gatewayEnvForRecipe returns the shell snippet that exports the managed
// model-gateway env into a recipe's post_start, or "" when the recipe doesn't
// opt in / the daemon can't broker its provider. It mints a long-lived scoped
// token bound to this box + recipe + provider. Best-effort: a mint failure logs
// and degrades to unmanaged (the box still comes up, just unconfigured).
func (s *RecipeServer) gatewayEnvForRecipe(recipe *pb.Recipe, boxName string) string {
	prov := recipe.ModelGatewayProvider
	if prov == "" || s.gateway == nil {
		return ""
	}
	if !s.gateway.providers[prov] {
		log.Printf("[recipe] %q requests model-gateway provider %q but the daemon holds no key for it; box comes up unconfigured", recipe.Id, prov)
		return ""
	}
	tok, err := modelgateway.MintToken(s.gateway.secret, modelgateway.GatewayClaims{
		Tenant:   boxName,
		SkillID:  recipe.Id,
		Provider: prov,
	}, recipeGatewayTokenTTL)
	if err != nil {
		log.Printf("[recipe] mint gateway token for %s failed (box runs unmanaged): %v", boxName, err)
		return ""
	}
	return gatewayRecipeEnvExports(prov, s.gateway.httpPort, tok)
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

// GetWorkspaceAccess returns a zero-click bootstrap URL for an agent-workspace
// box: it reads the box's in-box auth proxy token (written to
// /opt/wsauth/token by the agent-workspace recipe) and composes the
// /__ws_login URL the console embeds in an iframe to authenticate the
// workspace UI without showing a sign-in prompt.
func (s *RecipeServer) GetWorkspaceAccess(ctx context.Context, req *pb.GetWorkspaceAccessRequest) (*pb.GetWorkspaceAccessResponse, error) {
	// containers:write, not read: this mints an interactive-access credential
	// (the in-box session token + a zero-click /__ws_login URL), so it is a
	// write-class operation — a read-only token must not be able to obtain it.
	if err := auth.RequireScope(ctx, auth.ScopeContainersWrite); err != nil {
		return nil, err
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if err := auth.AuthorizeTenant(ctx, req.Name); err != nil {
		return nil, err
	}

	containerName := req.Name + "-container"
	stdout, _, err := s.containers.manager.ExecWithOutput(containerName, []string{"cat", "/opt/wsauth/token"})
	if err != nil {
		return nil, status.Errorf(codes.NotFound,
			"no workspace token on %s (is this an agent-workspace box?): %v", containerName, err)
	}
	token := strings.TrimSpace(stdout)
	if token == "" {
		return nil, status.Errorf(codes.NotFound, "empty workspace token on %s", containerName)
	}

	resp := &pb.GetWorkspaceAccessResponse{Token: token}
	// Only compose a URL when routing is actually configured (same precondition
	// as exposePorts): without a base domain the URL would be domain-less and
	// unusable, so return just the token and let the caller surface that.
	if s.network != nil && s.network.baseDomain != "" {
		// Mirror exposePorts' subdomain scheme: "<name>-workspace".
		subdomain := req.Name + "-workspace"
		resp.Url = "https://" + resolveFullDomain(subdomain, s.network.baseDomain) +
			"/__ws_login?t=" + url.QueryEscape(token)
	}
	return resp, nil
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
	return s.deploy(ctx, req)
}

// deploy is the provisioning body shared by DeployRecipe and the
// AgentSkillService. Callers must perform their own authorization first;
// the inner CreateContainer still enforces containers:write + tenant authz.
func (s *RecipeServer) deploy(ctx context.Context, req *pb.DeployRecipeRequest) (*pb.DeployRecipeResponse, error) {
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
	//    Caller labels (e.g. a control plane's tenant-attribution labels) are
	//    forwarded so a recipe-deployed box is labeled the same as a plain
	//    CreateContainer — otherwise a label-filtering front-end can't see it.
	createReq := &pb.CreateContainerRequest{
		Username:     req.Name,
		Image:        recipeBaseImage,
		EnablePodman: true,
		Resources:    resourceLimits(recipe, req.ResourceOverrides),
		Labels:       req.Labels,
	}
	// A recipe requests a single GPU device; map it onto the container's
	// repeated `gpus` (the singular `gpu` is no longer honored — #673).
	if req.Gpu != "" {
		createReq.Gpus = []string{req.Gpu}
	}
	if _, err := s.containers.CreateContainer(ctx, createReq); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to provision container: %v", err)
	}

	containerName := req.Name + "-container"

	// Managed model-gateway: if the recipe opts in and the daemon brokers its
	// provider, mint a scoped token + env exports to prepend to post_start (so
	// the box uses the platform key, metered, never leaked). "" otherwise.
	gatewayEnv := s.gatewayEnvForRecipe(recipe, req.Name)

	// Async path: decouple post_start from the RPC. A recipe's post_start can
	// pull multi-GB images (e.g. agent-workspace), taking longer than the
	// request/idle timeout of a caller reaching this daemon through a peer-proxy
	// — holding the call open would get it cut mid-pull, aborting the deploy.
	// Run post_start (and the port expose) in the background on a detached
	// context and return the freshly-created box now (state CREATING). The box
	// becomes fully functional once post_start completes; the caller polls.
	if req.Async {
		go func() {
			bg := context.WithoutCancel(ctx)
			if len(recipe.PostStart) > 0 {
				script := buildPostStartScript(recipe, params, gatewayEnv)
				if err := s.containers.manager.Exec(containerName, []string{"bash", "-c", script}); err != nil {
					log.Printf("[recipe] async post_start failed on %s (recipe %q): %v", containerName, recipe.Id, err)
					return
				}
			}
			if _, warnings := s.exposePorts(bg, recipe, req.Name); len(warnings) > 0 {
				log.Printf("[recipe] async expose warnings on %s: %s", containerName, strings.Join(warnings, "; "))
			}
		}()
		info, _ := s.containers.manager.Get(req.Name)
		var container *pb.Container
		if info != nil {
			st := boxlxc.StatusFromInfo(info)
			container = toProtoContainer(&st)
		}
		return &pb.DeployRecipeResponse{
			Container: container,
			Message:   fmt.Sprintf("Recipe %q deploying as %s (post_start running in background)", recipe.Id, containerName),
		}, nil
	}

	// 2. Run the recipe's post_start commands inside the container, with env
	//    and parameters exported. Same trust level as a stack's post_install.
	if len(recipe.PostStart) > 0 {
		script := buildPostStartScript(recipe, params, gatewayEnv)
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
		st := boxlxc.StatusFromInfo(info)
		container = toProtoContainer(&st)
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
// gatewayEnv, when non-empty, is the managed model-gateway export snippet
// (gatewayEnvForRecipe) prepended before the recipe's own env so post_start
// sees CONTAINARIUM_MODEL_GATEWAY_URL/_TOKEN.
func buildPostStartScript(recipe *pb.Recipe, params map[string]string, gatewayEnv string) string {
	var b strings.Builder
	b.WriteString("set -euo pipefail\n")
	if gatewayEnv != "" {
		b.WriteString(gatewayEnv)
	}
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
// the standard POSIX way ('\” closes, escapes, reopens).
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
