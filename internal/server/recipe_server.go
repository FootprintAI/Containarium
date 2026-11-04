package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/guardrailpolicy"
	"github.com/footprintai/containarium/internal/guardrailrate"
	"github.com/footprintai/containarium/internal/guardrailstage"
	"github.com/footprintai/containarium/internal/limitio"
	"github.com/footprintai/containarium/internal/modelgateway"
	boxlxc "github.com/footprintai/containarium/pkg/core/box/lxc"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/recipes"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/footprintai/containarium/pkg/version"
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
	boxes      recipeBoxes    // nil = the ContainerServer; tests substitute a fake

	// postStartRetry serialises re-running a box's unfinished post_start
	// (#3546, rerunPendingPostStart): box name -> *sync.Mutex, so two runs
	// that find the same not-ready box do not run post_start at once.
	postStartRetry sync.Map

	// The guardrail deploy gate (#2368, recipe_guardrail_gate.go). nil
	// provider or "" root: a gated recipe is refused; ungated recipes are
	// unaffected.
	guardrailPolicy      guardrailpolicy.PolicyProvider
	guardrailStagingRoot string
	// guardrailSnapshotParent is where verification snapshots are made ("" =
	// os.TempDir(); --guardrail-snapshot-dir). guardrailSnapshot makes them
	// (nil = the stager's Snapshot; a seam for tests).
	guardrailSnapshotParent string
	guardrailSnapshot       func(area *guardrailstage.Area, ref, parent string) (*guardrailstage.Snapshot, error)
	// guardrailDeployLimit rate-limits gated deploys per subject (#2404;
	// nil = disabled).
	guardrailDeployLimit *guardrailrate.Limiter
}

// recipeBoxes is the box surface deploy drives.
type recipeBoxes interface {
	CreateContainer(ctx context.Context, req *pb.CreateContainerRequest) (*pb.CreateContainerResponse, error)
	Exec(containerName string, command []string) error
	// ExecWithExitCode runs a command in the box and reports its exit status
	// as data. post_start runs through it (#3542): Exec reports success
	// whatever the command's exit status, so a failed post_start went
	// unreported.
	ExecWithExitCode(containerName string, command []string) (stdout, stderr string, exitCode int, err error)
	// ExecWithOutput runs a command in the box and returns its stdout and
	// stderr (GetWorkspaceAccess reads the box's login token with it).
	ExecWithOutput(containerName string, command []string) (string, string, error)
	// PushFile streams a file into the box (never buffering it whole).
	PushFile(containerName, path string, content io.ReadSeeker, mode string) error
	Get(username string) (*incus.ContainerInfo, error)
	// SetConfig and UnsetConfig write and remove one Incus config key on the
	// box. deploy records with them whether post_start completed (#3546).
	SetConfig(containerName, key, value string) error
	UnsetConfig(containerName, key string) error
}

// containerServerBoxes is recipeBoxes over the daemon's ContainerServer.
type containerServerBoxes struct{ s *ContainerServer }

// CreateContainer provisions under the daemon's own authority: deploy's
// callers authorise the caller for the box name before they get here (see
// deploy), so the public RPC's containers:write check is not repeated
// against the caller's claims (#2504). Going through the RPC made an
// agents:run-only token fail the first run of every skill on a daemon.
func (c containerServerBoxes) CreateContainer(ctx context.Context, req *pb.CreateContainerRequest) (*pb.CreateContainerResponse, error) {
	return c.s.createContainerAuthorized(ctx, req)
}
func (c containerServerBoxes) Exec(name string, command []string) error {
	return c.s.manager.Exec(name, command)
}
func (c containerServerBoxes) ExecWithExitCode(name string, command []string) (string, string, int, error) {
	return c.s.manager.ExecWithExitCode(name, command)
}
func (c containerServerBoxes) ExecWithOutput(name string, command []string) (string, string, error) {
	return c.s.manager.ExecWithOutput(name, command)
}
func (c containerServerBoxes) PushFile(name, path string, content io.ReadSeeker, mode string) error {
	return c.s.manager.PushFile(name, path, content, mode)
}
func (c containerServerBoxes) Get(username string) (*incus.ContainerInfo, error) {
	return c.s.manager.Get(username)
}
func (c containerServerBoxes) SetConfig(name, key, value string) error {
	return c.s.manager.SetConfig(name, key, value)
}
func (c containerServerBoxes) UnsetConfig(name, key string) error {
	return c.s.manager.UnsetConfig(name, key)
}

func (s *RecipeServer) boxOps() recipeBoxes {
	if s.boxes != nil {
		return s.boxes
	}
	return containerServerBoxes{s.containers}
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

// inferenceProviderParam is the librechat recipe parameter (#1728) that lets a
// deploy choose which model-gateway provider the workspace runs on, instead of
// always using the recipe's baked-in ModelGatewayProvider. Empty keeps that
// default; set, it overrides the provider gatewayEnvForRecipe mints for and
// the mint carries the box's key_owner (see resolveRecipeGatewayProvider).
const inferenceProviderParam = "inference_provider"

// validateInferenceProvider rejects an inference_provider value that names no
// provider this daemon's model-gateway package knows how to speak to. Empty is
// always valid (it keeps the recipe's own model_gateway_provider default).
//
// There is no proto GatewayProvider enum in this repo to validate against yet:
// the design doc ("workspace on your own inference key" cloud repo, §C1) puts
// it in a new OSS proto (proto/containarium/v1/model_gateway.proto), and that
// lands with #1726 (ModelGatewayService), unmerged as of this change and out
// of this issue's scope. Validating against code that doesn't exist isn't
// possible, so this checks against modelgateway's own known-provider surface
// instead: the compiled-in providers (DefaultProviders — always valid, even on
// a daemon with no gateway configured) plus, when this daemon serves the
// gateway, whatever it additionally brokers (an operator-registered
// <NAME>_UPSTREAM_URL provider, ProvidersFromEnv). A value outside both is
// rejected. Whether the daemon actually HOLDS A KEY for an otherwise-valid
// provider is a separate, later question — gatewayEnvForRecipe's degrade path
// below, not this validation.
func (s *RecipeServer) validateInferenceProvider(name string) error {
	if name == "" {
		return nil
	}
	if _, ok := modelgateway.DefaultProviders()[name]; ok {
		return nil
	}
	if s.gateway != nil && s.gateway.providers[name] {
		return nil
	}
	return fmt.Errorf("inference_provider %q is not a recognized model-gateway provider", name)
}

// resolveRecipeGatewayProvider returns the model-gateway provider a recipe
// deploy targets and, when the deploy overrides it via the inference_provider
// parameter, the key_owner the mint should carry.
//
// Empty inference_provider keeps the recipe's baked-in ModelGatewayProvider
// and returns no key_owner: the mint below then carries no KeyOwner claim,
// which is bit-for-bit the pre-#1728 behavior (modelgateway.GatewayClaims.
// KeyOwner's doc: a token without the claim resolves through the
// daemon-global key exactly as it always has). Set, it overrides the provider
// and stamps key_owner from this box's cloud-org attribution (cloudOrgIDLabel,
// the same label network_policy_enforcer.go reads) when the cloud stamped one
// at CreateContainer, else the self-hosted username — mirroring the design
// doc's "Resolution at mint time" for MintGatewayToken (#1726), implemented
// here directly since the recipe path mints through modelgateway.MintToken,
// not through that (unmerged) RPC.
func resolveRecipeGatewayProvider(recipe *pb.Recipe, boxName string, params, labels map[string]string) (provider, keyOwner string) {
	provider = recipe.ModelGatewayProvider
	override := strings.TrimSpace(params[inferenceProviderParam])
	if override == "" {
		return provider, ""
	}
	return override, recipeKeyOwner(labels, boxName)
}

// recipeKeyOwner resolves the key_owner a recipe deploy's gateway mint should
// carry: org:<cloud_org_id> when the box carries the cloud's attribution
// label, else user:<boxName> for a self-hosted daemon. Falls back to "" (no
// key_owner claim — the mint then behaves as it did before #1728, resolving
// through the daemon-global key) if the computed owner is somehow malformed,
// rather than failing the deploy over it.
func recipeKeyOwner(labels map[string]string, boxName string) string {
	if orgID := strings.TrimSpace(labels[cloudOrgIDLabel]); orgID != "" {
		owner := modelgateway.OrgKeyOwner(orgID)
		if err := modelgateway.ValidateKeyOwner(owner); err == nil {
			return owner
		}
		log.Printf("[recipe] cloud_org_id label %q on %q does not form a valid key_owner; falling back to the self-hosted username", orgID, boxName)
	}
	owner := modelgateway.UserKeyOwner(boxName)
	if err := modelgateway.ValidateKeyOwner(owner); err != nil {
		log.Printf("[recipe] box name %q does not form a valid key_owner (%v); minting with no key_owner claim", boxName, err)
		return ""
	}
	return owner
}

// gatewayEnvForRecipe returns the shell snippet that exports the managed
// model-gateway env into a recipe's post_start, or "" when the recipe doesn't
// opt in / the daemon can't broker its provider. It mints a long-lived scoped
// token bound to this box + recipe + provider (and, when keyOwner is set, that
// owner's key — see resolveRecipeGatewayProvider). Best-effort: a mint failure
// logs and degrades to unmanaged (the box still comes up, just unconfigured).
func (s *RecipeServer) gatewayEnvForRecipe(recipe *pb.Recipe, boxName, provider, keyOwner string) string {
	if provider == "" || s.gateway == nil {
		return ""
	}
	if !s.gateway.providers[provider] {
		log.Printf("[recipe] %q requests model-gateway provider %q but the daemon holds no key for it; box comes up unconfigured", recipe.Id, provider)
		return ""
	}
	tok, err := modelgateway.MintToken(s.gateway.secret, modelgateway.GatewayClaims{
		Tenant:   boxName,
		SkillID:  recipe.Id,
		Provider: provider,
		KeyOwner: keyOwner,
	}, recipeGatewayTokenTTL)
	if err != nil {
		log.Printf("[recipe] mint gateway token for %q failed (box runs unmanaged): %v", boxName, err)
		return ""
	}
	return gatewayRecipeEnvExports(provider, s.gateway.httpPort, tok)
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

// workspaceMint is the body the slides-agent login helper answers /__mint with
// (images/slides-agent/wsauth). A JSON object, where the librechat helper
// prints the bare token, marks a box whose proxy takes the token in the URL
// fragment (#3486).
type workspaceMint struct {
	Token string `json:"token"`
}

// fragmentTokenPattern is the slides-agent helper's token shape (32 random
// bytes, unpadded base64url): safe in a URL fragment without escaping.
var fragmentTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// bareTokenPattern is the shape a bare-token /__mint body must have to be
// used: the chat workspace helper's secrets.token_urlsafe(24) is 32
// base64url characters. Anything else (an error message, an HTML page) is a
// failed probe, never a token in a URL.
var bareTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{32,128}$`)

// parseWorkspaceMint returns the token of a slides-agent /__mint body, or ""
// when the body is not one.
func parseWorkspaceMint(body string) string {
	var m workspaceMint
	if json.Unmarshal([]byte(body), &m) != nil || !fragmentTokenPattern.MatchString(m.Token) {
		return ""
	}
	return m.Token
}

// GetWorkspaceAccess returns a zero-click bootstrap URL for a workspace box
// (librechat, slides-agent or agent-workspace): it obtains the box's in-box
// auth token — minted single-use by the librechat or slides-agent helper, or
// read from the static /opt/wsauth/token for agent-workspace — and composes the
// /__ws_login URL the console embeds in an iframe to authenticate the workspace
// UI without showing a sign-in prompt.
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

	// Three workspace flavours expose a /__ws_login bootstrap, with different
	// token semantics:
	//   * librechat: an in-box helper mints a SINGLE-USE, short-lived token on
	//     127.0.0.1:9099/__mint and does a fresh LibreChat login per access
	//     (LibreChat rotates its refresh token, so a session can't be replayed).
	//     It prints the bare token; the URL carries it as ?t=. Its exposed
	//     subdomain is "<name>-chat".
	//   * slides-agent: an in-box helper on the same port and path mints a
	//     SINGLE-USE, 120 s token and answers {"token":"..."}. The URL carries
	//     it in the fragment (#t=), which a browser never sends; the proxy's
	//     bootstrap page posts it. Its subdomain is "<name>-workspace".
	//   * agent-workspace (and slides-agent boxes from before #3486): a STATIC
	//     per-box token in /opt/wsauth/token (the proxy IS the auth), as ?t=.
	//     Its subdomain is "<name>-workspace".
	// Probe the helper first (preferred, single-use); fall back to the static
	// token so every recipe shape works without the daemon tracking the recipe.
	// curl -f: an HTTP error from a helper (e.g. 503 at its pending-token cap)
	// is a failed probe, and a 2xx body that is not a well-formed token is
	// treated the same; neither ever becomes a URL.
	var token, subdomain string
	inFragment := false
	if out, _, err := s.boxOps().ExecWithOutput(containerName,
		[]string{"curl", "-sf", "--max-time", "3", "http://127.0.0.1:9099/__mint"}); err == nil {
		t := strings.TrimSpace(out)
		switch {
		case strings.HasPrefix(t, "{"):
			if ft := parseWorkspaceMint(t); ft != "" {
				token, subdomain, inFragment = ft, req.Name+"-workspace", true
			}
		case bareTokenPattern.MatchString(t):
			token, subdomain = t, req.Name+"-chat"
		}
	}
	if token == "" {
		out, _, err := s.boxOps().ExecWithOutput(containerName, []string{"cat", "/opt/wsauth/token"})
		if err != nil {
			return nil, status.Errorf(codes.NotFound,
				"no workspace access on %s (is this a workspace box?): %v", containerName, err)
		}
		token, subdomain = strings.TrimSpace(out), req.Name+"-workspace"
	}
	if token == "" {
		return nil, status.Errorf(codes.NotFound, "empty workspace token on %s", containerName)
	}

	resp := &pb.GetWorkspaceAccessResponse{Token: token}
	// Only compose a URL when routing is actually configured (same precondition
	// as exposePorts): without a base domain the URL would be domain-less and
	// unusable, so return just the token and let the caller surface that. (On the
	// cloud the ossshim passthrough rebuilds the URL with the box's managed
	// subdomain; this URL is for self-hosted OSS.)
	if s.network != nil && s.network.baseDomain != "" {
		login := "/__ws_login?t=" + url.QueryEscape(token)
		if inFragment {
			login = "/__ws_login#t=" + token
		}
		resp.Url = "https://" + resolveFullDomain(subdomain, s.network.baseDomain) + login
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

// deploy is the provisioning body shared by DeployRecipe and the skill and
// crew run paths. Every caller MUST authorise the caller for req.Name before
// calling it — DeployRecipe with containers:write, a skill run with
// agents:run and a crew run with crews:run, each followed by
// AuthorizeTenant(ctx, req.Name) — because the create below runs under the
// daemon's own authority and does not re-check the caller's scopes (#2504).
// What is left here is the one check no caller can forget on our behalf: an
// authenticated subject must be present at all.
func (s *RecipeServer) deploy(ctx context.Context, req *pb.DeployRecipeRequest) (*pb.DeployRecipeResponse, error) {
	if _, _, ok := auth.SubjectFromGRPCContext(ctx); !ok {
		return nil, status.Error(codes.Unauthenticated, "no authenticated subject in request context")
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
	if err := s.validateInferenceProvider(params[inferenceProviderParam]); err != nil {
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

	// Guardrail gate (#2368): verified BEFORE the container exists, so a
	// refused deploy leaves nothing behind. dataset is the verified
	// snapshot; it is what gets copied into the box below.
	var dataset *guardrailstage.Snapshot
	if recipe.GetGuardrailGate() != nil {
		if dataset, err = s.checkGuardrailGate(ctx, recipe, req); err != nil {
			return nil, err
		}
		defer func() {
			if err := dataset.Remove(); err != nil {
				log.Printf("[recipe] remove guardrail snapshot %s: %v", dataset.Dir, err)
			}
		}()
	}

	// 1. Provision the dedicated container locally (reuses all of
	//    CreateContainer's validation, image allowlist, GPU wiring, etc. —
	//    everything but its scope check, see containerServerBoxes).
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
	if _, err := s.boxOps().CreateContainer(ctx, createReq); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to provision container: %v", err)
	}

	containerName := req.Name + "-container"

	// Record that the box is not prepared yet BEFORE anything else runs in
	// it (#3546). Only a post_start that succeeds removes the mark, so a
	// failed post_start, or a daemon that stops while it runs, leaves the box
	// marked, and a skill or crew run that would reuse it runs post_start
	// again (rerunPendingPostStart) instead of skipping it.
	if len(recipe.PostStart) > 0 {
		markPostStartPending(s.boxOps(), containerName)
	}

	// Gated: place exactly the verified bytes at dataset_path before
	// post_start. (Async is refused for a gated recipe, so this always
	// precedes post_start.)
	if dataset != nil {
		if err := deliverGuardrailDataset(s.boxOps(), containerName, recipe.GetGuardrailGate().GetDatasetPath(), dataset.Dir); err != nil {
			log.Printf("[recipe] guardrail gate: deliver dataset to %q: %v", containerName, err)
			return nil, status.Errorf(codes.Internal, "could not deliver the verified dataset to %s", containerName)
		}
	}

	// Managed model-gateway: if the recipe opts in (or the deploy overrides the
	// provider via inference_provider, #1728) and the daemon brokers that
	// provider, mint a scoped token + env exports to prepend to post_start (so
	// the box uses the platform key, metered, never leaked). "" otherwise.
	provider, keyOwner := resolveRecipeGatewayProvider(recipe, req.Name, params, req.Labels)
	gatewayEnv := s.gatewayEnvForRecipe(recipe, req.Name, provider, keyOwner)

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
				if err := completePostStart(s.boxOps(), containerName, script); err != nil {
					note := ""
					if len(recipe.Ports) > 0 {
						note = "; ports were not exposed"
					}
					log.Printf("[recipe] async post_start failed on %q (recipe %q): %v%s", containerName, recipe.Id, err, note)
					return
				}
			}
			if _, _, warnings := s.exposePorts(bg, recipe, req.Name); len(warnings) > 0 {
				log.Printf("[recipe] async expose warnings on %q: %q", containerName, strings.Join(warnings, "; "))
			}
		}()
		info, _ := s.boxOps().Get(req.Name)
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
		if err := completePostStart(s.boxOps(), containerName, script); err != nil {
			return nil, status.Errorf(codes.Internal, "post_start failed on %s: %v", containerName, err)
		}
	}

	// A failed post_start returned above, so no route is exposed for a
	// workload that did not finish starting (fail closed, #3545).
	//
	// 3. Expose configured ports (best-effort: a routing failure leaves the
	//    workload running and reachable on the LAN; surface it as a warning).
	url, endpoints, warnings := s.exposePorts(ctx, recipe, req.Name)

	msg := fmt.Sprintf("Recipe %q deployed as %s", recipe.Id, containerName)
	if len(endpoints) > 0 {
		msg += "; passthrough: " + strings.Join(endpoints, ", ")
	}
	if len(warnings) > 0 {
		msg += "; warnings: " + strings.Join(warnings, "; ")
	}

	info, _ := s.boxOps().Get(req.Name)
	var container *pb.Container
	if info != nil {
		st := boxlxc.StatusFromInfo(info)
		container = toProtoContainer(&st)
	}
	return &pb.DeployRecipeResponse{Container: container, Url: url, Message: msg}, nil
}

// markPostStartPending sets the post_start-pending mark on a box (#3546). A
// failure to write it is logged and the deploy goes on: refusing here would
// leave a box that exists, is unmarked and never ran post_start, which is
// the state the mark exists to prevent.
func markPostStartPending(boxes recipeBoxes, containerName string) {
	if err := boxes.SetConfig(containerName, incus.PostStartPendingKey, incus.PostStartPendingValue); err != nil {
		log.Printf("[recipe] could not mark %q as not prepared before post_start: %v", containerName, err)
	}
}

// completePostStart runs post_start and, only when it succeeds, removes the
// post_start-pending mark (#3546). A failure to remove the mark is logged and
// not returned: post_start did complete, and a mark left behind costs one
// extra post_start run on the box's next skill run, not a wrong result.
func completePostStart(boxes recipeBoxes, containerName, script string) error {
	if err := runPostStart(boxes, containerName, script); err != nil {
		return err
	}
	if err := boxes.UnsetConfig(containerName, incus.PostStartPendingKey); err != nil {
		log.Printf("[recipe] post_start completed on %q but its not-prepared mark could not be removed: %v", containerName, err)
	}
	return nil
}

// rerunPendingPostStart is the reuse half of the post_start-pending mark
// (#3546). A skill or crew run that is about to reuse box name (the
// daemon-provisioned agent-<skill> box) calls it; when the box still carries
// the mark, the recipe's post_start runs again with the parameters the first
// deploy used, and the mark is removed only if it succeeds. A box without the
// mark (prepared, or one deploy never marked) is left alone. When post_start
// fails again the box is kept for debugging and the run fails with
// FailedPrecondition naming the box; deleting the box makes the next run
// provision a fresh one.
//
// A guardrail-gated recipe is not re-run: its dataset is verified and
// delivered as part of a deploy, and re-running post_start over whatever is
// in the box now would skip that check. The run fails with the same advice.
func (s *RecipeServer) rerunPendingPostStart(ctx context.Context, recipeID, name string, parameters map[string]string) error {
	lock, _ := s.postStartRetry.LoadOrStore(name, &sync.Mutex{})
	mu := lock.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()

	// Re-read under the lock: a concurrent run may have finished it.
	info, err := s.boxOps().Get(name)
	if err != nil || info == nil || !info.PostStartPending {
		return nil
	}
	containerName := name + "-container"
	notPrepared := func(format string, args ...any) error {
		return status.Errorf(codes.FailedPrecondition,
			"box %s is not fully prepared: its recipe post_start did not complete on an earlier run and %s; the box is kept for debugging, delete it to provision a fresh one",
			containerName, fmt.Sprintf(format, args...))
	}
	recipe, err := s.catalog.Get(recipeID)
	if err != nil {
		return notPrepared("its recipe %q is no longer in the catalog", recipeID)
	}
	if recipe.GetGuardrailGate() != nil {
		return notPrepared("recipe %q is guardrail-gated, so post_start is not re-run on an existing box", recipeID)
	}
	params, err := recipes.ResolveParameters(recipe, parameters)
	if err != nil {
		return notPrepared("its parameters no longer resolve: %v", err)
	}
	if len(recipe.PostStart) == 0 {
		// Nothing left to run: the recipe no longer has a post_start.
		if err := s.boxOps().UnsetConfig(containerName, incus.PostStartPendingKey); err != nil {
			log.Printf("[recipe] could not remove the not-prepared mark from %q: %v", containerName, err)
		}
		return nil
	}
	provider, keyOwner := resolveRecipeGatewayProvider(recipe, name, params, nil)
	script := buildPostStartScript(recipe, params, s.gatewayEnvForRecipe(recipe, name, provider, keyOwner))
	log.Printf("[recipe] %q was not fully prepared by an earlier run; running post_start again", containerName)
	if err := completePostStart(s.boxOps(), containerName, script); err != nil {
		return notPrepared("running it again failed: %v", err)
	}
	// The first deploy returned before exposing ports; finish that too.
	if _, _, warnings := s.exposePorts(ctx, recipe, name); len(warnings) > 0 {
		log.Printf("[recipe] expose warnings on %q after re-running post_start: %q", containerName, strings.Join(warnings, "; "))
	}
	return nil
}

// runPostStart runs a post_start script in the box and fails on a non-zero
// exit (#3542). Its output is not returned or logged: a step may print what
// a deploy supplied. Output past the exec capture cap is not a failure on its
// own; the exit status decides. It is tolerated only when it is the only
// problem: the exec path joins a wait/transport error with the cap error and
// reports exit 0 then, so errors.Is alone would hide a timeout (#3545).
func runPostStart(boxes recipeBoxes, containerName, script string) error {
	_, _, code, err := boxes.ExecWithExitCode(containerName, []string{"bash", "-c", script})
	if err != nil && !onlyOutputCapErr(err) {
		return err
	}
	if code != 0 {
		return fmt.Errorf("exit status %d", code)
	}
	return nil
}

// onlyOutputCapErr reports whether every leaf of err (descending through
// errors.Join and %w wrapping) matches limitio.ErrTooLarge. The exec path
// returns *limitio.TooLargeError, which matches the sentinel through its Is
// method and has no Unwrap, so each leaf is compared with errors.Is.
func onlyOutputCapErr(err error) bool {
	if err == nil {
		return true
	}
	switch e := err.(type) {
	case interface{ Unwrap() []error }:
		children := e.Unwrap()
		for _, c := range children {
			if !onlyOutputCapErr(c) {
				return false
			}
		}
		return len(children) > 0
	case interface{ Unwrap() error }:
		return e.Unwrap() != nil && onlyOutputCapErr(e.Unwrap())
	default:
		return errors.Is(err, limitio.ErrTooLarge)
	}
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
// sees CONTAINARIUM_MODEL_GATEWAY_URL/_TOKEN. The daemon's release tag is
// exported as recipes.ReleaseEnvName.
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
	// The daemon's own release (#3542), after the recipe's env so nothing a
	// deploy supplies can stand in for it. Always exported, empty on a
	// non-release build, so `set -u` steps can test it.
	fmt.Fprintf(&b, "export %s=%s\n", recipes.ReleaseEnvName, shellSingleQuote(version.ReleaseTag()))
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

// exposePorts registers a route (HTTP/gRPC) or a direct passthrough route
// (TCP/UDP) per recipe port and returns the first public HTTPS URL, any
// passthrough endpoints, and any warnings. Routing is best-effort: a failure
// warns rather than failing the whole deploy — the workload is already
// running and reachable on the LAN either way (#1462).
func (s *RecipeServer) exposePorts(ctx context.Context, recipe *pb.Recipe, name string) (url string, endpoints []string, warnings []string) {
	if len(recipe.Ports) == 0 {
		return "", nil, nil
	}
	if s.network == nil {
		return "", nil, []string{"routing is not enabled on this daemon; expose ports manually with 'containarium route add'"}
	}
	info, err := s.containers.manager.Get(name)
	if err != nil || info == nil || info.IPAddress == "" {
		return "", nil, []string{fmt.Sprintf("could not resolve container IP to expose ports: %v", err)}
	}

	for _, p := range recipe.Ports {
		switch p.Protocol {
		case pb.RouteProtocol_ROUTE_PROTOCOL_TCP, pb.RouteProtocol_ROUTE_PROTOCOL_UDP:
			endpoint, err := s.exposePassthroughPort(ctx, recipe, info, p)
			if err != nil {
				warnings = append(warnings, err.Error())
				continue
			}
			endpoints = append(endpoints, endpoint)
		default:
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
	}
	return url, endpoints, warnings
}

// exposePassthroughPort registers a direct TCP/UDP passthrough route for one
// recipe port (#1462), returning the public "host:port/protocol" endpoint.
//
// Passthrough binds a host-wide port — unlike an HTTP route, which is scoped
// by hostname, two boxes cannot share one external_port. AddPassthroughRoute
// itself upserts by (external_port, protocol) with no ownership check, so
// without the lookup below a second recipe deploy landing on a busy port
// would silently redirect the first box's traffic to the new one. This fails
// loudly instead — the smallest correct handling of the collision, per the
// issue's own "External port allocation" discussion — while still letting a
// re-deploy of the SAME container onto its own existing port through.
func (s *RecipeServer) exposePassthroughPort(ctx context.Context, recipe *pb.Recipe, info *incus.ContainerInfo, p *pb.RecipePort) (string, error) {
	externalPort := p.ExternalPort
	if externalPort == 0 {
		externalPort = p.ContainerPort
	}
	protocolLabel := "tcp"
	if p.Protocol == pb.RouteProtocol_ROUTE_PROTOCOL_UDP {
		protocolLabel = "udp"
	}

	existing, err := s.network.ListPassthroughRoutes(ctx, &pb.ListPassthroughRoutesRequest{})
	if err != nil {
		return "", fmt.Errorf("could not check for a conflicting passthrough route on port %d/%s: %w",
			externalPort, protocolLabel, err)
	}
	for _, r := range existing.Routes {
		if r.ExternalPort == externalPort && r.Protocol == p.Protocol && r.ContainerName != "" && r.ContainerName != info.Name {
			return "", fmt.Errorf("port %d/%s is already claimed by %s; set a different external_port for container_port %d",
				externalPort, protocolLabel, r.ContainerName, p.ContainerPort)
		}
	}

	if _, err := s.network.AddPassthroughRoute(ctx, &pb.AddPassthroughRouteRequest{
		ExternalPort:  externalPort,
		TargetIp:      info.IPAddress,
		TargetPort:    p.ContainerPort,
		Protocol:      p.Protocol,
		ContainerName: info.Name,
		Description:   "recipe:" + recipe.Id,
	}); err != nil {
		return "", fmt.Errorf("failed to expose passthrough port %d: %w", p.ContainerPort, err)
	}

	host := s.network.baseDomain
	if host == "" {
		host = "<this host>"
	}
	return fmt.Sprintf("%s:%d/%s", host, externalPort, protocolLabel), nil
}
