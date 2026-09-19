package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/netpolicy"
	"github.com/footprintai/containarium/internal/runlease"
	"github.com/footprintai/containarium/internal/tracker"
	boxlxc "github.com/footprintai/containarium/pkg/core/box/lxc"
	// Aliased: this file's RunAgentSkill/provisionSkillBox already use
	// "container" as a local variable name (the *pb.Container being built).
	containerpkg "github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/skills"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/footprintai/containarium/pkg/version"
)

// agentBoxPrefix is the box/tenant name prefix RunAgentSkill assigns to a
// skill's box (agent-<skill-id>). The minted in-box JWT carries this as its
// subject, so a call originating from an agent box authenticates as
// agent-<skill-id> — which is how SendAgentTask recovers the real caller.
const agentBoxPrefix = "agent-"

// agentTokenTTL bounds the lifetime of the JWT minted for a skill's in-box
// agent loop. Short by design: a skill run is a bounded task, not a session.
const agentTokenTTL = 30 * time.Minute

// agentSeedRoot and agentWorkspaceRoot are the fixed parents of every run's
// own seed directory and (when it fetches a repo, #1859) workspace inside the
// box. Per-run (#1860): before this, every run of a skill shared one seed
// directory at the box level, so two concurrent runs of the same skill — or a
// crew member / queue worker sharing the box with a one-off run — collided on
// each other's prompt, token, and (once #1859 landed) checkout. seedDirFor and
// workspaceDirFor turn a run id, already validated by resolveRunID as a
// single safe path segment, into that run's own directory under these roots.
// The in-box agent loop (the agent-runtime image's job) reads its seed from
// AGENT_SEED_DIR, set to seedDirFor's result at launch.
const (
	agentSeedRoot      = "/etc/containarium/agent/runs"
	agentWorkspaceRoot = "/workspace/runs"
)

// seedDirFor returns the per-run seed directory for runID.
func seedDirFor(runID string) string { return agentSeedRoot + "/" + runID }

// workspaceDirFor returns the per-run workspace directory for runID.
func workspaceDirFor(runID string) string { return agentWorkspaceRoot + "/" + runID }

// workspaceSeed is the Go side of the daemon<->runtime workspace contract
// (design doc §5, coding-skill-on-a-repo, cloud repo). Written as
// <seed>/workspace.json whenever a run fetched a git source, so the in-box
// runtime can bind its file tools to the checkout (AGENTBOX_ROOT) and cite
// the commit it is working from, without re-deriving either from the run id.
type workspaceSeed struct {
	Path      string `json:"path"`
	GitSource string `json:"git_source"`
	GitRef    string `json:"git_ref"`
	GitCommit string `json:"git_commit"`
}

// buildWorkspaceSeedScript writes seed as JSON into seedDir/workspace.json.
// Mirrors buildAgentSeedScript's shape (mkdir -p, single-quoted printf) since
// every field here — a caller-supplied repo URL and ref included — needs the
// same shell-injection guard that function already carries.
func buildWorkspaceSeedScript(seedDir string, seed workspaceSeed) string {
	raw, err := json.Marshal(seed)
	if err != nil {
		// workspaceSeed has no field that can fail to marshal (four plain
		// strings) — reachable only if that ever changes, and a marshal
		// failure here must not crash the run: a workspace.json write is a
		// nicety for a future runtime, not a correctness requirement for the
		// fetch that already succeeded.
		raw = []byte(`{}`)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "mkdir -p %s\n", seedDir)
	fmt.Fprintf(&b, "printf '%%s' %s > %s/workspace.json\n", shellSingleQuote(string(raw)), seedDir)
	return b.String()
}

// Run-lease reasons, recorded on every revocation and in the end audit row so
// an operator reading jwt_revocations can tell a normal run exit from a run
// that never got off the ground.
const (
	runExitReason         = "run_exit"
	provisionFailedReason = "provision_failed"
)

// endRunLeaseCeiling is the design's 6s cap on the REVOCATION half of ending a
// lease: runlease.End derives each credential's 2s revoke context from the one
// endRunLease passes in, so this bounds them together.
//
// It is NOT a bound on runlease.End as a whole, and the arithmetic is worth
// stating exactly because it is easy to assume otherwise. runlease.wipeSeed
// and (#1860) runlease's directory removal each take no context at all —
// they enforce their own 3s with a bare timer apiece — so the true worst case
// is 2s + 2s + 3s + 3s = 10s, and with two credentials the 4s of revokes
// never reach this 6s cap in the first place.
//
// That the wipe/removal steps do not derive from this deadline is the
// property that keeps it safe: slow revokes can never truncate them, so the
// seed files (and, once fetched, the workspace) still leave the box. Anyone
// making wipeSeed or the directory removal context-aware must raise this
// ceiling (or give that step its own budget) in the same change — otherwise
// slow revokes would silently cut a later step short and leave a readable
// `token` / `gateway.env` — or a fetched repo — behind in a box that is
// reused across runs.
const endRunLeaseCeiling = 6 * time.Second

// auditWriteBudget bounds one run-lease audit write.
//
// It has to exist separately from endRunLeaseCeiling: audit.Store.Log opens a
// transaction and takes a GLOBAL pg_advisory_xact_lock with no timeout of its
// own, deliberately serialising every audit appender against every other. The
// run-lease rows are written on a context detached from the caller's, so
// without a deadline here a reachable-but-wedged Postgres — or plain contention
// from another long audit transaction — would block RunAgentSkill inside its
// own deferred cleanup for as long as the database took. A dropped audit row is
// recoverable; a hung RPC is not.
const auditWriteBudget = 3 * time.Second

// runIDPattern is the accepted shape of a caller-supplied run id. Deliberately
// narrow: a run id is caller data that lands in JWT claims and audit rows, so
// it gets a character class with no shell, SQL, or JSON significance. It is
// never interpolated into a shell command.
var runIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// resolveRunID validates a caller-supplied run id or generates one. Empty
// means "the daemon picks"; anything else must match runIDPattern. "." and
// ".." both match that character class but are rejected explicitly (#1860):
// a run id becomes the single trailing path segment of the run's seed dir
// and workspace (seedDirFor/workspaceDirFor), and either value would resolve
// to the root itself rather than a per-run directory under it.
func resolveRunID(raw string) (string, error) {
	if raw == "" {
		return uuid.NewString(), nil
	}
	if raw == "." || raw == ".." {
		return "", status.Errorf(codes.InvalidArgument, "run_id must not be %q", raw)
	}
	if !runIDPattern.MatchString(raw) {
		return "", status.Errorf(codes.InvalidArgument,
			"run_id must match %s (1-128 chars of letters, digits, dot, underscore, hyphen)", runIDPattern.String())
	}
	return raw, nil
}

// AgentSkillServer implements the gRPC AgentSkillService (Phase 0:
// agent-as-a-box). It is pure orchestration: RunAgentSkill resolves a skill
// from the catalog, provisions its box by reusing RecipeServer.deploy, mints a
// JWT scoped to exactly the skill's allowed_scopes, and seeds the box. The
// in-box agent loop that consumes the seed and produces an artifact is the
// agent-runtime image's responsibility and is intentionally out of scope for
// Phase 0 (artifact_json is returned empty until that lands).
type AgentSkillServer struct {
	pb.UnimplementedAgentSkillServiceServer
	catalog   *skills.Manager
	recipes   *RecipeServer        // box provisioning (reuses CreateContainer/exec/expose)
	tokens    *auth.TokenManager   // mints the skill's scoped in-box token
	netpolicy *NetworkPolicyServer // compiles allowed_peers into a per-box egress policy (Phase 2)
	audit     auditLogger          // records A2A hops and run leases; set once the pool is ready
	gateway   *gatewayProvisioning // model-gateway provisioning (#674); nil ⇒ boxes run in direct mode
	queue     AgentTaskQueue       // pull-based run queue (#674) — Enqueue/Lease/Complete
	// revocations kills a run's credentials when the run ends (#1817). nil on a
	// daemon without Postgres: runs still complete and seed files are still
	// wiped, but the credentials live to their expiry and each run says so in
	// the log.
	revocations runlease.Revoker
	// runs is the in-memory registry of currently-live runs (#1922) —
	// nil until dual_server.go wires the same instance into both this
	// server and ContainerServer via SetRunRegistry. Registration is
	// nil-guarded at each call site rather than inside Registry itself,
	// matching this file's existing convention for audit/revocations.
	runs *runlease.Registry
	// trackerConnections validates a caller-supplied
	// RunAgentSkillRequest.tracker_connection against the caller's own
	// tenant before it's minted into the run's JWT (#1922 step 6, design
	// note decision D3). Nil on a daemon without the tracker store wired
	// (--standalone, or Postgres unavailable): a request naming a
	// tracker_connection then fails closed rather than minting an
	// unvalidated claim — see RunAgentSkill.
	trackerConnections trackerConnectionChecker
}

// trackerConnectionChecker is the one method of *tracker.Store
// RunAgentSkill needs, narrowed the same way auditLogger narrows
// *audit.Store — so the tenant-ownership check is testable without a
// real Postgres-backed tracker.Store. *tracker.Store satisfies this
// directly.
type trackerConnectionChecker interface {
	Get(ctx context.Context, username, name string) (*tracker.Connection, error)
}

// SetRunRegistry wires the shared in-memory run registry (#1922) — the
// SAME instance dual_server.go also gives to ContainerServer, so a
// tracker write RPC can resolve run_id -> skill/model and ask "is this
// run still live" for a run this server created.
func (s *AgentSkillServer) SetRunRegistry(r *runlease.Registry) {
	s.runs = r
}

// SetTrackerConnections wires the tracker-connections store (#1922 step
// 6) so RunAgentSkill can validate a tracker_connection request field
// against the caller's own tenant before minting it into the run's JWT.
// Nil (the default) makes any request naming a tracker_connection fail
// closed with FailedPrecondition.
func (s *AgentSkillServer) SetTrackerConnections(c trackerConnectionChecker) {
	s.trackerConnections = c
}

// auditLogger is the one method of *audit.Store this server uses. Narrowed to
// an interface so what actually lands in audit_logs — the action, the resource
// type, the run id column — is assertable in a unit test; *audit.Store itself
// needs a live Postgres pool, which is why the A2A hop path was only ever
// smoke-tested.
type auditLogger interface {
	Log(ctx context.Context, entry *audit.AuditEntry) error
}

// SetAuditStore wires the audit store once the Postgres pool exists (it isn't
// available at construction). A2A hop and run-lease logging no-op until then.
//
// The nil check is load-bearing now that the field is an interface: a nil
// *audit.Store assigned straight into it would arrive as a non-nil interface
// holding a nil pointer, and the `s.audit == nil` guards below would stop
// firing. Same hazard as SetRevocationStore, but caught here because this
// setter takes the concrete type.
func (s *AgentSkillServer) SetAuditStore(store *audit.Store) {
	if store == nil {
		s.audit = nil
		return
	}
	s.audit = store
}

// SetRevocationStore wires the jti revocation store so a run's credentials can
// be killed when the run ends (#1817), mirroring SetAuditStore: it isn't
// available at construction, and revocation no-ops until it is.
//
// The CALLER must pass a true nil when it has no store. A nil
// *auth.PgRevocationStore handed in here arrives as a NON-nil interface holding
// a nil pointer, which no `== nil` check in this package or in runlease can
// see, and the first revoke of the first run then dereferences nil.
// dual_server.go does that nil check at the one place the concrete pointer
// exists.
func (s *AgentSkillServer) SetRevocationStore(store auth.RevocationStore) {
	s.revocations = store
}

// SetGatewayProvisioning enables model-gateway provisioning for skill boxes:
// each provisioned box gets a per-skill gateway token + the SDK base-URL env so
// its model calls route through the daemon-served gateway (key custody +
// metering). Wired from dual_server when a provider key is configured; nil-safe
// (no call ⇒ direct mode). provider is the gateway's configured provider,
// httpPort the daemon HTTP port the box dials, secret the shared jwt secret,
// hostIP the bridge gateway IP the box reaches the gateway/daemon/DNS on (used
// to pin skill-box egress to the gateway, #674 inc 4; empty disables pinning).
func (s *AgentSkillServer) SetGatewayProvisioning(provider string, httpPort int, secret []byte, hostIP string) {
	g := &gatewayProvisioning{provider: provider, httpPort: httpPort, secret: secret}
	if hostIP = strings.TrimSpace(hostIP); hostIP != "" {
		g.egressCIDR = hostIP + "/32"
	}
	s.gateway = g
}

// NewAgentSkillServer wires the agent-skill service to the recipe server (for
// box provisioning), the token manager (for minting scoped in-box tokens), and
// the network policy server (to compile allowed_peers into a per-box egress
// policy at launch). netpolicy may be nil — policy compilation then no-ops.
func NewAgentSkillServer(recipes *RecipeServer, tokens *auth.TokenManager, netpolicy *NetworkPolicyServer) *AgentSkillServer {
	return &AgentSkillServer{
		catalog:   skills.GetDefault(),
		recipes:   recipes,
		tokens:    tokens,
		netpolicy: netpolicy,
		queue:     NewMemAgentTaskQueue(),
	}
}

// ListAgentSkills returns all built-in skills.
func (s *AgentSkillServer) ListAgentSkills(ctx context.Context, _ *pb.ListAgentSkillsRequest) (*pb.ListAgentSkillsResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeAgentsRead); err != nil {
		return nil, err
	}
	return &pb.ListAgentSkillsResponse{Skills: s.catalog.List()}, nil
}

// GetAgentSkill returns a single skill by ID.
func (s *AgentSkillServer) GetAgentSkill(ctx context.Context, req *pb.GetAgentSkillRequest) (*pb.GetAgentSkillResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeAgentsRead); err != nil {
		return nil, err
	}
	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	skill, err := s.catalog.Get(req.Id)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	return &pb.GetAgentSkillResponse{Skill: skill}, nil
}

// RunAgentSkill provisions a skill's box, mints a token scoped to exactly the
// skill's allowed_scopes, seeds the prompt/token/input into the box, and
// returns the box. Gated on agents:run; the inner provisioning still enforces
// containers:write + tenant authz via CreateContainer.
//
// Phase 0 limitations (documented seams):
//   - The in-box agent loop is the agent-runtime image's job; artifact_json is
//     returned empty until it lands.
//   - The box name is derived deterministically from the skill id, so two
//     concurrent runs of the same skill collide. Per-run boxes / a warm pool
//     are a later concern (see docs/EPHEMERAL-SANDBOX-DESIGN.md).
//   - allowed_peers is inert until Phase 2 (eBPF enforcement).
func (s *AgentSkillServer) RunAgentSkill(ctx context.Context, req *pb.RunAgentSkillRequest) (*pb.RunAgentSkillResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeAgentsRun); err != nil {
		return nil, err
	}
	if req.SkillId == "" {
		return nil, status.Error(codes.InvalidArgument, "skill_id is required")
	}

	// Resolve the run id before any box work: it is bound into every credential
	// this run is given, so a malformed one must fail the RPC, not the run.
	runID, err := resolveRunID(req.GetRunId())
	if err != nil {
		return nil, err
	}

	// Validate tracker_connection against the CALLER's own tenant before any
	// box work, same reasoning as the run id above: a request naming a
	// connection it doesn't own must fail the RPC, not mint a claim that
	// looks legitimate. Empty means the run isn't bound to a connection —
	// unchanged, pre-#1922 behavior (#1922 step 6, design note decision D3).
	if err := s.validateTrackerConnection(ctx, req.GetTrackerConnection()); err != nil {
		return nil, err
	}

	skill, err := s.catalog.Get(req.SkillId)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}

	containerName, box, lease, gitCommit, workspacePath, err := s.provisionSkillBox(ctx, skill, req.BackendId, req.Pool, req.InputJson, runID,
		req.GetGitSource(), req.GetGitRef(), req.GetGitCredential(), req.GetTrackerConnection())
	if err != nil {
		return nil, err
	}

	// The run holds its credentials for exactly as long as the run (#1817). The
	// defer sits AFTER provisioning on purpose: a provisioning failure has
	// nothing to end but a partially minted lease, which provisionSkillBox ends
	// itself before returning its error. From here on every exit path — the
	// artifact below, an agent error, a cancelled caller — revokes both jtis and
	// wipes the seed files.
	//
	// RESOLVED (#1860) — the box is still shared by skill id ("agent-"+skill.Id,
	// see provisionSkillBox), but the seed directory no longer is: every run,
	// crew member, and queue worker gets its own seedDirFor(runID), so this
	// run's exit removes only ITS OWN directory and never touches a co-resident
	// crew member's or worker's files. What remains open, by design and matching
	// #1860's own "Not in scope": a leftover in-box PROCESS (not a file) from an
	// earlier run can still read a later run's live token out of /proc while
	// both happen to share the box's UID — closing that needs a per-run box or a
	// Clean()-style process reset, not a seed-path change. Crew/queue leases are
	// also still never explicitly ended here (they outlive this RPC by design);
	// see docs/architecture/execution-scoped-authorization.md §3.
	// Record this run in the in-memory registry (#1922) so other daemon
	// components — the tracker broker's ClaimTrackerIssue liveness check
	// and identity stamp — can resolve run_id -> skill/model without a
	// database round trip. Symmetric with endRunLease's Unregister
	// below: a run is "live" for exactly the window between successful
	// provisioning (here) and its lease ending.
	if s.runs != nil {
		s.runs.Register(runID, runlease.Info{SkillID: skill.Id, Model: skill.Model})
	}
	defer s.endRunLease(ctx, lease, s.boxWiper(), runExitReason)

	// Run the in-box agent loop (Phase 4a) and read its artifact back.
	// Best-effort: until the box image ships agent-runtime + agent-box this
	// degrades to an empty artifact (prior behavior), so a base-image box never
	// fails the run.
	//
	// Note on "caller-cancel": runInBoxAgent takes no context (it goes through
	// ExecWithOutput), so cancelling the RPC does NOT interrupt the in-box
	// process — the lease ends when the exec returns, under a detached context.
	// Making the exec cancellable is a separate change and doesn't alter this.
	//
	// #1860: this read happens before the function returns, and `defer`s run
	// after a function's return values are computed but before it returns to
	// its caller — so artifact.json is always read into this Go string BEFORE
	// endRunLease's directory removal ever runs. A run whose artifact was
	// returned never loses it to the wipe.
	artifact := s.runInBoxAgent(containerName, lease.SeedDir)
	return &pb.RunAgentSkillResponse{
		Container:     box,
		ArtifactJson:  artifact,
		RunId:         runID,
		GitCommit:     gitCommit,
		WorkspacePath: workspacePath,
	}, nil
}

// boxWiper is the seam runlease.End wipes a run's seed files through.
// *container.Manager already satisfies runlease.Wiper; nil when no container
// manager is wired (then the wipe is skipped and reported as not done),
// mirroring runInBoxAgent's own guard.
func (s *AgentSkillServer) boxWiper() runlease.Wiper {
	if s.recipes == nil || s.recipes.containers == nil || s.recipes.containers.manager == nil {
		return nil
	}
	return s.recipes.containers.manager
}

// endRunLease revokes a run's credentials and wipes its seed files, then
// records what happened.
//
// The context is detached from the caller's (context.WithoutCancel) so a
// cancelled or timed-out RPC still gets its credentials killed — the whole
// point of the lease. Every step that can block is bounded: the revokes by
// endRunLeaseCeiling, the wipe by runlease's own timer, and the audit write by
// auditWriteBudget inside auditRunLease. The wiper is passed in rather than
// read off s so the behavior is testable without a live container backend.
func (s *AgentSkillServer) endRunLease(ctx context.Context, lease runlease.Lease, w runlease.Wiper, reason string) {
	if len(lease.Credentials) == 0 && lease.RunID == "" {
		return // nothing was ever issued
	}

	if s.runs != nil {
		s.runs.Unregister(lease.RunID)
	}

	detached := context.WithoutCancel(ctx)
	lctx, cancel := context.WithTimeout(detached, endRunLeaseCeiling)
	out := runlease.End(lctx, lease, s.revocations, w, reason)
	cancel()

	if len(out.Unrevoked) > 0 {
		// One line per run, naming the run, so an operator running without
		// Postgres can see exactly which credentials are now alive until their
		// 30-minute expiry.
		log.Printf("[agent-skill] run %s: %d credential(s) could not be revoked before expiry (no revocation store, or the store rejected them)",
			lease.RunID, len(out.Unrevoked))
	}
	for _, err := range out.Errs {
		log.Printf("[agent-skill] run %s: ending lease: %v", lease.RunID, err)
	}

	s.auditRunLease(detached, "agent.run_lease_end", lease.RunID, runLeaseEndPayload(lease, reason, out))
}

// agentRuntimeReleaseTag returns the GitHub release tag the agent-runtime box
// pulls its artifacts from. version.GetVersion() is the BARE semver ("0.26.6")
// — the release workflow builds with VERSION=${tag#v}, so the `v` is stripped
// at build time — but the git tag and release are `v`-prefixed ("v0.26.6"),
// and the recipe's post_start uses this value directly in
// raw.githubusercontent.com/<repo>/<ref>/... and releases/download/<ref>/...
// URLs. Without the `v` those 404 and the best-effort assembly silently skips,
// so the box comes up without the in-box loop. Re-add the prefix (idempotent —
// a value that already carries it, or a dev/unpublished version, is left as-is
// and just degrades to skip-assembly as before).
func agentRuntimeReleaseTag() string {
	v := version.GetVersion()
	if v == "" || strings.HasPrefix(v, "v") {
		return v
	}
	return "v" + v
}

// provisionSkillBox provisions a skill's box and gets it ready to run: resolve
// the box recipe, deploy it, mint a JWT scoped to exactly the skill's
// allowed_scopes, seed the prompt/token/input/card, and compile allowed_peers
// into the per-box egress policy. It does NOT run the loop — RunAgentSkill runs
// it one-shot, RunCrew starts it in serve mode. Returns the container name +
// the provisioned Container.
// mintedAgentAct computes the RFC 8693 `act` delegation claim (#1677) for a
// token minted on behalf of the caller authenticated in ctx — used by both
// RunAgentSkill (single skill) and RunCrew (per-member boxes, both funnel
// through provisionSkillBox) via GenerateDelegatedToken.
//
// Derived ONLY from ctx — never from the request proto — which is the
// anti-forgery invariant this claim exists to hold: RunAgentSkillRequest
// and RunCrewRequest have no actor-ish field a caller could set, and this
// function doesn't accept the request as a parameter at all, so there is
// nothing for a caller to forge through.
//
// Nests rather than overwrites: if the caller's OWN token already carried
// an act (it is itself a derived/agent token — e.g. an agent box that
// itself holds agents:run calling RunAgentSkill again), the new token's act
// wraps {caller's subject, caller's own act}, so the chain always resolves
// back to the root human principal at whatever depth it's read.
// validateTrackerConnection checks that connName, when non-empty, names a
// tracker connection owned by the CALLER's own tenant (never a request
// field's claimed identity) — the anti-forgery check that makes minting it
// into the run's `tracker_conn` claim trustworthy. Empty connName is valid
// (no binding requested) and always passes without touching the store.
func (s *AgentSkillServer) validateTrackerConnection(ctx context.Context, connName string) error {
	if connName == "" {
		return nil
	}
	if s.trackerConnections == nil {
		return status.Error(codes.FailedPrecondition, "tracker connections not configured on this daemon")
	}
	username, _, ok := auth.SubjectFromGRPCContext(ctx)
	if !ok || username == "" {
		return status.Error(codes.Unauthenticated, "no authenticated subject")
	}
	if _, err := s.trackerConnections.Get(ctx, username, connName); err != nil {
		if errors.Is(err, tracker.ErrNotFound) {
			return status.Errorf(codes.InvalidArgument, "tracker_connection %q not found for tenant %q", connName, username)
		}
		return status.Errorf(codes.Internal, "check tracker_connection: %v", err)
	}
	return nil
}

func mintedAgentAct(ctx context.Context) *auth.Actor {
	username, _, ok := auth.SubjectFromGRPCContext(ctx)
	if !ok || username == "" {
		return nil // unauthenticated/system context — nothing meaningful to record
	}
	callerAct, _ := auth.ActFromGRPCContext(ctx)
	return &auth.Actor{Subject: username, Act: callerAct}
}

// mintedAgentTokenScopes computes the scopes for a skill's in-box token: the
// intersection of the caller's own granted scopes and the skill manifest's
// allowed_scopes (#1676). auth.ScopesFromGRPCContext — not the plain
// ScopesFromContext — is required here: the primary API surface is REST via
// grpc-gateway, and the HTTP middleware propagates the caller's scopes claim
// through outgoing gRPC metadata (internal/auth/middleware.go), not a context
// value that would survive the HTTP→gateway→gRPC hop. RequireScope and
// AuthorizeTenant already read the caller this same way.
//
// runForbiddenScopes are then stripped unconditionally — caught in review
// of #1924 (CWE-862): tracker:admin gates tracker connection CRUD
// (repointing the broker at a different project or credential), an
// operator decision that must never reach a bounded skill run no matter
// how permissive the dispatching caller or the skill manifest's own
// allowed_scopes are. Without this, a caller with the admin role calling
// RunAgentSkill on a manifest that (mistakenly or not) lists tracker:admin
// in allowed_scopes would mint a run token that could redirect the
// broker's held credential — the exact thing a run-scoped token binding
// to one connection (#1922 step 6) exists to prevent.
func mintedAgentTokenScopes(ctx context.Context, skill *pb.AgentSkill) []string {
	callerScopes, _ := auth.ScopesFromGRPCContext(ctx)
	granted := auth.IntersectScopes(callerScopes, skill.AllowedScopes)
	return auth.ExcludeScopes(granted, runForbiddenScopes...)
}

// runForbiddenScopes never reach a minted run token, regardless of what
// the dispatching caller or the skill manifest's allowed_scopes grant.
// tracker:admin is the only entry today — see mintedAgentTokenScopes's
// doc comment. A future admin-tier scope gets added here on the same
// reasoning, not by auditing every skill manifest for it.
var runForbiddenScopes = []string{auth.ScopeTrackerAdmin}

// provisionSkillBox provisions (or reuses) the skill's box, mints its
// credentials, seeds the task, and — when gitSource is set (#1859) —
// shallow-fetches that repo into the box's workspace before the agent starts.
// The fetch runs AFTER the seed exec succeeds and BEFORE the allowed_peers
// policy is applied: seeding first means a failed fetch still leaves a
// consistent, end-able lease behind (same reasoning as the seed-failure path
// below); applying policy last means a fetch that needs the platform egress
// allowlist (git-installer package fetches) isn't fighting the skill's own
// restrictive policy while it runs.
//
// The workspace is box-level (not yet per-run — see #1860), so concurrent
// runs of the same skill overwrite each other's checkout exactly as they
// already overwrite each other's seed files; #1860 gives both their own
// per-run directory.
func (s *AgentSkillServer) provisionSkillBox(ctx context.Context, skill *pb.AgentSkill, backendID, pool, inputJSON, runID, gitSource, gitRef, gitCredential, trackerConnection string) (containerName string, box *pb.Container, lease runlease.Lease, gitCommit, workspacePath string, err error) {
	var noLease runlease.Lease

	// Phase 0 supports only the recipe_id box form (catalog skills). Inline
	// recipes are an API-only construct deferred to a later phase.
	recipeID := skill.GetRecipeId()
	if recipeID == "" {
		return "", nil, noLease, "", "", status.Error(codes.Unimplemented,
			"inline-recipe skills are not supported yet; use a skill that references a recipe_id")
	}

	// Deterministic box identity (concurrent same-skill runs collide — a later
	// per-run-box / warm-pool concern, see docs/EPHEMERAL-SANDBOX-DESIGN.md).
	name := "agent-" + skill.Id
	if err := auth.AuthorizeTenant(ctx, name); err != nil {
		return "", nil, noLease, "", "", err
	}

	// Provision the box, idempotently. The normal skill flow is run → (set a
	// secret / inspect) → run again, and a crew re-drives its members every
	// run, so the SAME box name recurs. The deploy path's CreateContainer
	// errors on an existing instance ("already exists"), which would make every
	// re-run fail. So if the box is already provisioned, reuse it: skip deploy
	// (and its one-time post_start assembly) and just re-mint the token,
	// re-seed, and re-apply policy below. A stopped box (idle-sleep, host
	// reboot) is started so the subsequent seed-exec / loop-exec lands.
	if info, gerr := s.recipes.containers.manager.Get(name); gerr == nil && info != nil {
		if info.State != "Running" {
			if err := s.recipes.containers.manager.Start(name); err != nil {
				return "", nil, noLease, "", "", status.Errorf(codes.Internal, "failed to start existing agent box %s: %v", name, err)
			}
			if reread, rerr := s.recipes.containers.manager.Get(name); rerr == nil && reread != nil {
				info = reread
			}
		}
		st := boxlxc.StatusFromInfo(info)
		box = toProtoContainer(&st)
	} else {
		// First provision. Pass the daemon's version as the agent-runtime
		// recipe's `release` param so the box's post_start pulls matching
		// agent-box + agent-runtime artifacts (box-image assembly). Recipes that
		// don't declare these params ignore the extras; assembly is best-effort
		// (a dev/unpublished version just skips it).
		dep, err := s.recipes.deploy(ctx, &pb.DeployRecipeRequest{
			RecipeId:   recipeID,
			Name:       name,
			BackendId:  backendID,
			Pool:       pool,
			Parameters: map[string]string{"release": agentRuntimeReleaseTag()},
		})
		if err != nil {
			return "", nil, noLease, "", "", err // already a gRPC status from deploy/CreateContainer
		}
		box = dep.Container
	}

	containerName = name + "-container"
	// The run's lease: every credential minted below is recorded here so the
	// run's exit can revoke exactly what the run was given (#1817). SeedDir is
	// per-run (#1860) so concurrent runs of the same skill — which share this
	// box — no longer collide on one shared seed directory.
	seedDir := seedDirFor(runID)
	lease = runlease.Lease{RunID: runID, Box: containerName, SeedDir: seedDir}

	// Mint a JWT scoped to the intersection of the CALLER's own granted scopes
	// and the skill's allowed_scopes (#1676: the manifest is a ceiling, never
	// a floor — a caller with no scopes claim/wildcard gets the manifest
	// unchanged, anyone else only receives scopes they already hold), carrying
	// the dispatching caller as its `act` delegation claim (#1677) so an
	// auditor asking "who authorized this?" doesn't get the name of a robot.
	// Minted through the WithRun variant so the daemon keeps the jti + expiry
	// of what it issued, with runID so the token itself says which run it
	// belongs to (the `run_id` claim), and with trackerConnection — already
	// validated against the caller's own tenant by validateTrackerConnection
	// before this function was called — so the token also says which tracker
	// connection the run is bound to (the `tracker_conn` claim, #1922 step 6).
	// Empty trackerConnection mints no claim, unchanged pre-#1922 behavior.
	token, minted, mintErr := s.tokens.GenerateDelegatedTokenWithRun(name, []string{}, agentTokenTTL, mintedAgentAct(ctx), runID, trackerConnection, mintedAgentTokenScopes(ctx, skill)...)
	if mintErr != nil {
		return "", nil, noLease, "", "", status.Errorf(codes.Internal, "failed to mint scoped agent token: %v", mintErr)
	}
	lease.Credentials = append(lease.Credentials, runlease.Credential{
		Kind: runlease.KindPlatformJWT, JTI: minted.JTI, ExpiresAt: minted.ExpiresAt,
	})

	// Seed the prompt/token/input/card into the box.
	cardJSON := ""
	if skill.AgentCard != nil {
		if b, err := protojson.Marshal(skill.AgentCard); err == nil {
			cardJSON = string(b)
		}
	}
	seedScript := buildAgentSeedScript(seedDir, skill.SystemPrompt, token, inputJSON, cardJSON)
	// Model-gateway provisioning (#674): when the daemon serves a gateway, mint a
	// per-skill gateway token and append the env-seeding to the same exec, so the
	// box's engine routes model calls through the gateway (real key never enters
	// the box). Best-effort: a mint/script error logs and falls back to direct
	// mode rather than failing provisioning.
	if s.gateway != nil {
		if gwTok, gwMinted, gerr := s.gateway.mintGatewayToken(name, skill.Id, runID); gerr != nil {
			log.Printf("[agent-skill] gateway token mint failed for %s (box runs direct mode): %v", name, gerr)
		} else if envScript, eerr := gatewayEnvScript(s.gateway.provider, s.gateway.httpPort, gwTok, seedDir); eerr != nil {
			log.Printf("[agent-skill] gateway env script failed for %s (box runs direct mode): %v", name, eerr)
		} else {
			seedScript += "\n" + envScript
			lease.Credentials = append(lease.Credentials, runlease.Credential{
				Kind: runlease.KindGatewayToken, JTI: gwMinted.JTI, ExpiresAt: gwMinted.ExpiresAt,
			})
		}
	}
	if err := s.recipes.containers.manager.Exec(containerName,
		[]string{"bash", "-c", seedScript}); err != nil {
		// Credentials exist but the box never received them (or received only
		// part of the seed). RunAgentSkill's defer isn't armed yet — it arms on
		// a successful provision — so this partial lease is ours to end.
		//
		// This path writes an agent.run_lease_end row with NO preceding
		// agent.run_lease_issue row, because the issue row is written below,
		// after the seed lands. That orphan end row is by construction, not a
		// lost write, and it lists the jtis it revoked — so an operator meeting
		// one can still answer "what was this run given".
		s.endRunLease(ctx, lease, s.boxWiper(), provisionFailedReason)
		return "", nil, noLease, "", "", status.Errorf(codes.Internal, "failed to seed agent box %s: %v", containerName, err)
	}

	// #1859/#1860: fetch the run's repo, if any, now that the box has
	// credentials and is ready to read them. The workspace is per-run
	// (workspaceDirFor), so two concurrent runs of this skill never share a
	// checkout. A fetch failure is treated exactly like a seed failure — the
	// partial lease (already-minted credentials) is ended here, before
	// RunAgentSkill's defer would have taken over.
	if gitSource != "" {
		workspacePath = workspaceDirFor(runID)
		// #1871: recorded on the lease BEFORE the fetch attempt, not after it
		// succeeds. buildGitFetchScript's `mkdir -p`/`git init` land on disk
		// before the `git fetch` that can fail, so a failed fetch still
		// leaves a (credential-free, empty) workspace dir behind. Ending the
		// lease below must target it for removal even on this failure path.
		lease.Workspace = workspacePath
		commit, ferr := s.recipes.containers.manager.FetchGitSource(containerName, containerpkg.GitSourceSpec{
			Source:        gitSource,
			Ref:           gitRef,
			Credential:    gitCredential,
			WorkspacePath: workspacePath,
		})
		if ferr != nil {
			s.endRunLease(ctx, lease, s.boxWiper(), provisionFailedReason)
			return "", nil, noLease, "", "", status.Errorf(codes.FailedPrecondition, "git fetch into agent box %s failed: %v", containerName, ferr)
		}
		gitCommit = commit

		// #1861: tell the in-box runtime what it's looking at. Best-effort —
		// a write failure here means a future runtime can't auto-bind
		// AGENTBOX_ROOT or cite the commit in its own words, not that the
		// fetch it describes was wrong (already durable in gitCommit/
		// workspacePath above, and reported in the RPC response either way).
		wsScript := buildWorkspaceSeedScript(seedDir, workspaceSeed{
			Path:      workspacePath,
			GitSource: gitSource,
			GitRef:    gitRef,
			GitCommit: gitCommit,
		})
		if werr := s.recipes.containers.manager.Exec(containerName, []string{"bash", "-c", wsScript}); werr != nil {
			log.Printf("[agent-skill] workspace.json seed failed for %s (runtime won't see the workspace path via the contract file): %v", containerName, werr)
		}
	}

	// Compile allowed_peers into the per-box egress policy (Phase 2).
	s.applyAllowedPeersPolicy(ctx, name, skill)

	s.auditRunLease(ctx, "agent.run_lease_issue", runID, runLeaseIssuePayload(lease))

	return containerName, box, lease, gitCommit, workspacePath, nil
}

// engineForProvider maps a gateway provider to the agent-runtime engine that
// speaks it. Empty for an unknown provider (caller then leaves the engine
// unset, so the box falls back to its own default).
func engineForProvider(provider string) string {
	switch provider {
	case "anthropic":
		return "claude"
	case "gemini":
		return "gemini"
	case "openai":
		return "codex"
	default:
		return ""
	}
}

// engineEnvPrefix returns a `CONTAINARIUM_AGENT_ENGINE=<engine> ` command prefix
// pinning the box to the engine that matches the gateway provider (#748). When
// the daemon serves a gateway it knows the provider, so it must tell the box
// which engine to run — otherwise the box uses its default (claude) and a
// gemini/openai gateway run fails ("Not logged in") because the default engine
// looks for the wrong gateway env vars. Empty in direct mode (no gateway): the
// box's own env/default decides.
func (s *AgentSkillServer) engineEnvPrefix() string {
	if s.gateway == nil {
		return ""
	}
	if eng := engineForProvider(s.gateway.provider); eng != "" {
		return "CONTAINARIUM_AGENT_ENGINE=" + eng + " "
	}
	return ""
}

// startServeMode launches the in-box agent-runtime in serve mode (the A2A
// server on :8674) as a background process, so peers/crews can delegate tasks
// to this box. Best-effort: until the box image ships agent-runtime this is a
// no-op failure (logged), like runInBoxAgent. Used by RunCrew for members.
func (s *AgentSkillServer) startServeMode(containerName, seedDir string) {
	if s.recipes == nil || s.recipes.containers == nil || s.recipes.containers.manager == nil {
		return
	}
	cmd := sourceGatewayEnvPrefix(seedDir) + s.engineEnvPrefix() + "CONTAINARIUM_AGENT_MODE=serve AGENT_SEED_DIR=" + seedDir +
		" setsid agent-runtime >/var/log/agent-runtime.log 2>&1 &"
	if _, stderr, err := s.recipes.containers.manager.ExecWithOutput(containerName,
		[]string{"bash", "-lc", cmd}); err != nil {
		log.Printf("[agent-skill] could not start serve mode on %s (image may not ship runtime): %v; stderr=%s",
			containerName, err, strings.TrimSpace(stderr))
	}
}

// runInBoxAgent executes the in-box agent-runtime over the seeded task and
// reads its artifact back. The agent-runtime + agent-box live in the
// agent-runtime box image (Phase 4a image assembly); the model/engine/provider
// key come from the box env (secrets-injected). Best-effort: any failure
// (runtime absent, exec error, bad artifact) logs and returns "" rather than
// failing RunAgentSkill — the box is still provisioned + gated + traced.
func (s *AgentSkillServer) runInBoxAgent(containerName, seedDir string) string {
	if s.recipes == nil || s.recipes.containers == nil || s.recipes.containers.manager == nil {
		return ""
	}
	mgr := s.recipes.containers.manager

	if _, stderr, err := mgr.ExecWithOutput(containerName,
		[]string{"bash", "-lc", sourceGatewayEnvPrefix(seedDir) + s.engineEnvPrefix() + "AGENT_SEED_DIR=" + seedDir + " agent-runtime"}); err != nil {
		log.Printf("[agent-skill] in-box runtime did not run on %s (image may not ship it yet): %v; stderr=%s",
			containerName, err, strings.TrimSpace(stderr))
		return ""
	}

	raw, err := mgr.ReadFile(containerName, seedDir+"/artifact.json")
	if err != nil {
		log.Printf("[agent-skill] could not read artifact from %s: %v", containerName, err)
		return ""
	}
	out, err := parseArtifactOutput(raw)
	if err != nil {
		log.Printf("[agent-skill] in-box agent on %s reported an error: %v", containerName, err)
		return ""
	}
	return out
}

// parseArtifactOutput extracts the agent's output JSON from artifact.json
// (written by agent-runtime). A non-empty `error` field is surfaced as an
// error so RunAgentSkill can log it and fall back to an empty artifact.
func parseArtifactOutput(raw []byte) (string, error) {
	var a struct {
		OutputJSON string `json:"outputJson"`
		Error      string `json:"error"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return "", fmt.Errorf("decode artifact.json: %w", err)
	}
	if a.Error != "" {
		return "", fmt.Errorf("%s", a.Error)
	}
	return a.OutputJSON, nil
}

// applyAllowedPeersPolicy compiles a skill's allowed_peers into a per-box
// egress NetworkPolicy and stores it (LOG_ONLY). The box's tenant is its name
// (the agent-<skill-id> / <tenant>-container convention the enforcer resolves).
// Best-effort: logs and returns on any error so a policy hiccup never blocks a
// run. No-op when no policy server is wired or the skill declares no peers.
//
// Phase 2 seam: the policy is observe-only here. Dropping non-allowed egress
// in-kernel needs the env-gated eBPF enforcer (CONTAINARIUM_NETWORK_POLICY_*)
// on a Linux backend and a flip to ENFORCE. Also, before ENFORCE is safe the
// allowlist must be broadened to the platform egress the agent legitimately
// needs (daemon API, DNS) — a peer-only allowlist would otherwise strand the
// agent. Tracked in #574.
func (s *AgentSkillServer) applyAllowedPeersPolicy(ctx context.Context, tenant string, skill *pb.AgentSkill) {
	// Gateway pinning (#674 inc 4): when the model-gateway is enabled, every
	// skill box is pinned to it — even one with no allowed_peers — so model
	// calls can ONLY go through the gateway.
	gatewayCIDR := ""
	if s.gateway != nil {
		gatewayCIDR = s.gateway.egressCIDR
	}
	// Default-deny (#750): install a policy for EVERY skill box, not only ones
	// that declare allowed_peers or run under a gateway. A leaf skill
	// (allowed_peers: []) in direct mode still gets a policy whose egress is just
	// the provider domains (+ operator CIDRs), with metadata and intra-tenant
	// denied — so under ENFORCE the box is locked down rather than left with no
	// eBPF program (i.e. unrestricted egress). The empty-allowlist guard below
	// still skips the degenerate "nothing allowed" case.
	if s.netpolicy == nil {
		return
	}
	extraCIDRs, extraDomains, enforce := agentNetworkPolicyConfig()
	policy := compileAllowedPeersPolicy(tenant, skill.AllowedPeers, s.resolvePeerIP, extraCIDRs, extraDomains, gatewayCIDR, enforce)
	if len(policy.EgressCidrs) == 0 && len(policy.EgressDomains) == 0 {
		// Nothing to allow at all. Skip rather than install an empty allowlist
		// (which, under ENFORCE, denies everything).
		return
	}
	if enforce && len(policy.EgressDomains) == 0 && gatewayCIDR == "" {
		// #611: an armed agent with no model-provider egress is stranded — it
		// can reach its peers but not the Claude/OpenAI API. Default domains
		// prevent this; warn loudly if an operator cleared them. (In gateway
		// mode model egress is the gatewayCIDR, so this doesn't apply.)
		log.Printf("[agent-skill] WARNING: ENFORCE armed for %q with no model egress (CONTAINARIUM_AGENT_EGRESS_DOMAINS empty) — the agent loop may be unable to reach its provider API", tenant)
	}
	// Compile (validate + normalize) before storing — same path the
	// SetNetworkPolicy RPC uses — so a bad operator-supplied egress CIDR is
	// caught here instead of silently dropped by the enforcer's reconcile.
	compiled, err := netpolicy.Compile(policy)
	if err != nil {
		log.Printf("[agent-skill] invalid network policy for %q: %v", tenant, err)
		return
	}
	if err := s.netpolicy.Store().Set(ctx, compiled.ToProto()); err != nil {
		log.Printf("[agent-skill] could not set network policy for %q: %v", tenant, err)
	}
}

// agentNetworkPolicyConfig reads the operator opt-ins for arming enforcement:
//   - CONTAINARIUM_AGENT_NETWORK_POLICY_ENFORCE=1 → compile the policy in
//     ENFORCE mode (drop), instead of the default LOG_ONLY (observe).
//   - CONTAINARIUM_AGENT_EGRESS_CIDRS=cidr,cidr → platform egress the agent
//     legitimately needs (daemon API, DNS resolver) added to every agent box's
//     allowlist, so ENFORCE doesn't strand the agent.
//
// Both default off/empty, so the out-of-the-box behaviour stays observe-only.
// ENFORCE additionally requires the daemon-wide eBPF enforcer to be armed
// (CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT + CONTAINARIUM_NETWORK_POLICY_ENFORCE).
// defaultAgentEgressDomains is the model-provider egress every agent box needs
// so an armed (ENFORCE) policy doesn't strand the loop (#611). All supported
// providers are allowed since a box may run any engine (Claude, Codex, or
// Gemini); the Gemini engine reaches the Gemini API at generativelanguage.googleapis.com.
var defaultAgentEgressDomains = []string{"api.anthropic.com", "api.openai.com", "generativelanguage.googleapis.com"}

func agentNetworkPolicyConfig() (extraCIDRs, extraDomains []string, enforce bool) {
	enforce = os.Getenv("CONTAINARIUM_AGENT_NETWORK_POLICY_ENFORCE") == "1"
	for _, c := range strings.Split(os.Getenv("CONTAINARIUM_AGENT_EGRESS_CIDRS"), ",") {
		if c = strings.TrimSpace(c); c != "" {
			extraCIDRs = append(extraCIDRs, c)
		}
	}
	// Model-provider egress: operator override, else the provider defaults.
	if raw, ok := os.LookupEnv("CONTAINARIUM_AGENT_EGRESS_DOMAINS"); ok {
		for _, d := range strings.Split(raw, ",") {
			if d = strings.TrimSpace(d); d != "" {
				extraDomains = append(extraDomains, d)
			}
		}
	} else {
		extraDomains = append(extraDomains, defaultAgentEgressDomains...)
	}
	return extraCIDRs, extraDomains, enforce
}

// callerSkillID recovers the skill id of the agent making an A2A call. The
// authenticated token subject wins (an agent box's JWT subject is
// agent-<skill-id>); otherwise it falls back to the caller-asserted value.
func (s *AgentSkillServer) callerSkillID(ctx context.Context, asserted string) string {
	// Use the same gRPC-metadata subject the rest of the server authenticates
	// on (RequireScope / AuthorizeTenant). The authenticated subject is the
	// real boundary; the caller-asserted from_skill_id is only a fallback for
	// non-agent callers (admin/operator), who aren't gated here anyway.
	if subj, _, ok := auth.SubjectFromGRPCContext(ctx); ok && strings.HasPrefix(subj, agentBoxPrefix) {
		return strings.TrimPrefix(subj, agentBoxPrefix)
	}
	return asserted
}

// peerAllowed reports whether the calling skill may send to toPeer per its
// declared allowed_peers. An unknown/empty caller (admin or operator direct
// call, not an agent box) is allowed — for box-originated traffic the eBPF
// egress policy is the hard boundary; this is the API-boundary courtesy check.
func (s *AgentSkillServer) peerAllowed(fromSkillID, toPeerID string) bool {
	if fromSkillID == "" {
		return true
	}
	skill, err := s.catalog.Get(fromSkillID)
	if err != nil {
		return true // unknown caller skill — not ours to gate here
	}
	for _, p := range skill.AllowedPeers {
		if p == toPeerID {
			return true
		}
	}
	return false
}

// resolvePeerIP returns a running peer box's IPv4 address, if any. Used to turn
// an allowed_peer skill id into an egress /32 at launch.
func (s *AgentSkillServer) resolvePeerIP(peerID string) (string, bool) {
	info, err := s.recipes.containers.manager.Get("agent-" + peerID)
	if err != nil || info == nil || info.IPAddress == "" {
		return "", false
	}
	return info.IPAddress, true
}

// compileAllowedPeersPolicy builds a per-box egress NetworkPolicy from a skill's
// allowed_peers: each currently-running peer's box IP becomes an egress /32.
// Pure (resolution is injected) so it is unit-testable without a daemon. The
// policy is LOG_ONLY — observe, never drop — until Phase 2 enforcement is armed.
// compileAllowedPeersPolicy builds a skill box's egress policy. gatewayCIDR
// pins the box to the model-gateway (#674 inc 4): when set, the box's model
// egress is the gateway host (gatewayCIDR — also the daemon API + DNS) and the
// direct provider domains are DROPPED, so a box can't bypass the gateway to
// reach a provider with a key it doesn't hold. When empty (direct mode) the
// box gets the provider domains directly, as before.
func compileAllowedPeersPolicy(tenant string, allowedPeers []string, resolve func(peerID string) (string, bool), extraCIDRs, extraDomains []string, gatewayCIDR string, enforce bool) *pb.NetworkPolicy {
	var cidrs []string
	for _, peer := range allowedPeers {
		if ip, ok := resolve(peer); ok {
			cidrs = append(cidrs, ip+"/32")
		}
	}
	// Platform egress the agent legitimately needs (daemon API, DNS) so an
	// armed ENFORCE policy doesn't strand the agent.
	cidrs = append(cidrs, extraCIDRs...)

	// Gateway pinning: allow the gateway host (model calls go here) and serve no
	// direct provider domains. Without a gateway, fall back to direct provider
	// egress.
	domains := extraDomains
	if gatewayCIDR != "" {
		cidrs = append(cidrs, gatewayCIDR)
		domains = nil
	}

	mode := pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY
	if enforce {
		mode = pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE
	}
	return &pb.NetworkPolicy{
		Tenant:           tenant,
		AllowIntraTenant: false,
		EgressCidrs:      cidrs,
		// Direct model-provider egress (resolved to IPs by the enforcer's domain
		// resolver) so the in-box loop can reach the Claude/OpenAI API (#611) —
		// EMPTY in gateway mode, where model calls go through gatewayCIDR instead.
		EgressDomains: domains,
		Mode:          mode,
		AllowMetadata: false,
		Source:        "agent-skill",
	}
}

// SendAgentTask delegates a task to a running peer agent over A2A and returns
// the peer's artifact (Phase 1 transport). Gated on agents:call.
//
// Phase 2 will enforce that to_peer_id is in the from-skill's allowed_peers and
// that network policy permits the hop (the eBPF "trust fabric"); in Phase 1 the
// send is best-effort. The peer's in-box A2A server (which receives the task)
// is the agent-runtime image's job — until it lands, a call to a real box
// reaches no listener and returns Unavailable. The transport itself is wired
// and unit-tested (see a2a_client_test.go).
func (s *AgentSkillServer) SendAgentTask(ctx context.Context, req *pb.SendAgentTaskRequest) (*pb.SendAgentTaskResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeAgentsCall); err != nil {
		return nil, err
	}
	if req.ToPeerId == "" {
		return nil, status.Error(codes.InvalidArgument, "to_peer_id is required")
	}

	// Enforce allowed_peers at the API boundary (Phase 2). The real caller is
	// the authenticated token subject when it's an agent box (agent-<skill-id>);
	// fall back to the caller-asserted from_skill_id otherwise. This is
	// defense-in-depth + fail-fast UX — the hard boundary for raw box-originated
	// traffic is the eBPF egress policy compiled from allowed_peers.
	caller := s.callerSkillID(ctx, req.FromSkillId)

	// Correlation id for the whole delegation: honor a caller-threaded id
	// (a crew, Phase 3), else generate one. Every audit record for this hop
	// shares it.
	trace := req.TraceId
	if trace == "" {
		trace = genTraceID()
	}

	if !s.peerAllowed(caller, req.ToPeerId) {
		s.auditHop(ctx, trace, caller, req.ToPeerId, "denied", "not in allowed_peers")
		return nil, status.Errorf(codes.PermissionDenied,
			"skill %q is not permitted to call peer %q (not in its allowed_peers)", caller, req.ToPeerId)
	}

	baseURL, _, err := s.resolvePeerA2A(req.ToPeerId)
	if err != nil {
		s.auditHop(ctx, trace, caller, req.ToPeerId, "unreachable", err.Error())
		return nil, err
	}

	task := &pb.AgentTask{
		Id:        "task-" + caller + "-" + req.ToPeerId,
		InputJson: req.InputJson,
	}
	art, err := sendA2ATask(ctx, baseURL, task)
	if err != nil {
		s.auditHop(ctx, trace, caller, req.ToPeerId, "failed", err.Error())
		return nil, status.Errorf(codes.Unavailable, "deliver task to peer %q: %v", req.ToPeerId, err)
	}
	s.auditHop(ctx, trace, caller, req.ToPeerId, "delivered", "")
	return &pb.SendAgentTaskResponse{Artifact: art, TraceId: trace}, nil
}

// genTraceID returns a random 128-bit hex correlation id for an A2A run.
func genTraceID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// rand failure is effectively impossible; fall back to a time nonce so
		// the trace is still non-empty rather than colliding on "".
		return fmt.Sprintf("t%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// auditHop records one A2A delegation under the shared trace id. Best-effort:
// audit must never fail the call. No-op until the audit store is wired.
//
// #1678 — an A2A call is agent-performed: username (from) is the agent's own
// synthetic subject, so this also resolves and records the dispatching
// human (auth.RootActor, walked from the caller's delegation chain) and the
// acting token's jti, per the AC that every agent-performed action records
// both.
func (s *AgentSkillServer) auditHop(ctx context.Context, trace, from, to, outcome, detail string) {
	if s.audit == nil {
		return
	}
	username := from
	if username == "" {
		username = "_unknown"
	}
	payload, _ := json.Marshal(map[string]string{
		"trace_id": trace,
		"from":     from,
		"to":       to,
		"outcome":  outcome,
		"detail":   detail,
	})

	actor, delegationChain, tokenID := auditAttributionFromContext(ctx)

	if err := s.audit.Log(ctx, &audit.AuditEntry{
		Username:        username,
		Action:          "agent.a2a_call",
		ResourceType:    "agent_skill",
		ResourceID:      to,
		Detail:          string(payload),
		Actor:           actor,
		DelegationChain: delegationChain,
		TokenID:         tokenID,
	}); err != nil {
		log.Printf("[agent-skill] audit A2A hop %s->%s: %v", from, to, err)
	}
}

// ---- run-lease audit rows (#1817, design §5) --------------------------------
//
// Two rows per run, both ResourceType "agent_skill_run" with the run id as
// ResourceID and RunID. Detail is marshalled from the named structs below
// rather than a map, so the shape an operator queries is declared in one place
// and a typo is a compile error.

// runLeaseCredential is one minted credential as it appears in an audit row.
// Exp is RFC3339 so a reader can tell when the credential dies on its own,
// independent of whether the revoke landed.
type runLeaseCredential struct {
	Kind string `json:"kind"`
	JTI  string `json:"jti"`
	Exp  string `json:"exp"`
}

// runLeaseIssueDetail is the Detail of agent.run_lease_issue: what this run was
// given, and where.
type runLeaseIssueDetail struct {
	RunID       string               `json:"run_id"`
	Box         string               `json:"box"`
	Credentials []runLeaseCredential `json:"credentials"`
}

// runLeaseEndDetail is the Detail of agent.run_lease_end: what actually
// happened when the run's authority was taken back.
type runLeaseEndDetail struct {
	RunID       string   `json:"run_id"`
	Reason      string   `json:"reason"`
	Revoked     []string `json:"revoked"`
	Unrevoked   []string `json:"unrevoked"`
	Wiped       bool     `json:"wiped"`
	DirsRemoved bool     `json:"dirs_removed"` // #1860: the seed dir + workspace are gone
	Errors      []string `json:"errors"`
}

func runLeaseIssuePayload(lease runlease.Lease) string {
	d := runLeaseIssueDetail{
		RunID:       lease.RunID,
		Box:         lease.Box,
		Credentials: make([]runLeaseCredential, 0, len(lease.Credentials)),
	}
	for _, c := range lease.Credentials {
		d.Credentials = append(d.Credentials, runLeaseCredential{
			Kind: string(c.Kind), JTI: c.JTI, Exp: c.ExpiresAt.UTC().Format(time.RFC3339),
		})
	}
	b, _ := json.Marshal(d)
	return string(b)
}

func runLeaseEndPayload(lease runlease.Lease, reason string, out runlease.Outcome) string {
	d := runLeaseEndDetail{
		RunID:  lease.RunID,
		Reason: reason,
		// Non-nil so the row reads "nothing here" rather than JSON null.
		Revoked:     append([]string{}, out.Revoked...),
		Unrevoked:   append([]string{}, out.Unrevoked...),
		Wiped:       out.Wiped,
		DirsRemoved: out.DirsRemoved,
		Errors:      make([]string, 0, len(out.Errs)),
	}
	for _, err := range out.Errs {
		d.Errors = append(d.Errors, err.Error())
	}
	b, _ := json.Marshal(d)
	return string(b)
}

// auditRunLease writes one run-lease row. Best-effort and a no-op until the
// audit store is wired, exactly like auditHop.
//
// TokenID stays the CALLER's jti (auditAttributionFromContext): "what did this
// credential do" must keep meaning the credential that made the call. The jtis
// this run was issued live in Detail.
//
// Both rows are written on a context detached from the caller's and bounded by
// auditWriteBudget — the detach and the deadline live HERE, in the one place
// both call sites go through, so neither can get one without the other:
//
//   - Detached, because a run lease exists precisely for the caller-cancel
//     path. On the RPC context the issue row would be the single write that
//     fails exactly when the cancellation happens, leaving a run with an end
//     row and no issue row.
//   - Bounded, because the write takes a global advisory lock with no timeout
//     of its own (see auditWriteBudget).
//
// Attribution still comes off the ORIGINAL ctx: WithoutCancel keeps the
// values (gRPC metadata, claims) and drops only the cancellation.
func (s *AgentSkillServer) auditRunLease(ctx context.Context, action, runID, detail string) {
	if s.audit == nil {
		return
	}
	username, _, _ := auth.SubjectFromGRPCContext(ctx)
	if username == "" {
		username = "_unknown"
	}
	actor, delegationChain, tokenID := auditAttributionFromContext(ctx)

	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditWriteBudget)
	defer cancel()

	if err := s.audit.Log(wctx, &audit.AuditEntry{
		Username:        username,
		Action:          action,
		ResourceType:    "agent_skill_run",
		ResourceID:      runID,
		Detail:          detail,
		Actor:           actor,
		DelegationChain: delegationChain,
		TokenID:         tokenID,
		RunID:           runID,
	}); err != nil {
		log.Printf("[agent-skill] audit %s for run %s: %v", action, runID, err)
	}
}

// auditAttributionFromContext resolves the #1678 audit attribution fields
// from an authenticated request context: actor is the root human/service
// principal at the base of the caller's delegation chain (auth.RootActor),
// delegationChain is that chain's own JSON serialization (kept for full
// depth reconstruction beyond what the flat actor column shows), and
// tokenID is the acting token's jti. All three are "" when the context
// carries no delegation claim / no jti — the valid, backward-compatible
// case for a direct (non-delegated) or pre-#1677/#1678 caller.
//
// Extracted as a pure function (no audit.Store dependency) specifically so
// it's unit-testable without a live Postgres — auditHop's own Log() call
// only runs against a real *audit.Store, which the test suite can't fake.
func auditAttributionFromContext(ctx context.Context) (actor, delegationChain, tokenID string) {
	if act, ok := auth.ActFromGRPCContext(ctx); ok {
		actor = auth.RootActor(act)
		if encoded, err := json.Marshal(act); err == nil {
			delegationChain = string(encoded)
		}
	}
	tokenID, _ = auth.JTIFromGRPCContext(ctx)
	return actor, delegationChain, tokenID
}

// resolvePeerA2A finds a running peer's in-box A2A base URL and its agent card.
// The peer is addressed by skill id; its box is named agent-<skill-id> (the
// deterministic name RunAgentSkill assigns). Returns FailedPrecondition when
// the peer is not running.
func (s *AgentSkillServer) resolvePeerA2A(peerID string) (string, *pb.AgentCard, error) {
	skill, err := s.catalog.Get(peerID)
	if err != nil {
		return "", nil, status.Error(codes.NotFound, err.Error())
	}
	name := "agent-" + peerID
	info, err := s.recipes.containers.manager.Get(name)
	if err != nil || info == nil || info.IPAddress == "" {
		return "", nil, status.Errorf(codes.FailedPrecondition,
			"peer %q is not running (no box %q with an IP); run it first with 'containarium agent run %s'",
			peerID, name+"-container", peerID)
	}
	baseURL := fmt.Sprintf("http://%s:%d", info.IPAddress, a2aPort)
	return baseURL, skill.AgentCard, nil
}

// buildAgentSeedScript writes the skill's system prompt, scoped token, task
// input, and agent card under agentSeedDir with restrictive permissions. The
// agent card lets the box's A2A server (Phase 1) serve it for peer discovery.
// Values are single-quote escaped (shellSingleQuote, from recipe_server.go) to
// prevent shell injection.
func buildAgentSeedScript(seedDir, systemPrompt, token, inputJSON, cardJSON string) string {
	if inputJSON == "" {
		inputJSON = "{}"
	}
	if cardJSON == "" {
		cardJSON = "{}"
	}
	var b strings.Builder
	b.WriteString("set -euo pipefail\n")
	b.WriteString("umask 077\n")
	fmt.Fprintf(&b, "mkdir -p %s\n", seedDir)
	fmt.Fprintf(&b, "printf '%%s' %s > %s/system_prompt.txt\n", shellSingleQuote(systemPrompt), seedDir)
	fmt.Fprintf(&b, "printf '%%s' %s > %s/token\n", shellSingleQuote(token), seedDir)
	fmt.Fprintf(&b, "printf '%%s' %s > %s/input.json\n", shellSingleQuote(inputJSON), seedDir)
	fmt.Fprintf(&b, "printf '%%s' %s > %s/agent-card.json\n", shellSingleQuote(cardJSON), seedDir)
	fmt.Fprintf(&b, "chmod 600 %s/token\n", seedDir)
	return b.String()
}
