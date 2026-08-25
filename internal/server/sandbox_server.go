package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/safecast"
	"github.com/footprintai/containarium/internal/sandbox/pool"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// sandboxKindLabelSuffix marks an Incus instance as an ephemeral sandbox
// (SandboxService), distinct from a persistent tenant box. Listing/reaping
// code that iterates ContainerService's tenant boxes should skip instances
// carrying this label — not yet wired in Phase 1, since sandbox names
// (sandbox-<id>) don't collide with the <username>-container convention
// those paths key on, but worth flagging for whoever adds a sandbox-aware
// sweep.
const sandboxKindLabelSuffix = "kind"

// SandboxKindLabelKey is the full Incus config key
// (incus.LabelPrefix-qualified) written via ContainerConfig.ExtraConfig at
// spawn time.
const SandboxKindLabelKey = incus.LabelPrefix + sandboxKindLabelSuffix

// SandboxKindLabelValue is the label's value on every sandbox.
const SandboxKindLabelValue = "sandbox"

// sandboxNamePrefix names every sandbox's Incus container: sandbox-<12 hex
// chars>. The sandbox_id IS the Incus container name — no separate mapping
// table, matching how a tenant's container name IS its box.BoxRef.Tenant +
// "-container" elsewhere in this codebase.
const sandboxNamePrefix = "sandbox-"

// defaultSandboxIdleTTL applies when SpawnSandboxRequest.idle_ttl_seconds is
// unset (0). No sweeper enforces it yet in Phase 1 (see the design note's
// Phase 4) — expires_at is reported so a caller can see the horizon its
// sandbox will eventually be reaped against once the sweeper exists.
const defaultSandboxIdleTTL = 30 * time.Minute

// spawnNetworkTimeout bounds how long SpawnSandbox waits for the guest's
// network to come up. Same bound container.Manager.Create uses for the
// equivalent wait.
const spawnNetworkTimeout = 30 * time.Second

// SandboxServer implements SandboxService: the two-digit-ms spawn path. A
// sandbox has no per-tenant Linux account and no SSH — these five RPCs are
// its entire access surface.
//
// Talks to incus.Backend directly rather than going through
// pkg/core/container.Manager: Manager.Create is the full persistent-box
// identity flow (jump-server account, in-guest user, SSH keys) that
// sandboxes are explicitly scoped to skip. Reusing it would mean threading
// a "skip everything" option through a function whose entire shape is that
// provisioning.
//
// pool is optional (#1488 Phase 3). nil means every spawn takes the cold
// path — today's exact Phase 1 behavior, including for a caller that never
// sets allow_cold_start (its zero value is false): admission control
// (RESOURCE_EXHAUSTED on an exhausted pool) only ever applies when a pool
// is actually configured. A configured-but-untargeted pool (no ready
// member for a requested template) is indistinguishable from "no pool at
// all" from SpawnSandbox's perspective — both fall through to cold,
// subject to the same allow_cold_start gate.
type SandboxServer struct {
	pb.UnimplementedSandboxServiceServer
	incus incus.Backend
	pool  *pool.Pool

	// claimed tracks, per pool-claimed sandbox_id, the pool.Member Claim
	// returned — DeleteSandbox needs it to route to pool.Release (which
	// also frees the member's IPAM address) instead of destroy() (which
	// doesn't know about IPAM at all; a cold-path sandbox never has an
	// address to free). In-memory only: like container_server.go's own
	// pendingCreations, a claimed-but-not-yet-deleted sandbox's tracking
	// doesn't survive a daemon restart — no different in kind from every
	// other piece of this daemon's in-flight state, and sandboxes are
	// short-lived by design.
	claimedMu sync.Mutex
	claimed   map[string]*pool.Member
}

// NewSandboxServer constructs a SandboxServer over the given Incus backend.
// p is optional; nil disables pool-backed spawns (see the type doc).
func NewSandboxServer(backend incus.Backend, p *pool.Pool) *SandboxServer {
	return &SandboxServer{incus: backend, pool: p, claimed: make(map[string]*pool.Member)}
}

// StartReconciler runs pool.Reconcile on interval until ctx is done. No-op
// if s.pool is nil (no pool configured). Same ticker shape as this
// package's other background loops (see startIntegrityHeartbeat in
// dual_server.go): one immediate reconcile so a freshly-started daemon
// doesn't wait a full interval before warming its first members, then on
// the cadence.
func (s *SandboxServer) StartReconciler(ctx context.Context, interval time.Duration) {
	if s.pool == nil {
		return
	}

	s.pool.Reconcile(ctx)
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.pool.Reconcile(ctx)
			}
		}
	}()
}

// newSandboxID generates a sandbox_id / Incus container name: sandbox- plus
// 12 hex characters (6 random bytes) — collision odds low enough that a
// create-time name clash is not worth handling as anything other than the
// CreateContainer error it would surface.
func newSandboxID() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate sandbox id: %w", err)
	}
	return sandboxNamePrefix + hex.EncodeToString(b), nil
}

// resolveTemplate maps a requested template to its guest image.
// SANDBOX_TEMPLATE_UNSPECIFIED resolves to BASE, mirroring
// ostype.ImageForOSType's unspecified-defaults-to-Ubuntu convention. Any
// other value is rejected: v1 ships BASE only (see the proto's doc comment
// on SandboxTemplate), and silently falling back would let a caller depend
// on a template that doesn't actually exist yet.
func resolveTemplate(t pb.SandboxTemplate) (resolved pb.SandboxTemplate, image string, err error) {
	switch t {
	case pb.SandboxTemplate_SANDBOX_TEMPLATE_UNSPECIFIED, pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE:
		return pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE, "images:ubuntu/24.04", nil
	default:
		return t, "", status.Errorf(codes.InvalidArgument, "unsupported sandbox template %v (v1 ships SANDBOX_TEMPLATE_BASE only)", t)
	}
}

// destroy stops (force, errors ignored — deleting a stopped or a still-
// running instance both work) then deletes name, returning the delete
// error. Same shape as pkg/core/container.Manager.cleanup, duplicated
// rather than shared because SandboxServer deliberately does not depend on
// container.Manager (see the type doc). A spawn-failure rollback discards
// the returned error (the spawn already failed); DeleteSandbox propagates
// it — a caller asking to delete needs to know if that didn't happen.
func (s *SandboxServer) destroy(name string) error {
	_ = s.incus.StopContainer(name, true)
	return s.incus.DeleteContainer(name)
}

// SpawnSandbox tries the warm pool first (#1488 Phase 3, served_from =
// POOL) when one is configured, and falls back to the cold path
// (served_from = COLD) otherwise: pool disabled, or the requested
// template's ready ring is empty and the caller set allow_cold_start. An
// exhausted pool with allow_cold_start unset (false) returns
// RESOURCE_EXHAUSTED instead of silently paying the cold path's cost — a
// latency SLO whose slow path is invisible isn't an SLO.
func (s *SandboxServer) SpawnSandbox(ctx context.Context, req *pb.SpawnSandboxRequest) (*pb.SpawnSandboxResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeSandboxesWrite); err != nil {
		return nil, err
	}
	subject, _, ok := auth.SubjectFromGRPCContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no authenticated subject")
	}

	template, image, err := resolveTemplate(req.Template)
	if err != nil {
		return nil, err
	}

	if s.pool != nil {
		resp, err := s.claimFromPool(template, subject, req)
		switch {
		case err == nil:
			return resp, nil
		case !errors.Is(err, pool.ErrPoolExhausted):
			// A member was actually claimed (removed from the ring) but
			// setup failed after that — a real error, not "no pool
			// member available." claimFromPool already unwound it.
			return nil, err
		case !req.AllowColdStart:
			return nil, status.Errorf(codes.ResourceExhausted,
				"no warm %s sandbox available; retry, or set allow_cold_start=true for the slower cold-create path", template)
		}
		// Exhausted, but the caller opted into the cold path — fall
		// through to it below, exactly like a nil pool would.
	}

	id, err := newSandboxID()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}

	ttl := sandboxTTL(req.IdleTtlSeconds)
	now := time.Now()

	extraConfig := qualifyLabels(sandboxLabelSuffixes(template, ttl))
	extraConfig[incus.TenantLabelKey] = subject
	config := incus.ContainerConfig{
		Name:        id,
		Image:       image,
		ExtraConfig: extraConfig,
	}

	if err := s.incus.CreateContainer(config); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create sandbox: %v", err)
	}
	if err := s.incus.StartContainer(id); err != nil {
		_ = s.incus.DeleteContainer(id)
		return nil, status.Errorf(codes.Internal, "failed to start sandbox: %v", err)
	}
	if _, err := s.incus.WaitForNetwork(id, spawnNetworkTimeout); err != nil {
		_ = s.destroy(id)
		return nil, status.Errorf(codes.Internal, "sandbox network did not come up: %v", err)
	}

	return &pb.SpawnSandboxResponse{
		Sandbox: &pb.Sandbox{
			SandboxId:  id,
			State:      pb.SandboxState_SANDBOX_STATE_RUNNING,
			Template:   template,
			ServedFrom: pb.ServedFrom_SERVED_FROM_COLD,
			CreatedAt:  timestamppb.New(now),
			ExpiresAt:  timestamppb.New(now.Add(ttl)),
		},
	}, nil
}

// sandboxTTL resolves a request's idle_ttl_seconds to a concrete duration,
// applying defaultSandboxIdleTTL when unset (<= 0).
func sandboxTTL(idleTTLSeconds int32) time.Duration {
	ttl := time.Duration(idleTTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = defaultSandboxIdleTTL
	}
	return ttl
}

// sandboxLabelSuffixes builds the (bare, unqualified) label keys every
// sandbox carries once fully provisioned, regardless of which path
// created it — shared by the cold path (via qualifyLabels, below) and
// claimFromPool's post-claim SetLabels so the two constructions can't
// drift into stamping different keys.
//
// Bare because that's SetLabels' own contract — it adds incus.LabelPrefix
// itself, so passing an already-prefixed key double-prefixes it. This
// deliberately does NOT include incus.TenantLabelKey: that key lives
// outside the LabelPrefix namespace entirely (SetLabels can't touch it —
// it only clears/rewrites LabelPrefix-prefixed keys), so it's set
// separately via SetConfig everywhere it's needed.
func sandboxLabelSuffixes(template pb.SandboxTemplate, ttl time.Duration) map[string]string {
	return map[string]string{
		sandboxKindLabelSuffix:  SandboxKindLabelValue,
		"sandbox-template":      template.String(),
		"sandbox-idle-ttl-secs": fmt.Sprintf("%d", int64(ttl.Seconds())),
	}
}

// qualifyLabels prefixes each key with incus.LabelPrefix, for a caller
// (the cold path's CreateContainer ExtraConfig) that needs fully-qualified
// keys rather than SetLabels' bare ones.
func qualifyLabels(suffixes map[string]string) map[string]string {
	qualified := make(map[string]string, len(suffixes))
	for k, v := range suffixes {
		qualified[incus.LabelPrefix+k] = v
	}
	return qualified
}

// claimFromPool attempts to serve a spawn from the warm pool: claim a
// ready member, then stamp its ownership — a warmed-but-unclaimed member
// carries none of it, since the pool has no notion of tenant — so the
// existing ownership/lookup path (lookupOwnedSandbox) recognizes it
// exactly like a cold-path sandbox.
//
// Returns pool.ErrPoolExhausted unchanged when there is simply no ready
// member; the caller (SpawnSandbox) decides whether that's RESOURCE_EXHAUSTED
// or a signal to fall back to the cold path. Any OTHER error means a
// member WAS claimed (removed from the ring) but setup failed after that —
// claimFromPool destroys it via pool.Release before returning, rather than
// leaking a claimed member with no sandbox_id a caller could ever use to
// clean it up: unlabeled (lookupOwnedSandbox wouldn't recognize it as a
// sandbox at all) or unowned (info.Tenant == "" fails the ownership check
// for everyone but an admin, including the tenant who thinks they just
// spawned it).
//
// Two Incus round-trip PAIRS on the claim path — SetConfig for the tenant
// key (outside the label namespace, see sandboxLabelSuffixes) plus
// SetLabels for kind/template/ttl — because no existing incus.Backend
// primitive sets both a raw config key and a batch of labels in one call.
// This is real, and it's the piece of "two-digit ms" this integration
// does not yet fully deliver on; a combined bulk-set primitive is a
// legitimate follow-up once real latency numbers (Phase 3's own exit
// criterion) show it's worth adding.
func (s *SandboxServer) claimFromPool(template pb.SandboxTemplate, subject string, req *pb.SpawnSandboxRequest) (*pb.SpawnSandboxResponse, error) {
	member, err := s.pool.Claim(template)
	if err != nil {
		return nil, err
	}

	ttl := sandboxTTL(req.IdleTtlSeconds)
	now := time.Now()

	if err := s.incus.SetConfig(member.ID, incus.TenantLabelKey, subject); err != nil {
		s.releaseFailedClaim(member, "set tenant", err)
		return nil, status.Errorf(codes.Internal, "claimed a warm sandbox but failed to set its owner: %v", err)
	}
	if err := s.incus.SetLabels(member.ID, sandboxLabelSuffixes(template, ttl)); err != nil {
		s.releaseFailedClaim(member, "set labels", err)
		return nil, status.Errorf(codes.Internal, "claimed a warm sandbox but failed to label it: %v", err)
	}

	s.trackClaimed(member)

	return &pb.SpawnSandboxResponse{
		Sandbox: &pb.Sandbox{
			SandboxId:  member.ID,
			State:      pb.SandboxState_SANDBOX_STATE_RUNNING,
			Template:   template,
			ServedFrom: pb.ServedFrom_SERVED_FROM_POOL,
			CreatedAt:  timestamppb.New(member.WarmedAt),
			ExpiresAt:  timestamppb.New(now.Add(ttl)),
		},
	}, nil
}

// releaseFailedClaim destroys member after a post-claim setup step
// (naming which one, for the log) failed, so a member that can never be
// correctly reached or owned doesn't sit around leaked instead of going
// back through the normal destroy-on-release path. Best-effort: if the
// release ALSO fails, there is nothing left to do but say so loudly —
// this member is now genuinely leaked and needs an operator, not a retry.
func (s *SandboxServer) releaseFailedClaim(m *pool.Member, step string, causeErr error) {
	if err := s.pool.Release(m); err != nil {
		log.Printf("[sandbox] claim %s: %s failed (%v) AND cleanup failed (%v) — this member is now leaked", m.ID, step, causeErr, err)
	}
}

// trackClaimed records that sandbox_id came from the pool, for
// DeleteSandbox to find later.
func (s *SandboxServer) trackClaimed(m *pool.Member) {
	s.claimedMu.Lock()
	s.claimed[m.ID] = m
	s.claimedMu.Unlock()
}

// untrackClaimed removes and returns the tracked pool.Member for id, or
// nil if id was never claimed from the pool (a cold-path sandbox, or an
// id this server has no record of).
func (s *SandboxServer) untrackClaimed(id string) *pool.Member {
	s.claimedMu.Lock()
	defer s.claimedMu.Unlock()
	m := s.claimed[id]
	delete(s.claimed, id)
	return m
}

// lookupOwnedSandbox fetches sandbox id and enforces ownership in one step:
// NotFound if it doesn't exist or isn't a sandbox, PermissionDenied if it
// exists but belongs to a different tenant (admins bypass the comparison).
// The ownership comparison happens immediately after the existence check,
// in the same function, so no caller of this helper can accidentally skip
// it or reorder it after some other early return — a cross-tenant
// sandbox_id must always resolve to PermissionDenied, never NotFound (the
// design note's own test list: "the ownership check must run before
// existence leaks").
func (s *SandboxServer) lookupOwnedSandbox(ctx context.Context, id string) (*incus.ContainerInfo, error) {
	subject, roles, ok := auth.SubjectFromGRPCContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no authenticated subject")
	}

	info, err := s.incus.GetContainer(id)
	// ContainerInfo.Labels is already prefix-stripped (see
	// extractLabelsFromConfig) — compare the suffix, not the
	// ExtraConfig-qualified SandboxKindLabelKey.
	if err != nil || info == nil || info.Labels[sandboxKindLabelSuffix] != SandboxKindLabelValue {
		return nil, status.Errorf(codes.NotFound, "sandbox %q not found", id)
	}

	if !auth.HasRole(roles, auth.RoleAdmin) && info.Tenant != subject {
		return nil, status.Errorf(codes.PermissionDenied, "sandbox %q belongs to a different tenant", id)
	}

	return info, nil
}

// ExecInSandbox runs one command inside the sandbox. The sandbox's only
// access surface — there is no SSH.
func (s *SandboxServer) ExecInSandbox(ctx context.Context, req *pb.ExecInSandboxRequest) (*pb.ExecInSandboxResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeSandboxesWrite); err != nil {
		return nil, err
	}
	if req.SandboxId == "" {
		return nil, status.Error(codes.InvalidArgument, "sandbox_id is required")
	}
	if len(req.Command) == 0 {
		return nil, status.Error(codes.InvalidArgument, "command is required")
	}
	if _, err := s.lookupOwnedSandbox(ctx, req.SandboxId); err != nil {
		return nil, err
	}

	stdout, stderr, exitCode, err := s.incus.ExecWithExitCode(req.SandboxId, req.Command)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "exec failed: %v", err)
	}

	return &pb.ExecInSandboxResponse{
		Stdout:   stdout,
		Stderr:   stderr,
		ExitCode: safecast.I32(exitCode),
	}, nil
}

// WriteFileInSandbox writes a file into the sandbox via the Incus file push
// API — never through a shell, so file content can never be interpreted as
// a command.
func (s *SandboxServer) WriteFileInSandbox(ctx context.Context, req *pb.WriteFileInSandboxRequest) (*pb.WriteFileInSandboxResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeSandboxesWrite); err != nil {
		return nil, err
	}
	if req.SandboxId == "" || req.Path == "" {
		return nil, status.Error(codes.InvalidArgument, "sandbox_id and path are required")
	}
	if _, err := s.lookupOwnedSandbox(ctx, req.SandboxId); err != nil {
		return nil, err
	}

	mode := req.Mode
	if mode == "" {
		mode = "0644"
	}
	if err := s.incus.WriteFile(req.SandboxId, req.Path, req.Content, mode); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to write file: %v", err)
	}

	return &pb.WriteFileInSandboxResponse{Message: fmt.Sprintf("wrote %d byte(s) to %s", len(req.Content), req.Path)}, nil
}

// ReadFileInSandbox reads a file back out of the sandbox.
func (s *SandboxServer) ReadFileInSandbox(ctx context.Context, req *pb.ReadFileInSandboxRequest) (*pb.ReadFileInSandboxResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeSandboxesRead); err != nil {
		return nil, err
	}
	if req.SandboxId == "" || req.Path == "" {
		return nil, status.Error(codes.InvalidArgument, "sandbox_id and path are required")
	}
	if _, err := s.lookupOwnedSandbox(ctx, req.SandboxId); err != nil {
		return nil, err
	}

	content, err := s.incus.ReadFile(req.SandboxId, req.Path)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to read file: %v", err)
	}

	return &pb.ReadFileInSandboxResponse{Content: content}, nil
}

// DeleteSandbox destroys the sandbox immediately. Sandboxes are never reset
// and reused (see the design note's Isolation section) — delete always
// means destroy, never "return to a pool". A pool-claimed sandbox routes
// through pool.Release rather than destroy() directly, since Release also
// frees the member's IPAM-allocated address — destroy() knows nothing
// about IPAM and a cold-path sandbox never held an allocation to free.
func (s *SandboxServer) DeleteSandbox(ctx context.Context, req *pb.DeleteSandboxRequest) (*pb.DeleteSandboxResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeSandboxesWrite); err != nil {
		return nil, err
	}
	if req.SandboxId == "" {
		return nil, status.Error(codes.InvalidArgument, "sandbox_id is required")
	}
	if _, err := s.lookupOwnedSandbox(ctx, req.SandboxId); err != nil {
		return nil, err
	}

	if member := s.untrackClaimed(req.SandboxId); member != nil {
		if err := s.pool.Release(member); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to delete sandbox: %v", err)
		}
	} else if err := s.destroy(req.SandboxId); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete sandbox: %v", err)
	}

	return &pb.DeleteSandboxResponse{Message: fmt.Sprintf("sandbox %s deleted", req.SandboxId)}, nil
}
