package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/footprintai/containarium/internal/auth"
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

// SandboxServer implements SandboxService (#1488 Phase 1): the two-digit-ms
// spawn path's cold-path implementation. A sandbox has no per-tenant Linux
// account and no SSH — these five RPCs are its entire access surface.
//
// Talks to incus.Backend directly rather than going through
// pkg/core/container.Manager: Manager.Create is the full persistent-box
// identity flow (jump-server account, in-guest user, SSH keys) that
// sandboxes are explicitly scoped to skip. Reusing it would mean threading
// a "skip everything" option through a function whose entire shape is that
// provisioning.
type SandboxServer struct {
	pb.UnimplementedSandboxServiceServer
	incus incus.Backend
}

// NewSandboxServer constructs a SandboxServer over the given Incus backend.
func NewSandboxServer(backend incus.Backend) *SandboxServer {
	return &SandboxServer{incus: backend}
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

// SpawnSandbox implements the two-digit-ms spawn path's Phase 1 cold
// fallback: every call creates a fresh container. served_from is always
// COLD until Phase 3 adds the warm pool.
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

	id, err := newSandboxID()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}

	ttl := time.Duration(req.IdleTtlSeconds) * time.Second
	if ttl <= 0 {
		ttl = defaultSandboxIdleTTL
	}
	now := time.Now()

	config := incus.ContainerConfig{
		Name:  id,
		Image: image,
		ExtraConfig: map[string]string{
			SandboxKindLabelKey:                         SandboxKindLabelValue,
			incus.TenantLabelKey:                        subject,
			incus.LabelPrefix + "sandbox-template":      template.String(),
			incus.LabelPrefix + "sandbox-idle-ttl-secs": fmt.Sprintf("%d", int64(ttl.Seconds())),
		},
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
		ExitCode: int32(exitCode),
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
// means destroy, never "return to a pool".
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

	if err := s.destroy(req.SandboxId); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete sandbox: %v", err)
	}

	return &pb.DeleteSandboxResponse{Message: fmt.Sprintf("sandbox %s deleted", req.SandboxId)}, nil
}
