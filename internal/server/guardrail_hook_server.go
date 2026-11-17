package server

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"sync/atomic"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/guardraildropin"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// guardrailHookSetAction is the audit action every successful switch writes.
const guardrailHookSetAction = "guardrail.hook.set"

type guardrailHookAuditDetail struct {
	Enabled  bool   `json:"enabled"`
	Coverage string `json:"coverage"`
}

// guardrailHookManager is the slice of *guardraildropin.Manager served here.
type guardrailHookManager interface {
	SetEnabled(username string, enabled bool) (guardraildropin.BoxCoverage, error)
	Coverage(username string) (guardraildropin.BoxCoverage, error)
	List() ([]guardraildropin.BoxCoverage, error)
}

// GuardrailHookServer serves the per-box switch of the managed guardrail
// hook drop-in and its coverage (#3762). Set and List are admin-only: the
// switch is the operator's, and a box's own tenant must not be able to turn
// it off. Get is open to the box's tenant. A scoped token also needs
// security:write (Set) or security:read (Get, List).
type GuardrailHookServer struct {
	pb.UnimplementedGuardrailHookServiceServer
	// mgr is set once the daemon has an Incus client; nil on a runtime with
	// no root path into a box.
	mgr   atomic.Pointer[guardrailHookManager]
	audit auditLogger
}

func NewGuardrailHookServer() *GuardrailHookServer { return &GuardrailHookServer{} }

func (s *GuardrailHookServer) SetManager(m guardrailHookManager) { s.mgr.Store(&m) }

// SetAuditStore wires the audit store once the Postgres pool exists. The nil
// check keeps a nil *audit.Store from becoming a non-nil interface.
func (s *GuardrailHookServer) SetAuditStore(store *audit.Store) {
	if store != nil {
		s.audit = store
	}
}

func (s *GuardrailHookServer) manager() (guardrailHookManager, error) {
	if m := s.mgr.Load(); m != nil {
		return *m, nil
	}
	return nil, status.Error(codes.Unavailable, "the guardrail hook drop-in needs the daemon's root path into a box, which this runtime does not have")
}

func guardrailHookError(err error) error {
	if errors.Is(err, guardraildropin.ErrBoxNotFound) {
		return status.Error(codes.NotFound, err.Error())
	}
	return status.Errorf(codes.Internal, "guardrail hook: %v", err)
}

func toProtoGuardrailHookBox(b guardraildropin.BoxCoverage) *pb.GuardrailHookBoxCoverage {
	out := &pb.GuardrailHookBoxCoverage{
		Username: b.Username, Enabled: b.Enabled, Coverage: b.Coverage, Detail: b.Detail, ClientVersion: b.ClientVersion,
	}
	if !b.CheckedAt.IsZero() {
		out.CheckedAt = timestamppb.New(b.CheckedAt)
	}
	return out
}

func (s *GuardrailHookServer) SetGuardrailHook(ctx context.Context, req *pb.SetGuardrailHookRequest) (*pb.SetGuardrailHookResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeSecurityWrite); err != nil {
		return nil, err
	}
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	if req.GetUsername() == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	mgr, err := s.manager()
	if err != nil {
		return nil, err
	}
	box, err := mgr.SetEnabled(req.GetUsername(), req.GetEnabled())
	if err != nil {
		return nil, guardrailHookError(err)
	}
	s.auditSet(ctx, box)
	return &pb.SetGuardrailHookResponse{Box: toProtoGuardrailHookBox(box)}, nil
}

// auditSet records the switch. Best-effort, like guardrail.policy.set: the
// switch is already applied.
func (s *GuardrailHookServer) auditSet(ctx context.Context, box guardraildropin.BoxCoverage) {
	subject, _, _ := auth.SubjectFromGRPCContext(ctx)
	log.Printf("[guardrail-hook] %s set enabled=%t for %s: %s", subject, box.Enabled, box.Username, box.Coverage)
	if s.audit == nil {
		return
	}
	payload, err := json.Marshal(guardrailHookAuditDetail{Enabled: box.Enabled, Coverage: box.Coverage.String()})
	if err != nil {
		return
	}
	if err := s.audit.Log(ctx, &audit.AuditEntry{
		Username: subject, Action: guardrailHookSetAction, ResourceType: "container", ResourceID: box.Username, Detail: string(payload),
	}); err != nil {
		log.Printf("[guardrail-hook] audit %s for %s: %v", guardrailHookSetAction, box.Username, err)
	}
}

func (s *GuardrailHookServer) GetGuardrailHookCoverage(ctx context.Context, req *pb.GetGuardrailHookCoverageRequest) (*pb.GetGuardrailHookCoverageResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeSecurityRead); err != nil {
		return nil, err
	}
	if req.GetUsername() == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if err := auth.AuthorizeTenant(ctx, req.GetUsername()); err != nil {
		return nil, err
	}
	mgr, err := s.manager()
	if err != nil {
		return nil, err
	}
	box, err := mgr.Coverage(req.GetUsername())
	if err != nil {
		return nil, guardrailHookError(err)
	}
	return &pb.GetGuardrailHookCoverageResponse{Box: toProtoGuardrailHookBox(box)}, nil
}

func (s *GuardrailHookServer) ListGuardrailHookCoverage(ctx context.Context, _ *pb.ListGuardrailHookCoverageRequest) (*pb.ListGuardrailHookCoverageResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeSecurityRead); err != nil {
		return nil, err
	}
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	mgr, err := s.manager()
	if err != nil {
		return nil, err
	}
	boxes, err := mgr.List()
	if err != nil {
		return nil, guardrailHookError(err)
	}
	out := &pb.ListGuardrailHookCoverageResponse{}
	for _, b := range boxes {
		out.Boxes = append(out.Boxes, toProtoGuardrailHookBox(b))
	}
	return out, nil
}
