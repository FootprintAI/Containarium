package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/retention"
	retentionpg "github.com/footprintai/containarium/internal/retention/pgstore"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Audit actions written by RetentionService changes (#2875).
const (
	retentionPolicySetAction   = "retention.policy.set"
	retentionHoldSetAction     = "retention.hold.set"
	retentionHoldReleaseAction = "retention.hold.release"
)

// retentionAuditWindow is one changed class in a retention.policy.set entry.
type retentionAuditWindow struct {
	Class string `json:"class"`
	Days  int32  `json:"days"`
}

// retentionPolicyAuditDetail is the Detail of a retention.policy.set entry:
// the revisions and the classes the call changed.
type retentionPolicyAuditDetail struct {
	PreviousRevision int64                  `json:"previous_revision"`
	Revision         int64                  `json:"revision"`
	Windows          []retentionAuditWindow `json:"windows"`
}

// retentionHoldAuditDetail is the Detail of a hold set or release entry.
type retentionHoldAuditDetail struct {
	OrgID  string `json:"org_id"`
	Reason string `json:"reason"`
	SetBy  string `json:"set_by"`
}

// errRetentionAuditFailed marks a beforeCommit audit write that failed; the
// change was rolled back.
var errRetentionAuditFailed = errors.New("audit write failed")

// errRetentionStoreUnavailable is what every call returns while Postgres is
// configured but the retention store could not be installed at startup.
var errRetentionStoreUnavailable = errors.New("retention store unavailable: Postgres is configured but the retention store was not installed (restart the daemon once Postgres answers)")

// unavailableRetentionStore fails closed: an in-memory stand-in would accept
// holds that a restart silently drops.
type unavailableRetentionStore struct{}

func (unavailableRetentionStore) GetPolicy(context.Context) (*pb.RetentionPolicy, error) {
	return nil, errRetentionStoreUnavailable
}
func (unavailableRetentionStore) SetPolicy(context.Context, []*pb.RetentionWindow, string, func(*retention.PolicySetResult) error) (*retention.PolicySetResult, error) {
	return nil, errRetentionStoreUnavailable
}
func (unavailableRetentionStore) ListHolds(context.Context) ([]*pb.LegalHold, error) {
	return nil, errRetentionStoreUnavailable
}
func (unavailableRetentionStore) SetHold(context.Context, string, string, string, func(*pb.LegalHold) error) (*pb.LegalHold, error) {
	return nil, errRetentionStoreUnavailable
}
func (unavailableRetentionStore) ReleaseHold(context.Context, string, string, func(*pb.LegalHold) error) (*pb.LegalHold, error) {
	return nil, errRetentionStoreUnavailable
}

// retentionStartupStore picks the store: in-memory with no Postgres (logged,
// since nothing survives a restart), the Postgres store when it was
// installed, otherwise the fail-closed stand-in.
func retentionStartupStore(postgresConfigured bool, pg retention.Store) retention.Store {
	switch {
	case !postgresConfigured:
		log.Printf("Retention: no database configured; using the in-memory store (a policy or legal hold set now is lost on restart)")
		return retention.NewMemoryStore()
	case pg != nil:
		return pg
	default:
		log.Printf("Warning: retention store UNAVAILABLE: Postgres is configured but its store was not installed; retention calls fail until the daemon restarts with Postgres reachable")
		return unavailableRetentionStore{}
	}
}

// retentionSweepInterval is how often the daemon recounts what a sweep would
// remove. The report carries its generated_at, and refresh=true sweeps now.
const retentionSweepInterval = time.Hour

// newRetentionReporter builds the dry-run reporter over the retention store
// and, when the daemon has a database pool, the Postgres sources.
func newRetentionReporter(store retention.Store, pool *pgxpool.Pool) *retention.Reporter {
	unswept := retention.ChainAndBundles()
	var sources []retention.Source
	if pool != nil {
		sources = retentionpg.NewSources(pool)
	} else {
		unswept = append(unswept, retentionpg.NoDatabase()...)
	}
	return retention.NewReporter(retention.NewSweeper(store, sources, unswept))
}

// RetentionServer serves the retention policy and legal holds (#2875). Every
// RPC is admin-only; changes are audited, and a failed audit write fails the
// change. It deletes nothing: GetRetentionReport only counts.
type RetentionServer struct {
	pb.UnimplementedRetentionServiceServer
	store    retention.Store
	audit    auditLogger
	reporter *retention.Reporter
}

func NewRetentionServer(store retention.Store) *RetentionServer {
	return &RetentionServer{store: store}
}

// SetStore sets the backing store at startup, before the server serves.
func (s *RetentionServer) SetStore(store retention.Store) { s.store = store }

// SetReporter wires the dry-run sweeper's reporter (#2876) at startup. With
// none, GetRetentionReport is UNAVAILABLE.
func (s *RetentionServer) SetReporter(r *retention.Reporter) { s.reporter = r }

// SetAuditStore wires the audit store. With none, changes succeed and write
// no entry (no Postgres, REST disabled, or an audit store that failed to
// start), the same as the guardrail baseline switch.
func (s *RetentionServer) SetAuditStore(a auditLogger) {
	if a != nil {
		s.audit = a
	}
}

// retentionStatus maps a store error onto a gRPC status.
func retentionStatus(op string, err error) error {
	switch {
	case errors.Is(err, retention.ErrInvalid):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, retention.ErrHoldExists):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.Is(err, retention.ErrHoldNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, errRetentionStoreUnavailable):
		return status.Error(codes.Unavailable, err.Error())
	case errors.Is(err, errRetentionAuditFailed):
		log.Printf("[retention] %s refused: %v", op, err)
		return status.Errorf(codes.Internal, "write the audit entry for %s failed; nothing changed", op)
	default:
		return status.Errorf(codes.Internal, "%s: %v", op, err)
	}
}

// requireRetentionAdmin authorizes an admin caller and returns its name.
func (s *RetentionServer) requireRetentionAdmin(ctx context.Context) (string, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return "", err
	}
	subject, _, _ := auth.SubjectFromGRPCContext(ctx)
	return subject, nil
}

// writeAudit logs one change; its error aborts the change.
func (s *RetentionServer) writeAudit(ctx context.Context, subject, action, resourceType, resourceID string, detail any) error {
	if s.audit == nil {
		return nil
	}
	payload, err := json.Marshal(detail)
	if err != nil {
		return fmt.Errorf("%w: marshal detail: %v", errRetentionAuditFailed, err)
	}
	if err := s.audit.Log(ctx, &audit.AuditEntry{
		Username: subject, Action: action, ResourceType: resourceType, ResourceID: resourceID, Detail: string(payload),
	}); err != nil {
		return fmt.Errorf("%w: %s: %v", errRetentionAuditFailed, action, err)
	}
	return nil
}

func (s *RetentionServer) GetRetentionPolicy(ctx context.Context, _ *pb.GetRetentionPolicyRequest) (*pb.GetRetentionPolicyResponse, error) {
	if _, err := s.requireRetentionAdmin(ctx); err != nil {
		return nil, err
	}
	p, err := s.store.GetPolicy(ctx)
	if err != nil {
		return nil, retentionStatus("get retention policy", err)
	}
	return &pb.GetRetentionPolicyResponse{Policy: p}, nil
}

func (s *RetentionServer) SetRetentionPolicy(ctx context.Context, req *pb.SetRetentionPolicyRequest) (*pb.SetRetentionPolicyResponse, error) {
	subject, err := s.requireRetentionAdmin(ctx)
	if err != nil {
		return nil, err
	}
	res, err := s.store.SetPolicy(ctx, req.GetWindows(), subject, func(r *retention.PolicySetResult) error {
		d := retentionPolicyAuditDetail{PreviousRevision: r.Previous.GetRevision(), Revision: r.Current.GetRevision()}
		for _, w := range req.GetWindows() {
			d.Windows = append(d.Windows, retentionAuditWindow{Class: w.GetClass().String(), Days: w.GetDays()})
		}
		return s.writeAudit(ctx, subject, retentionPolicySetAction, "retention_policy", "cluster", d)
	})
	if err != nil {
		return nil, retentionStatus("set retention policy", err)
	}
	return &pb.SetRetentionPolicyResponse{Policy: res.Current}, nil
}

func (s *RetentionServer) ListLegalHolds(ctx context.Context, _ *pb.ListLegalHoldsRequest) (*pb.ListLegalHoldsResponse, error) {
	if _, err := s.requireRetentionAdmin(ctx); err != nil {
		return nil, err
	}
	holds, err := s.store.ListHolds(ctx)
	if err != nil {
		return nil, retentionStatus("list legal holds", err)
	}
	return &pb.ListLegalHoldsResponse{Holds: holds}, nil
}

func (s *RetentionServer) holdAudit(ctx context.Context, subject, action string) func(*pb.LegalHold) error {
	return func(h *pb.LegalHold) error {
		return s.writeAudit(ctx, subject, action, "legal_hold", h.GetOrgId(),
			retentionHoldAuditDetail{OrgID: h.GetOrgId(), Reason: h.GetReason(), SetBy: h.GetSetBy()})
	}
}

func (s *RetentionServer) SetLegalHold(ctx context.Context, req *pb.SetLegalHoldRequest) (*pb.SetLegalHoldResponse, error) {
	subject, err := s.requireRetentionAdmin(ctx)
	if err != nil {
		return nil, err
	}
	h, err := s.store.SetHold(ctx, req.GetOrgId(), req.GetReason(), subject, s.holdAudit(ctx, subject, retentionHoldSetAction))
	if err != nil {
		return nil, retentionStatus("set legal hold", err)
	}
	return &pb.SetLegalHoldResponse{Hold: h}, nil
}

func (s *RetentionServer) ReleaseLegalHold(ctx context.Context, req *pb.ReleaseLegalHoldRequest) (*pb.ReleaseLegalHoldResponse, error) {
	subject, err := s.requireRetentionAdmin(ctx)
	if err != nil {
		return nil, err
	}
	h, err := s.store.ReleaseHold(ctx, req.GetOrgId(), subject, s.holdAudit(ctx, subject, retentionHoldReleaseAction))
	if err != nil {
		return nil, retentionStatus("release legal hold", err)
	}
	return &pb.ReleaseLegalHoldResponse{Hold: h}, nil
}

func (s *RetentionServer) GetRetentionReport(ctx context.Context, req *pb.GetRetentionReportRequest) (*pb.GetRetentionReportResponse, error) {
	if _, err := s.requireRetentionAdmin(ctx); err != nil {
		return nil, err
	}
	if s.reporter == nil {
		return nil, status.Error(codes.Unavailable, "the retention sweeper is not running on this daemon")
	}
	rep, err := s.reporter.Report(ctx, req.GetRefresh())
	if err != nil {
		return nil, retentionStatus("get retention report", err)
	}
	return &pb.GetRetentionReportResponse{Report: rep}, nil
}
