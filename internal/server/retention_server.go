package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
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
	// retentionModeSetAction and retentionSweepAction are the audit actions of
	// the mode switch and of an enforced sweep (#2877).
	retentionModeSetAction = "retention.mode.set"
	retentionSweepAction   = "retention.sweep"
	// retentionSweepResultAction is the second entry of a purge of the
	// hash-chained audit_logs (#2979): the retention.sweep entry is written
	// before the purge and can name only the chain base it started from, so
	// this one, written after, names the base it ended on.
	retentionSweepResultAction = "retention.sweep.result"
)

// retentionSweeperActor is the username on the audit entry of an enforced
// sweep, which no admin runs.
const retentionSweeperActor = "retention-sweeper"

// retentionModeAuditDetail is the Detail of a retention.mode.set entry.
type retentionModeAuditDetail struct {
	PreviousMode string `json:"previous_mode"`
	Mode         string `json:"mode"`
}

// retentionSweepAuditStore is one store in a retention.sweep entry: counts
// only, never the content of a record.
type retentionSweepAuditStore struct {
	Class      string `json:"class"`
	Store      string `json:"store"`
	WindowDays int32  `json:"window_days"`
	Eligible   int64  `json:"eligible"`
	Held       int64  `json:"held"`
	// PreviousBaseID is the chain base the sweep starts from, for the
	// audit_logs store; absent when the store has no chain base (#2979).
	PreviousBaseID int64 `json:"previous_base_id,omitempty"`
}

// retentionSweepAuditDetail is the Detail of a retention.sweep entry, written
// before an enforced sweep removes anything. Eligible is what the sweep will
// try to remove; a store with a backlog above retention.MaxRemovePerStore is
// worked off over the following sweeps.
type retentionSweepAuditDetail struct {
	PolicyRevision int64                      `json:"policy_revision"`
	ActiveHolds    int64                      `json:"active_holds"`
	Stores         []retentionSweepAuditStore `json:"stores"`
}

// retentionSweepResultClass is the rows one class lost in a purge.
type retentionSweepResultClass struct {
	Class   string `json:"class"`
	Removed int64  `json:"removed"`
}

// retentionSweepResultAuditDetail is the Detail of a retention.sweep.result
// entry: ids and counts only, never the content of a row (#2979).
type retentionSweepResultAuditDetail struct {
	Store          string                      `json:"store"`
	PreviousBaseID int64                       `json:"previous_base_id,omitempty"`
	BaseID         int64                       `json:"base_id"`
	RowsRemoved    int64                       `json:"rows_removed"`
	Classes        []retentionSweepResultClass `json:"classes"`
}

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

// errRetentionEnforceNeedsAudit is why ENFORCE is refused on a daemon with no
// audit store.
var errRetentionEnforceNeedsAudit = errors.New("enforce mode needs an audit store: this daemon has none (it needs Postgres, REST enabled and a started audit store), so deletions could not be recorded; the mode stays as it is")

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
func (unavailableRetentionStore) GetMode(context.Context) (*pb.RetentionModeState, error) {
	return nil, errRetentionStoreUnavailable
}
func (unavailableRetentionStore) SetMode(context.Context, pb.RetentionMode, string, func(*retention.ModeSetResult) error) (*retention.ModeSetResult, error) {
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

// newRetentionReporter builds the reporter over the retention store
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

// retentionAnchorFunc is the anchor that bounds a purge: the lower of the local
// file's and the external bucket's latest checkpoint (audit.SafeAnchor). It
// fails closed. With a bucket configured but not built (a bad URI, no gcloud) it
// returns ok=false, so the purge gets no anchor at all rather than a file-only
// one: turning the external copy on can never be a way to purge against less
// evidence than the operator asked for.
func retentionAnchorFunc(file *audit.FileSink, bucket *audit.GCSAnchorSink, bucketURI string) (retentionpg.AnchorFunc, bool) {
	var external audit.RootSink // stays a nil interface without a bucket
	switch {
	case bucket != nil:
		external = bucket
	case strings.TrimSpace(bucketURI) != "":
		return nil, false
	}
	return func(ctx context.Context) (retentionpg.Anchor, bool, error) {
		a, ok, err := audit.SafeAnchor(ctx, file, external)
		return retentionpg.Anchor{Checkpoint: a.Checkpoint, Root: a.Root}, ok, err
	}, true
}

// RetentionServer serves the retention policy and legal holds (#2875). Every
// RPC is admin-only; changes are audited, and a failed audit write fails the
// change. The server itself deletes nothing: GetRetentionReport only counts,
// and the periodic sweep removes records only while the mode is ENFORCE.
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

// SetReporter wires the sweeper's reporter (#2876) at startup. With none,
// GetRetentionReport is UNAVAILABLE.
func (s *RetentionServer) SetReporter(r *retention.Reporter) {
	s.reporter = r
	s.wireSweepAudit()
}

// wireSweepAudit gives the reporter's sweeper the audit entry an enforced
// sweep writes, once both the reporter and the audit store are known.
func (s *RetentionServer) wireSweepAudit() {
	if s.reporter != nil && s.audit != nil {
		s.reporter.SetAuditor(s.auditSweep)
		s.reporter.SetResultAuditor(s.auditSweepResult)
	}
}

// auditSweep writes the retention.sweep entry of an enforced sweep.
func (s *RetentionServer) auditSweep(ctx context.Context, rep *pb.RetentionReport) error {
	d := retentionSweepAuditDetail{PolicyRevision: rep.GetPolicyRevision(), ActiveHolds: rep.GetActiveHolds(), Stores: []retentionSweepAuditStore{}}
	for _, st := range rep.GetStores() {
		if st.GetStatus() != pb.RetentionSweepStatus_RETENTION_SWEEP_STATUS_COUNTED {
			continue
		}
		d.Stores = append(d.Stores, retentionSweepAuditStore{
			Class: st.GetClass().String(), Store: st.GetStore(), WindowDays: st.GetWindowDays(),
			Eligible: st.GetEligible(), Held: st.GetHeld(),
			PreviousBaseID: st.GetChainBase().GetBaseId(),
		})
	}
	return s.writeAudit(ctx, retentionSweeperActor, retentionSweepAction, "retention_sweep", "cluster", d)
}

// auditSweepResult writes the retention.sweep.result entry of a prefix purge
// that removed rows (#2979): the chain base the purge ended on, written after
// the rows are gone because it did not exist before. The sweeper treats a
// failure here as non-fatal, since the purge is already committed.
func (s *RetentionServer) auditSweepResult(ctx context.Context, r retention.PurgeResult) error {
	d := retentionSweepResultAuditDetail{
		Store: r.Store, PreviousBaseID: r.PreviousBaseID, BaseID: r.BaseID, RowsRemoved: r.RowsRemoved,
		Classes: []retentionSweepResultClass{},
	}
	for class, n := range r.ByClass {
		if n > 0 {
			d.Classes = append(d.Classes, retentionSweepResultClass{Class: class.String(), Removed: n})
		}
	}
	sort.Slice(d.Classes, func(i, j int) bool { return d.Classes[i].Class < d.Classes[j].Class })
	return s.writeAudit(ctx, retentionSweeperActor, retentionSweepResultAction, "retention_sweep", "cluster", d)
}

// SetAuditStore wires the audit store. With none, changes succeed and write
// no entry (no Postgres, REST disabled, or an audit store that failed to
// start), the same as the guardrail baseline switch.
func (s *RetentionServer) SetAuditStore(a auditLogger) {
	if a != nil {
		s.audit = a
		s.wireSweepAudit()
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

func (s *RetentionServer) GetRetentionMode(ctx context.Context, _ *pb.GetRetentionModeRequest) (*pb.GetRetentionModeResponse, error) {
	if _, err := s.requireRetentionAdmin(ctx); err != nil {
		return nil, err
	}
	m, err := s.store.GetMode(ctx)
	if err != nil {
		return nil, retentionStatus("get retention mode", err)
	}
	return &pb.GetRetentionModeResponse{State: m}, nil
}

func (s *RetentionServer) SetRetentionMode(ctx context.Context, req *pb.SetRetentionModeRequest) (*pb.SetRetentionModeResponse, error) {
	subject, err := s.requireRetentionAdmin(ctx)
	if err != nil {
		return nil, err
	}
	// Enforcing deletes data, so it must leave a record: without an audit store
	// (no Postgres, REST disabled, or an audit store that failed to start) it
	// is refused rather than run unaudited.
	if req.GetMode() == pb.RetentionMode_RETENTION_MODE_ENFORCE && s.audit == nil {
		return nil, status.Error(codes.FailedPrecondition, errRetentionEnforceNeedsAudit.Error())
	}
	res, err := s.store.SetMode(ctx, req.GetMode(), subject, func(r *retention.ModeSetResult) error {
		return s.writeAudit(ctx, subject, retentionModeSetAction, "retention_mode", "cluster",
			retentionModeAuditDetail{PreviousMode: r.Previous.GetMode().String(), Mode: r.Current.GetMode().String()})
	})
	if err != nil {
		return nil, retentionStatus("set retention mode", err)
	}
	return &pb.SetRetentionModeResponse{State: res.Current}, nil
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
