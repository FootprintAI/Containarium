package server

import (
	"context"
	"errors"
	"log"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/tracker"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Tracker dispatch (#2022): one tick of the dispatcher per
// DispatchTrackerIssues call, plus the dispatch-row listing. Both are
// tracker:admin; dispatch additionally needs agents:run because it
// starts runs on the caller's behalf. See
// docs/architecture/issue-triggered-agents.md.

// SetTrackerRunStarter wires the launcher the dispatcher starts runs
// through — in production, trackerRunStarter over the same
// AgentSkillServer that serves RunAgentSkill. Nil keeps
// DispatchTrackerIssues returning Unavailable.
func (s *ContainerServer) SetTrackerRunStarter(r tracker.RunStarter) {
	s.trackerRunStarter = r
}

// DispatchTrackerIssues runs one dispatcher tick for a connection.
func (s *ContainerServer) DispatchTrackerIssues(ctx context.Context, req *pb.DispatchTrackerIssuesRequest) (*pb.DispatchTrackerIssuesResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeTrackerAdmin); err != nil {
		return nil, err
	}
	// Checked up front: without it every routed issue would become a
	// failed dispatch instead of one clear error.
	if err := auth.RequireScope(ctx, auth.ScopeAgentsRun); err != nil {
		return nil, err
	}
	if err := s.requireTrackerRouteAccess(ctx, req.Username, req.Connection); err != nil {
		return nil, err
	}
	if s.trackerRunStarter == nil {
		return nil, status.Error(codes.Unavailable, "tracker dispatch is not configured on this daemon (no run starter)")
	}
	provider, conn, err := s.resolveWriterConn(ctx, req.Username, req.Connection)
	if err != nil {
		return nil, err
	}

	d := &tracker.Dispatcher{
		Store:    s.trackerStore,
		Provider: provider,
		Conn:     conn,
		Runs:     s.trackerRunStarter,
		Clock:    tracker.SystemClock,
	}
	res, err := d.Tick(ctx, req.Username, req.Connection)
	if err != nil {
		return nil, mapTrackerDispatchError(err)
	}

	out := &pb.DispatchTrackerIssuesResponse{
		SkippedNeedsApproval: int32(res.SkippedNeedsApproval),
		SkippedActive:        int32(res.SkippedActive),
		SkippedUnrouted:      int32(res.SkippedUnrouted),
	}
	for i := range res.Started {
		out.Started = append(out.Started, toProtoTrackerDispatch(&res.Started[i]))
	}
	for i := range res.Failed {
		out.Failed = append(out.Failed, toProtoTrackerDispatch(&res.Failed[i]))
	}
	log.Printf("[tracker] dispatch %s/%s: started=%d failed=%d skipped(approval=%d active=%d unrouted=%d)",
		req.Username, req.Connection, len(res.Started), len(res.Failed),
		res.SkippedNeedsApproval, res.SkippedActive, res.SkippedUnrouted)
	return out, nil
}

// ListTrackerDispatches returns a connection's dispatch rows, newest
// first.
func (s *ContainerServer) ListTrackerDispatches(ctx context.Context, req *pb.ListTrackerDispatchesRequest) (*pb.ListTrackerDispatchesResponse, error) {
	if err := s.requireTrackerRouteAccess(ctx, req.Username, req.Connection); err != nil {
		return nil, err
	}
	rows, err := s.trackerStore.ListDispatches(ctx, req.Username, req.Connection, req.State)
	if err != nil {
		return nil, mapTrackerDispatchError(err)
	}
	out := make([]*pb.TrackerDispatch, 0, len(rows))
	for i := range rows {
		out = append(out, toProtoTrackerDispatch(&rows[i]))
	}
	return &pb.ListTrackerDispatchesResponse{Dispatches: out}, nil
}

func mapTrackerDispatchError(err error) error {
	if errors.Is(err, tracker.ErrNotFound) {
		return status.Error(codes.NotFound, "tracker connection not found")
	}
	if _, ok := status.FromError(err); ok && status.Code(err) != codes.Unknown {
		return err
	}
	return status.Errorf(codes.Internal, "%v", err)
}

func toProtoTrackerDispatch(d *tracker.Dispatch) *pb.TrackerDispatch {
	if d == nil {
		return nil
	}
	out := &pb.TrackerDispatch{
		Id:            d.ID,
		Username:      d.Username,
		Connection:    d.Connection,
		IssueNumber:   d.IssueNumber,
		Scope:         d.Scope,
		SkillId:       d.SkillID,
		RunId:         d.RunID,
		Depth:         d.Depth,
		State:         d.State,
		FailureReason: d.FailureReason,
	}
	if !d.CreatedAt.IsZero() {
		out.CreatedAt = timestamppb.New(d.CreatedAt)
	}
	if !d.StartedAt.IsZero() {
		out.StartedAt = timestamppb.New(d.StartedAt)
	}
	if !d.EndedAt.IsZero() {
		out.EndedAt = timestamppb.New(d.EndedAt)
	}
	return out
}

// trackerRunStarter is the production tracker.RunStarter: it starts a
// dispatched run through beginSkillRun — the same scope check, run id,
// tracker_connection validation, provisioning, run-JWT mint (bound to
// the connection via the tracker_conn claim) and run registration as
// RunAgentSkill. Provisioning is synchronous, so a start failure comes
// back in the same tick and fails the dispatch row there. The in-box
// agent then runs in the background and its lease is ended when it
// returns.
type trackerRunStarter struct {
	agents *AgentSkillServer
}

var _ tracker.RunStarter = trackerRunStarter{}

// NewTrackerRunStarter returns the production RunStarter over agents.
func NewTrackerRunStarter(agents *AgentSkillServer) tracker.RunStarter {
	return trackerRunStarter{agents: agents}
}

// dispatchRunRequest maps a dispatch onto the RunAgentSkill request.
// input_json is exactly the dispatcher's TrackerDispatchInput; no git
// source or credential is invented.
func dispatchRunRequest(req tracker.StartRunRequest) *pb.RunAgentSkillRequest {
	return &pb.RunAgentSkillRequest{
		SkillId:           req.SkillID,
		RunId:             req.RunID,
		InputJson:         req.InputJSON,
		TrackerConnection: req.Connection,
	}
}

func (r trackerRunStarter) StartRun(ctx context.Context, req tracker.StartRunRequest) error {
	// The run JWT and the tracker_connection check are both keyed off
	// the CALLER's tenant; a mismatch would validate (and bind) a
	// same-named connection in the wrong tenant.
	caller, _, ok := auth.SubjectFromGRPCContext(ctx)
	if !ok || caller == "" {
		return status.Error(codes.Unauthenticated, "no authenticated subject")
	}
	if caller != req.Username {
		return status.Errorf(codes.PermissionDenied,
			"dispatch for tenant %q must be run with that tenant's own token (caller is %q)", req.Username, caller)
	}

	run, err := r.agents.beginSkillRun(ctx, dispatchRunRequest(req))
	if err != nil {
		return err
	}
	// The run outlives the tick RPC: detach from its cancellation but
	// keep its auth values (endRunLease detaches the same way).
	bg := context.WithoutCancel(ctx)
	go func() {
		defer r.agents.endRunLease(bg, run.lease, r.agents.boxWiper(), runExitReason)
		// The artifact is consumed by the completion hook (#2023), which
		// moves the dispatch row to done/failed; until then it is dropped.
		_ = r.agents.runInBoxAgent(run.containerName, run.lease.SeedDir)
	}()
	return nil
}
