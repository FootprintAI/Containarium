package server

import (
	"context"
	"errors"
	"log"
	"runtime/debug"
	"strings"

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
	// Rejected here, before any store or forge write: a platform admin
	// passes the tenant check, but the run starter mints for the CALLER's
	// tenant and would refuse every issue — turning a wrong username
	// into N failed rows, N agent:failed labels and N public comments on
	// the other tenant's forge.
	if err := requireDispatchCaller(ctx, req.Username); err != nil {
		return nil, err
	}
	if s.trackerRunStarter == nil {
		return nil, status.Error(codes.Unavailable, "tracker dispatch is not configured on this daemon (no run starter)")
	}
	// resolveWriterConn's two halves, split so the connection record
	// also yields the run's repository URL.
	if err := enforceConnectionBinding(ctx, req.Connection); err != nil {
		return nil, err
	}
	record, err := s.trackerStore.Get(ctx, req.Username, req.Connection)
	if err != nil {
		return nil, mapTrackerError(err)
	}
	provider, conn, err := s.writerConnFor(ctx, record)
	if err != nil {
		return nil, err
	}

	d := &tracker.Dispatcher{
		Store:    s.trackerStore,
		Provider: provider,
		Conn:     conn,
		Runs:     s.trackerRunStarter,
		Clock:    tracker.SystemClock,
		// The run's workspace is the connection's own repository, built
		// from the connection record like SubmitTrackerChange's push
		// target — never from the issue or the box (#2023).
		RepoURL: remoteURLFor(record.Provider, record.BaseURL, record.Project),
	}
	res, err := d.Tick(ctx, req.Username, req.Connection)
	if err != nil {
		return nil, mapTrackerDispatchError(err)
	}

	out := &pb.DispatchTrackerIssuesResponse{
		SkippedNeedsApproval: res.SkippedNeedsApproval,
		SkippedActive:        res.SkippedActive,
		SkippedUnrouted:      res.SkippedUnrouted,
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
// input_json is exactly the dispatcher's TrackerDispatchInput. The git
// source is the connection's repository (#2023) so the run can submit a
// doc change; no credential is ever passed — the fetch is anonymous, and
// the push happens daemon-side in SubmitTrackerChange.
func dispatchRunRequest(req tracker.StartRunRequest) *pb.RunAgentSkillRequest {
	return &pb.RunAgentSkillRequest{
		SkillId:           req.SkillID,
		RunId:             req.RunID,
		InputJson:         req.InputJSON,
		TrackerConnection: req.Connection,
		GitSource:         req.RepoURL,
	}
}

// requireDispatchCaller checks that the authenticated subject IS the
// tenant being dispatched for. The run JWT and the tracker_connection
// check are both keyed off the caller's tenant; a mismatch would
// validate (and bind) a same-named connection in the wrong tenant.
// Checked by the RPC before any write and again by the starter, so the
// starter is safe on its own too.
func requireDispatchCaller(ctx context.Context, username string) error {
	caller, _, ok := auth.SubjectFromGRPCContext(ctx)
	if !ok || caller == "" {
		return status.Error(codes.Unauthenticated, "no authenticated subject")
	}
	if caller != username {
		return status.Errorf(codes.PermissionDenied,
			"dispatch for tenant %q must be run with that tenant's own token (caller is %q)", username, caller)
	}
	return nil
}

func (r trackerRunStarter) StartRun(ctx context.Context, req tracker.StartRunRequest) error {
	if err := requireDispatchCaller(ctx, req.Username); err != nil {
		return err
	}
	// Best-effort workspace: an anonymous fetch of a private repository
	// fails, and that run must still read the issue and comment.
	run, err := r.agents.beginSkillRunWith(ctx, dispatchRunRequest(req), provisionOptions{gitSourceBestEffort: true})
	if err != nil {
		return err
	}
	r.agents.launchDispatchedRun(ctx, run, req.Lifecycle, r.agents.runInBoxAgentResult)
	return nil
}

// launchDispatchedRun reports the run's start to the dispatch row
// (QUEUED -> RUNNING, agent:running) and only then launches the in-box
// agent in the background, so the RUNNING projection can never land
// after the terminal one. lc is nil for a run with no dispatch row.
func (s *AgentSkillServer) launchDispatchedRun(ctx context.Context, run *startedSkillRun, lc tracker.RunLifecycle, agent func(containerName, seedDir string) (string, error)) {
	if lc != nil {
		lc.RunStarted(ctx)
	}
	go s.finishDispatchedRun(ctx, run, agent, lc)
}

// finishDispatchedRun is the background half of a dispatched run: run
// the in-box agent, end the lease (revoke the run's JWTs, wipe the
// seed, unregister), then report the outcome to the dispatch row — the
// completion hook (#2023). It is the counterpart of RunAgentSkill's
// `defer endRunLease`, kept out of the RPC because the run outlives the
// tick that started it — so it detaches from the tick's cancellation
// while keeping its auth values, exactly as endRunLease does. The lease
// ends BEFORE the row is marked done, so nothing the run holds can
// still write once the issue says agent:done. agent is a seam for
// tests, which cannot drive a real box; production passes
// runInBoxAgentResult. An agent error or an empty artifact is a failed
// run.
//
// It runs in a bare goroutine, so a panic in it would skip the lease end
// (the run's JWTs stay valid, the run stays registered), never report
// the end, and terminate the daemon (#2050). The lease end and the end
// report therefore run in defers that recover, in the normal order, and
// a run that panicked or was ended by runtime.Goexit is reported failed.
func (s *AgentSkillServer) finishDispatchedRun(ctx context.Context, run *startedSkillRun, agent func(containerName, seedDir string) (string, error), lc tracker.RunLifecycle) {
	bg := context.WithoutCancel(ctx)
	// Not completing is the default: only a normal return from the agent
	// overwrites it. A runtime.Goexit is not a panic (recover returns
	// nil), so without this default it would be reported as success.
	err := errDispatchedRunDidNotComplete
	leaseEnded := false
	// Deferred first so it runs last, after the lease end, and still runs
	// when a Goexit inside the lease end unwinds the goroutine.
	defer func() {
		if lc == nil {
			return
		}
		defer func() { logDispatchedRunPanic(run.runID, "completion report", recover()) }()
		if !leaseEnded {
			// Its credentials may still be live: never report it done.
			err = errDispatchedRunDidNotComplete
		}
		lc.RunEnded(bg, tracker.RunOutcome{Err: err})
	}()
	defer func() {
		if logDispatchedRunPanic(run.runID, "in-box agent", recover()) {
			err = errDispatchedRunDidNotComplete
		}
		defer func() { logDispatchedRunPanic(run.runID, "lease end", recover()) }()
		s.endRunLease(bg, run.lease, s.boxWiper(), runExitReason)
		leaseEnded = true
	}()
	artifact, aerr := agent(run.containerName, run.lease.SeedDir)
	if aerr == nil && strings.TrimSpace(artifact) == "" {
		aerr = errors.New("the agent produced no artifact")
	}
	err = aerr
}

// errDispatchedRunDidNotComplete is the outcome of a dispatched run whose
// background half did not complete (a panic or runtime.Goexit in the
// agent or the lease end). Generic on purpose: a panic value may carry
// anything the run held, so it is neither logged nor stored.
var errDispatchedRunDidNotComplete = errors.New("the dispatched run did not complete")

// logDispatchedRunPanic takes what a deferred function's recover()
// returned and, for a panic in a dispatched run's background half, logs
// the run id, the step and the stack — never the panic value. It reports
// whether there was a panic.
func logDispatchedRunPanic(runID, step string, recovered any) bool {
	if recovered == nil {
		return false
	}
	log.Printf("[agent-skill] run %s: %s panicked (value withheld); recovered\n%s", runID, step, debug.Stack())
	return true
}
