package server

import (
	"context"
	"sync"
	"testing"

	"github.com/footprintai/containarium/internal/runlease"
	"github.com/footprintai/containarium/internal/tracker"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// DispatchTrackerIssues / ListTrackerDispatches (#2022) and the
// production RunStarter over the RunAgentSkill path.

type recordingRunStarter struct {
	mu    sync.Mutex
	calls []tracker.StartRunRequest
	err   error
}

func (r *recordingRunStarter) StartRun(_ context.Context, req tracker.StartRunRequest) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, req)
	return r.err
}

func TestTrackerDispatch_RequiresTrackerAdmin(t *testing.T) {
	s := &ContainerServer{}
	tests := []struct {
		name string
		ctx  context.Context
		want codes.Code
	}{
		{"no auth context", context.Background(), codes.Unauthenticated},
		{"tracker:write is not enough", kmsKeyTestCtx("alice", "member", "tracker:write,agents:run"), codes.PermissionDenied},
		{"tracker:read is not enough", kmsKeyTestCtx("alice", "member", "tracker:read"), codes.PermissionDenied},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := s.DispatchTrackerIssues(tt.ctx, &pb.DispatchTrackerIssuesRequest{Username: "alice", Connection: "default"})
			if status.Code(err) != tt.want {
				t.Errorf("DispatchTrackerIssues code = %v, want %v", status.Code(err), tt.want)
			}
			_, err = s.ListTrackerDispatches(tt.ctx, &pb.ListTrackerDispatchesRequest{Username: "alice", Connection: "default"})
			if status.Code(err) != tt.want {
				t.Errorf("ListTrackerDispatches code = %v, want %v", status.Code(err), tt.want)
			}
		})
	}
}

// Dispatch starts runs, so the operator token must also carry agents:run
// — checked up front, before any issue is touched, rather than turning
// every routed issue into a failed dispatch.
func TestDispatchTrackerIssues_RequiresAgentsRun(t *testing.T) {
	s := &ContainerServer{trackerRunStarter: &recordingRunStarter{}}
	_, err := s.DispatchTrackerIssues(kmsKeyTestCtx("alice", "member", "tracker:admin"),
		&pb.DispatchTrackerIssuesRequest{Username: "alice", Connection: "default"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied (agents:run missing)", status.Code(err))
	}
}

func TestDispatchTrackerIssues_NoRunStarterUnavailable(t *testing.T) {
	s := &ContainerServer{trackerStore: &tracker.Store{}}
	_, err := s.DispatchTrackerIssues(kmsKeyTestCtx("alice", "member", "tracker:admin,agents:run"),
		&pb.DispatchTrackerIssuesRequest{Username: "alice", Connection: "default"})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable (no run starter wired)", status.Code(err))
	}
}

func TestListTrackerDispatches_CrossTenantDenied(t *testing.T) {
	s := &ContainerServer{trackerStore: mustTestTrackerStore(t)}
	_, err := s.ListTrackerDispatches(kmsKeyTestCtx("tracker-dispatch-rpc-alice", "member", "tracker:admin"),
		&pb.ListTrackerDispatchesRequest{Username: "tracker-dispatch-rpc-bob", Connection: "default"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", status.Code(err))
	}
}

// TestDispatchTrackerIssues_TickThroughRPC drives one tick end to end
// through the RPC: real tracker/secrets stores, fake forge, recording
// RunStarter. Then ListTrackerDispatches shows the row.
func TestDispatchTrackerIssues_TickThroughRPC(t *testing.T) {
	const user = "tracker-dispatch-rpc"
	provider := &fakeWriterProvider{fakeReaderProvider: fakeReaderProvider{issues: []tracker.Issue{
		{Number: 42, Title: "idea", Body: "the body", State: pb.TrackerIssueState_TRACKER_ISSUE_STATE_OPEN, Labels: []string{"scope:product"}},
	}}}
	ctx := context.Background()
	// Start from no dispatch rows: they cascade from the connection, which
	// setUpWriterConnection only upserts.
	_ = mustTestTrackerStore(t).Delete(ctx, user, "default")
	s, _ := setUpWriterConnection(t, user, provider)
	if _, err := s.trackerStore.SetRoute(ctx, tracker.Route{Username: user, Connection: "default", Scope: "product", SkillID: "product-define"}); err != nil {
		t.Fatalf("SetRoute: %v", err)
	}
	starter := &recordingRunStarter{}
	s.SetTrackerRunStarter(starter)
	admin := kmsKeyTestCtx(user, "member", "tracker:admin,agents:run")

	resp, err := s.DispatchTrackerIssues(admin, &pb.DispatchTrackerIssuesRequest{Username: user, Connection: "default"})
	if err != nil {
		t.Fatalf("DispatchTrackerIssues: %v", err)
	}
	if len(resp.GetStarted()) != 1 {
		t.Fatalf("started = %+v, want one", resp.GetStarted())
	}
	got := resp.GetStarted()[0]
	if got.GetIssueNumber() != 42 || got.GetScope() != "product" || got.GetSkillId() != "product-define" ||
		got.GetState() != pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_QUEUED || got.GetRunId() == "" || got.GetCreatedAt() == nil {
		t.Errorf("started[0] = %+v", got)
	}
	if len(starter.calls) != 1 || starter.calls[0].RunID != got.GetRunId() || starter.calls[0].Connection != "default" {
		t.Fatalf("StartRun calls = %+v, want one bound to connection default with the row's run id", starter.calls)
	}
	if len(provider.labelsAdd) != 1 || provider.labelsAdd[0] != tracker.LabelAgentQueued {
		t.Errorf("labels added = %v, want [%s]", provider.labelsAdd, tracker.LabelAgentQueued)
	}

	// Second tick: the forge fake still shows the issue unlabeled, but
	// the active row holds — exactly once.
	resp, err = s.DispatchTrackerIssues(admin, &pb.DispatchTrackerIssuesRequest{Username: user, Connection: "default"})
	if err != nil {
		t.Fatalf("DispatchTrackerIssues (2): %v", err)
	}
	if len(resp.GetStarted()) != 0 || resp.GetSkippedActive() != 1 || len(starter.calls) != 1 {
		t.Fatalf("tick 2 = %+v, calls = %d, want nothing new", resp, len(starter.calls))
	}

	list, err := s.ListTrackerDispatches(admin, &pb.ListTrackerDispatchesRequest{
		Username: user, Connection: "default", State: pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_QUEUED,
	})
	if err != nil {
		t.Fatalf("ListTrackerDispatches: %v", err)
	}
	if len(list.GetDispatches()) != 1 || list.GetDispatches()[0].GetId() != got.GetId() {
		t.Fatalf("dispatches = %+v, want the one queued row", list.GetDispatches())
	}
}

func TestDispatchTrackerIssues_UnknownConnectionNotFound(t *testing.T) {
	store := mustTestTrackerStore(t)
	s := &ContainerServer{trackerStore: store, trackerRunStarter: &recordingRunStarter{}}
	_, err := s.DispatchTrackerIssues(kmsKeyTestCtx("tracker-dispatch-rpc-noconn", "member", "tracker:admin,agents:run"),
		&pb.DispatchTrackerIssuesRequest{Username: "tracker-dispatch-rpc-noconn", Connection: "nope"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("code = %v, want NotFound", status.Code(err))
	}
}

// ---- production RunStarter ---------------------------------------------

func TestDispatchRunRequest_BindsConnectionAndInput(t *testing.T) {
	req := dispatchRunRequest(tracker.StartRunRequest{
		Username: "alice", Connection: "default", SkillID: "product-define", RunID: "run-1",
		InputJSON: `{"connection":"default","issueNumber":"42"}`,
	})
	if req.GetSkillId() != "product-define" || req.GetRunId() != "run-1" || req.GetTrackerConnection() != "default" ||
		req.GetInputJson() != `{"connection":"default","issueNumber":"42"}` {
		t.Fatalf("RunAgentSkillRequest = %+v, want skill/run id/tracker_connection/input carried through", req)
	}
	if req.GetGitSource() != "" || req.GetGitCredential() != "" {
		t.Errorf("dispatch must not invent a git source or credential: %+v", req)
	}
}

// The dispatched run is minted for the CALLER's tenant; a caller naming
// another tenant's connection could otherwise bind the run to a
// same-named connection in its own tenant.
func TestTrackerRunStarter_TenantMismatchRejected(t *testing.T) {
	s := &AgentSkillServer{trackerConnections: &fakeTrackerConnectionChecker{conn: &tracker.Connection{}}}
	err := trackerRunStarter{s}.StartRun(ctxAs("alice", true), tracker.StartRunRequest{
		Username: "bob", Connection: "default", SkillID: "hello-agent", RunID: "run-x",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", status.Code(err))
	}
}

func TestTrackerRunStarter_BadConnectionRejectedSynchronously(t *testing.T) {
	s, skill := newSkillBoxHarness(t, newFakeRevocationStore())
	s.trackerConnections = &fakeTrackerConnectionChecker{err: tracker.ErrNotFound}
	err := trackerRunStarter{s}.StartRun(ctxAs("alice", true), tracker.StartRunRequest{
		Username: "alice", Connection: "default", SkillID: skill.Id, RunID: "run-bad-conn",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
	}
}

// A provisioning failure (the harness's seed exec always fails) comes
// back from StartRun synchronously — the dispatcher fails the row in the
// same tick — and the run is never registered as live.
func TestTrackerRunStarter_ProvisionFailureIsSynchronous(t *testing.T) {
	s, skill := newSkillBoxHarness(t, newFakeRevocationStore())
	checker := &fakeTrackerConnectionChecker{conn: &tracker.Connection{Username: "alice", Name: "default"}}
	s.trackerConnections = checker
	reg := runlease.NewRegistry()
	s.SetRunRegistry(reg)

	err := trackerRunStarter{s}.StartRun(ctxAs("alice", true), tracker.StartRunRequest{
		Username: "alice", Connection: "default", SkillID: skill.Id, RunID: "run-prov-fail",
	})
	if err == nil {
		t.Fatal("StartRun = nil, want the provisioning error returned synchronously")
	}
	if checker.gotName != "default" || checker.gotUsername != "alice" {
		t.Errorf("connection validated as %s/%s, want alice/default (run bound to the dispatch connection)", checker.gotUsername, checker.gotName)
	}
	if reg.Live("run-prov-fail") {
		t.Error("run registered as live despite failing to provision")
	}
}

func TestTrackerRunStarter_UnknownSkillFails(t *testing.T) {
	s, _ := newSkillBoxHarness(t, newFakeRevocationStore())
	s.trackerConnections = &fakeTrackerConnectionChecker{conn: &tracker.Connection{}}
	err := trackerRunStarter{s}.StartRun(ctxAs("alice", true), tracker.StartRunRequest{
		Username: "alice", Connection: "default", SkillID: "no-such-skill", RunID: "run-noskill",
	})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("code = %v, want NotFound", status.Code(err))
	}
}
