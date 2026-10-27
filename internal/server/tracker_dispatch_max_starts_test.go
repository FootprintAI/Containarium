package server

import (
	"context"
	"testing"

	"github.com/footprintai/containarium/internal/tracker"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// max_starts (#2270) through the RPC: the request bounds the tick, the
// response reports how many eligible issues were left for a later tick.

func TestDispatchTrackerIssues_MaxStartsThroughRPC(t *testing.T) {
	const user = "tracker-dispatch-rpc-max-starts"
	var issues []tracker.Issue
	for n := int64(1); n <= 3; n++ {
		issues = append(issues, tracker.Issue{Number: n, State: pb.TrackerIssueState_TRACKER_ISSUE_STATE_OPEN, Labels: []string{"scope:product"}})
	}
	// issues[0] is also what the post-insert re-read sees: open, routed.
	provider := &fakeWriterProvider{fakeReaderProvider: fakeReaderProvider{issues: issues, issue: issues[0]}}
	ctx := context.Background()
	_ = mustTestTrackerStore(t).Delete(ctx, user, "default")
	s, _ := setUpWriterConnection(t, user, provider)
	if _, err := s.trackerStore.SetRoute(ctx, tracker.Route{Username: user, Connection: "default", Scope: "product", SkillID: "product-define"}); err != nil {
		t.Fatalf("SetRoute: %v", err)
	}
	starter := &recordingRunStarter{}
	s.SetTrackerRunStarter(starter)
	admin := kmsKeyTestCtx(user, "member", "tracker:admin,agents:run")

	resp, err := s.DispatchTrackerIssues(admin, &pb.DispatchTrackerIssuesRequest{Username: user, Connection: "default", MaxStarts: 1})
	if err != nil {
		t.Fatalf("DispatchTrackerIssues: %v", err)
	}
	if len(resp.GetStarted()) != 1 || len(starter.calls) != 1 || resp.GetLeftUndispatched() != 2 {
		t.Fatalf("started = %d, calls = %d, left = %d; want 1 started and 2 left undispatched",
			len(resp.GetStarted()), len(starter.calls), resp.GetLeftUndispatched())
	}
	rows, err := s.trackerStore.ListDispatches(ctx, user, "default", pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_UNSPECIFIED)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows = %+v (err %v), want exactly the one started", rows, err)
	}
}

func TestDispatchTrackerIssues_NegativeMaxStartsInvalid(t *testing.T) {
	s := &ContainerServer{trackerStore: &tracker.Store{}, trackerRunStarter: &recordingRunStarter{}}
	_, err := s.DispatchTrackerIssues(kmsKeyTestCtx("alice", "member", "tracker:admin,agents:run"),
		&pb.DispatchTrackerIssuesRequest{Username: "alice", Connection: "default", MaxStarts: -1})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v (%v), want InvalidArgument", status.Code(err), err)
	}
}
