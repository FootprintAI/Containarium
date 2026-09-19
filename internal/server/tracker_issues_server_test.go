package server

import (
	"context"
	"testing"

	"github.com/footprintai/containarium/internal/tracker"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestGetTrackerIssue_NoAuthContext(t *testing.T) {
	s := &ContainerServer{}
	_, err := s.GetTrackerIssue(context.Background(), &pb.GetTrackerIssueRequest{Username: "alice", Connection: "default", Number: 1})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", status.Code(err))
	}
}

// TestGetTrackerIssue_TrackerAdminScopeInsufficient pins the inverse
// separation from TestSetTrackerConnection_TrackerWriteScopeInsufficient:
// tracker:admin (connection CRUD) does not imply tracker:read (the
// verbs). An operator token scoped only for managing connections cannot
// also read issues through it.
func TestGetTrackerIssue_TrackerAdminScopeInsufficient(t *testing.T) {
	s := &ContainerServer{}
	ctx := kmsKeyTestCtx("alice", "member", "tracker:admin")
	_, err := s.GetTrackerIssue(ctx, &pb.GetTrackerIssueRequest{Username: "alice", Connection: "default", Number: 1})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", status.Code(err))
	}
}

func TestListTrackerIssues_NoAuthContext(t *testing.T) {
	s := &ContainerServer{}
	_, err := s.ListTrackerIssues(context.Background(), &pb.ListTrackerIssuesRequest{Username: "alice", Connection: "default"})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", status.Code(err))
	}
}

func TestGetTrackerChange_NoAuthContext(t *testing.T) {
	s := &ContainerServer{}
	_, err := s.GetTrackerChange(context.Background(), &pb.GetTrackerChangeRequest{Username: "alice", Connection: "default", Number: 1})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", status.Code(err))
	}
}

// TestGetTrackerIssue_NoSuchConnection needs a configured store — with
// a nil store, the handler's nil-store check runs before the
// connection lookup and would test the wrong thing.
func TestGetTrackerIssue_NoSuchConnection(t *testing.T) {
	s := &ContainerServer{trackerStore: mustTestTrackerStore(t)}
	const user = "tracker-issues-rpc-no-conn"
	ctx := kmsKeyTestCtx(user, "member", "tracker:read")
	_, err := s.GetTrackerIssue(ctx, &pb.GetTrackerIssueRequest{Username: user, Connection: "does-not-exist", Number: 1})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("code = %v, want NotFound", status.Code(err))
	}
}

func TestGetTrackerIssue_Success(t *testing.T) {
	fake := &fakeReaderProvider{issue: tracker.Issue{
		Number: 7, Title: "bug", Body: "it broke",
		State:  pb.TrackerIssueState_TRACKER_ISSUE_STATE_OPEN,
		Labels: []string{"bug"}, Assignee: "agent",
		Comments: []tracker.Comment{{Author: "reviewer", Body: "looking"}},
	}}
	s, _ := setUpBrokerConnection(t, "tracker-issues-rpc-get-success", fake)
	// setUpBrokerConnection mints an admin (tracker:admin) context for
	// connection setup; the issue verb itself needs tracker:read.
	readCtx := kmsKeyTestCtx("tracker-issues-rpc-get-success", "member", "tracker:read")

	resp, err := s.GetTrackerIssue(readCtx, &pb.GetTrackerIssueRequest{
		Username: "tracker-issues-rpc-get-success", Connection: "default", Number: 7,
	})
	if err != nil {
		t.Fatalf("GetTrackerIssue: %v", err)
	}
	if resp.Issue.Number != 7 || resp.Issue.Title != "bug" || resp.Issue.Assignee != "agent" {
		t.Errorf("Issue = %+v, want number=7 title=bug assignee=agent", resp.Issue)
	}
	if len(resp.Issue.Comments) != 1 || resp.Issue.Comments[0].Author != "reviewer" {
		t.Errorf("Comments = %+v, want one comment from reviewer", resp.Issue.Comments)
	}
}

func TestGetTrackerIssue_NotFoundOnTracker(t *testing.T) {
	fake := &fakeReaderProvider{issueErr: tracker.ErrNotFound}
	s, _ := setUpBrokerConnection(t, "tracker-issues-rpc-not-found", fake)
	readCtx := kmsKeyTestCtx("tracker-issues-rpc-not-found", "member", "tracker:read")

	_, err := s.GetTrackerIssue(readCtx, &pb.GetTrackerIssueRequest{
		Username: "tracker-issues-rpc-not-found", Connection: "default", Number: 999,
	})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("code = %v, want NotFound", status.Code(err))
	}
}

func TestListTrackerIssues_PassesFilterThrough(t *testing.T) {
	fake := &fakeReaderProvider{issues: []tracker.Issue{
		{Number: 1, Title: "a"},
		{Number: 2, Title: "b"},
	}}
	s, _ := setUpBrokerConnection(t, "tracker-issues-rpc-list", fake)
	readCtx := kmsKeyTestCtx("tracker-issues-rpc-list", "member", "tracker:read")

	resp, err := s.ListTrackerIssues(readCtx, &pb.ListTrackerIssuesRequest{
		Username: "tracker-issues-rpc-list", Connection: "default",
		State: pb.TrackerIssueState_TRACKER_ISSUE_STATE_OPEN, Labels: []string{"bug"},
	})
	if err != nil {
		t.Fatalf("ListTrackerIssues: %v", err)
	}
	if len(resp.Issues) != 2 {
		t.Fatalf("Issues = %+v, want 2", resp.Issues)
	}
}

func TestGetTrackerChange_Success(t *testing.T) {
	fake := &fakeReaderProvider{change: tracker.Change{
		Number: 3, State: pb.TrackerIssueState_TRACKER_ISSUE_STATE_MERGED,
		CIVerdict: pb.TrackerCiVerdict_TRACKER_CI_VERDICT_SUCCESS, URL: "https://example.com/3",
	}}
	s, _ := setUpBrokerConnection(t, "tracker-issues-rpc-change", fake)
	readCtx := kmsKeyTestCtx("tracker-issues-rpc-change", "member", "tracker:read")

	resp, err := s.GetTrackerChange(readCtx, &pb.GetTrackerChangeRequest{
		Username: "tracker-issues-rpc-change", Connection: "default", Number: 3,
	})
	if err != nil {
		t.Fatalf("GetTrackerChange: %v", err)
	}
	if resp.Change.Number != 3 || resp.Change.State != pb.TrackerIssueState_TRACKER_ISSUE_STATE_MERGED || resp.Change.CiVerdict != pb.TrackerCiVerdict_TRACKER_CI_VERDICT_SUCCESS {
		t.Errorf("Change = %+v, want number=3 state=MERGED ci_verdict=SUCCESS", resp.Change)
	}
}

// TestGetTrackerIssue_UpstreamUnreachable pins the mapProviderError ->
// Unavailable mapping distinct from a rejected credential.
func TestGetTrackerIssue_UpstreamUnreachable(t *testing.T) {
	fake := &fakeReaderProvider{issueErr: tracker.ErrUnreachable}
	s, _ := setUpBrokerConnection(t, "tracker-issues-rpc-unreachable", fake)
	readCtx := kmsKeyTestCtx("tracker-issues-rpc-unreachable", "member", "tracker:read")

	_, err := s.GetTrackerIssue(readCtx, &pb.GetTrackerIssueRequest{
		Username: "tracker-issues-rpc-unreachable", Connection: "default", Number: 1,
	})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", status.Code(err))
	}
}
