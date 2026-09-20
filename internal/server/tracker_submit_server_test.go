package server

import (
	"context"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestSubmitTrackerChange_NoAuthContext(t *testing.T) {
	s := &ContainerServer{}
	_, err := s.SubmitTrackerChange(context.Background(), &pb.SubmitTrackerChangeRequest{
		Username: "alice", Connection: "default", Issue: 1, Title: "t",
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", status.Code(err))
	}
}

func TestSubmitTrackerChange_TrackerReadScopeInsufficient(t *testing.T) {
	s := &ContainerServer{}
	ctx := kmsKeyTestCtx("alice", "member", "tracker:read")
	_, err := s.SubmitTrackerChange(ctx, &pb.SubmitTrackerChangeRequest{
		Username: "alice", Connection: "default", Issue: 1, Title: "t",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied (tracker:read must not grant a write verb)", status.Code(err))
	}
}

func TestSubmitTrackerChange_NoTrackerStoreConfigured(t *testing.T) {
	s := &ContainerServer{}
	ctx := kmsKeyTestCtx("alice", "member", "tracker:write")
	_, err := s.SubmitTrackerChange(ctx, &pb.SubmitTrackerChangeRequest{
		Username: "alice", Connection: "default", Issue: 1, Title: "t",
	})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", status.Code(err))
	}
}

func TestSubmitTrackerChange_RejectsMissingIssue(t *testing.T) {
	s := &ContainerServer{trackerStore: mustTestTrackerStore(t)}
	ctx := kmsKeyTestCtx("alice", "member", "tracker:write")
	_, err := s.SubmitTrackerChange(ctx, &pb.SubmitTrackerChangeRequest{
		Username: "alice", Connection: "default", Title: "t",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument (missing issue)", status.Code(err))
	}
}

func TestSubmitTrackerChange_RejectsMissingTitle(t *testing.T) {
	s := &ContainerServer{trackerStore: mustTestTrackerStore(t)}
	ctx := kmsKeyTestCtx("alice", "member", "tracker:write")
	_, err := s.SubmitTrackerChange(ctx, &pb.SubmitTrackerChangeRequest{
		Username: "alice", Connection: "default", Issue: 1,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument (missing title)", status.Code(err))
	}
}

func TestSubmitTrackerChange_CrossTenantDenied(t *testing.T) {
	s := &ContainerServer{trackerStore: mustTestTrackerStore(t)}
	ctx := kmsKeyTestCtx("mallory", "member", "tracker:write")
	_, err := s.SubmitTrackerChange(ctx, &pb.SubmitTrackerChangeRequest{
		Username: "alice", Connection: "default", Issue: 1, Title: "t",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied (cross-tenant)", status.Code(err))
	}
}

// TestSubmitTrackerChange_UnimplementedOnceEveryCheckPasses proves the
// stub fails CLOSED, not open: every authn/authz/connection-resolution
// check that will gate the real orchestration (#1923 follow-up PR) is
// exercised here and must pass before Unimplemented is even reached —
// a request that fails any earlier check must never reach this far.
func TestSubmitTrackerChange_UnimplementedOnceEveryCheckPasses(t *testing.T) {
	const user = "tracker-rpc-submit-unimplemented"
	provider := &fakeWriterProvider{}
	s, ctx := setUpWriterConnection(t, user, provider)

	_, err := s.SubmitTrackerChange(ctx, &pb.SubmitTrackerChangeRequest{
		Username: user, Connection: "default", Issue: 1, Title: "t",
	})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("code = %v, want Unimplemented (orchestration lands in a follow-up PR)", status.Code(err))
	}
}
