package server

import (
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/tracker"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ---- enforceConnectionBinding: pure unit coverage, no store needed ----

func TestEnforceConnectionBinding_NoClaim_AllowsAnyConnection(t *testing.T) {
	// An operator/human token (no tracker_conn claim) may name any
	// connection in its tenant — design note decision D3.
	ctx := kmsKeyTestCtx("alice", "member", "tracker:read")
	if err := enforceConnectionBinding(ctx, "whatever"); err != nil {
		t.Errorf("operator token should be able to name any connection: %v", err)
	}
}

func TestEnforceConnectionBinding_MatchingClaim_Allows(t *testing.T) {
	ctx := auth.ContextWithTestTrackerConn(kmsKeyTestCtx("alice", "member", "tracker:read"), "default")
	if err := enforceConnectionBinding(ctx, "default"); err != nil {
		t.Errorf("a run naming the connection it's bound to should be allowed: %v", err)
	}
}

func TestEnforceConnectionBinding_MismatchedClaim_Rejects(t *testing.T) {
	ctx := auth.ContextWithTestTrackerConn(kmsKeyTestCtx("alice", "member", "tracker:read"), "default")
	err := enforceConnectionBinding(ctx, "other")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied (run bound to \"default\", named \"other\")", status.Code(err))
	}
}

// ---- TestResolveConnection_*: the design note's own named tests,
// exercised end to end through a real tracker verb RPC (GetTrackerIssue)
// so the wiring into resolveReaderConn is proven, not just the helper.

func TestResolveConnection_RunTokenUsesClaim_RejectsMismatch(t *testing.T) {
	const user = "tracker-conn-binding-mismatch"
	fake := &fakeReaderProvider{issue: tracker.Issue{Number: 1}}
	s, adminCtx := setUpBrokerConnection(t, user, fake)

	// A second connection for the same tenant, reusing the same broker
	// secret — its own content doesn't matter, only that it EXISTS, so a
	// rejection here can only be explained by the binding check, not a
	// not-found.
	if _, err := s.SetTrackerConnection(adminCtx, &pb.SetTrackerConnectionRequest{
		Username: user, Name: "other",
		Provider: pb.TrackerProvider_TRACKER_PROVIDER_GITHUB,
		Project:  "acme/other", CredentialSecret: "GH_TOKEN",
	}); err != nil {
		t.Fatalf("SetTrackerConnection(other): %v", err)
	}

	// A run token bound to "default" naming "other" instead.
	runCtx := auth.ContextWithTestTrackerConn(
		kmsKeyTestCtx(user, "member", "tracker:read"), "default")

	_, err := s.GetTrackerIssue(runCtx, &pb.GetTrackerIssueRequest{
		Username: user, Connection: "other", Number: 1,
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied (run bound to \"default\", named \"other\")", status.Code(err))
	}

	// The SAME run token naming the connection it IS bound to still works.
	if _, err := s.GetTrackerIssue(runCtx, &pb.GetTrackerIssueRequest{
		Username: user, Connection: "default", Number: 1,
	}); err != nil {
		t.Errorf("GetTrackerIssue(bound connection): %v", err)
	}
}

func TestResolveConnection_OperatorTokenMayName(t *testing.T) {
	const user = "tracker-conn-binding-operator"
	fake := &fakeReaderProvider{issue: tracker.Issue{Number: 1}}
	s, _ := setUpBrokerConnection(t, user, fake)

	// An operator/human token — tracker:read scope, no run binding at
	// all (not even a run_id claim) — may still name the connection
	// directly.
	operatorCtx := kmsKeyTestCtx(user, "member", "tracker:read")
	if _, err := s.GetTrackerIssue(operatorCtx, &pb.GetTrackerIssueRequest{
		Username: user, Connection: "default", Number: 1,
	}); err != nil {
		t.Errorf("operator token should be able to name any connection in its tenant: %v", err)
	}
}
