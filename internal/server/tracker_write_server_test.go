package server

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/tracker"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// mustTestAuditStore returns a real audit.Store against
// CONTAINARIUM_TEST_DSN, skipping the test if it isn't set — same
// convention as mustTestTrackerStore.
func mustTestAuditStore(t *testing.T) *audit.Store {
	t.Helper()
	dsn := os.Getenv("CONTAINARIUM_TEST_DSN")
	if dsn == "" {
		t.Skip("set CONTAINARIUM_TEST_DSN to run this against Postgres")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect Postgres: %v", err)
	}
	t.Cleanup(pool.Close)
	store, err := audit.NewStore(ctx, pool)
	if err != nil {
		t.Fatalf("audit.NewStore: %v", err)
	}
	return store
}

// fakeWriterProvider extends fakeReaderProvider with the write verbs, for
// testing the tracker write-verb RPCs (CommentOnTrackerIssue here;
// ClaimTrackerIssue and SetTrackerIssueLabels in their own follow-up PRs)
// without a real GitHub/GitLab call — those adapters' own request/response
// shapes are covered by internal/tracker/github and internal/tracker/gitlab.
type fakeWriterProvider struct {
	fakeReaderProvider

	commentBody string
	commentOut  tracker.Comment
	commentErr  error

	assignCalled bool
	assignOut    bool
	assignErr    error

	labelsAdd, labelsRemove []string
	labelsErr               error

	openChangeReq tracker.OpenChangeRequest
	openChangeOut tracker.Change
	openChangeErr error

	defaultBranchOut string
	defaultBranchErr error
}

func (f *fakeWriterProvider) Comment(_ context.Context, _ tracker.Conn, _ int64, body string) (tracker.Comment, error) {
	f.commentBody = body
	if f.commentErr != nil {
		return tracker.Comment{}, f.commentErr
	}
	out := f.commentOut
	out.Body = body
	return out, nil
}

func (f *fakeWriterProvider) AssignIfUnassigned(context.Context, tracker.Conn, int64) (bool, error) {
	f.assignCalled = true
	return f.assignOut, f.assignErr
}

func (f *fakeWriterProvider) SetLabels(_ context.Context, _ tracker.Conn, _ int64, add, remove []string) error {
	f.labelsAdd, f.labelsRemove = add, remove
	return f.labelsErr
}

// WhoAmI returns the zero value, matching this fake's own Comment
// output (commentOut.Author defaults to "") and every fixture comment
// in this file (none set Author) — so ClaimTrackerIssue's marker
// authentication (#1922, caught in review of #1924) treats them all as
// trusted without needing every existing fixture updated.
func (f *fakeWriterProvider) WhoAmI(context.Context, tracker.Conn) (string, error) {
	return "", nil
}

// OpenChange records the request and returns a canned result — added
// (#1923) so this fake satisfies the full tracker.Provider interface,
// which SubmitTrackerChange's connection resolution requires; every
// existing caller that never sets openChangeOut/openChangeErr gets the
// zero Change and no error, same "safe default" shape as the other
// fields here.
func (f *fakeWriterProvider) OpenChange(_ context.Context, _ tracker.Conn, req tracker.OpenChangeRequest) (tracker.Change, error) {
	f.openChangeReq = req
	return f.openChangeOut, f.openChangeErr
}

// DefaultBranch returns a canned value (default "main"), matching this
// fake's own "safe default, override when a test needs to prove
// something about it" convention.
func (f *fakeWriterProvider) DefaultBranch(context.Context, tracker.Conn) (string, error) {
	if f.defaultBranchErr != nil {
		return "", f.defaultBranchErr
	}
	if f.defaultBranchOut == "" {
		return "main", nil
	}
	return f.defaultBranchOut, nil
}

// setUpWriterConnection is setUpBrokerConnection's write-verb
// counterpart: a broker-only secret and a connection referencing it,
// with a wired ClaimLocks and a run-scoped write context ready to use.
func setUpWriterConnection(t *testing.T, user string, provider *fakeWriterProvider) (*ContainerServer, context.Context) {
	t.Helper()
	s := &ContainerServer{
		secretsStore:      mustTestSecretsStore(t),
		trackerStore:      mustTestTrackerStore(t),
		trackerDescribers: fakeDescriberSet(provider),
		claimLocks:        tracker.NewClaimLocks(),
	}
	secretCtx := kmsKeyTestCtx(user, "member", "secrets:write")
	if _, err := s.SetSecret(secretCtx, &pb.SetSecretRequest{
		Username: user, Name: "GH_TOKEN", Value: "ghp_x",
		DeliveryMode: pb.SecretDelivery_SECRET_DELIVERY_BROKER_ONLY,
	}); err != nil {
		t.Fatalf("SetSecret (broker-only): %v", err)
	}
	adminCtx := kmsKeyTestCtx(user, "member", "tracker:admin")
	if _, err := s.SetTrackerConnection(adminCtx, &pb.SetTrackerConnectionRequest{
		Username: user, Name: "default",
		Provider: pb.TrackerProvider_TRACKER_PROVIDER_GITHUB,
		Project:  "acme/widgets", CredentialSecret: "GH_TOKEN",
	}); err != nil {
		t.Fatalf("SetTrackerConnection: %v", err)
	}
	writeCtx := auth.ContextWithTestRunID(kmsKeyTestCtx(user, "member", "tracker:write"), "run-abc123")
	return s, writeCtx
}

// ---- CommentOnTrackerIssue ----------------------------------------------

func TestCommentOnTrackerIssue_NoAuthContext(t *testing.T) {
	s := &ContainerServer{}
	_, err := s.CommentOnTrackerIssue(context.Background(), &pb.CommentOnTrackerIssueRequest{
		Username: "alice", Connection: "default", Number: 1, Body: "hi",
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", status.Code(err))
	}
}

func TestCommentOnTrackerIssue_TrackerReadScopeInsufficient(t *testing.T) {
	s := &ContainerServer{}
	ctx := kmsKeyTestCtx("alice", "member", "tracker:read")
	_, err := s.CommentOnTrackerIssue(ctx, &pb.CommentOnTrackerIssueRequest{
		Username: "alice", Connection: "default", Number: 1, Body: "hi",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied (tracker:read must not grant a write verb)", status.Code(err))
	}
}

func TestCommentOnTrackerIssue_RejectsEmptyBody(t *testing.T) {
	s := &ContainerServer{trackerStore: mustTestTrackerStore(t)}
	ctx := kmsKeyTestCtx("alice", "member", "tracker:write")
	_, err := s.CommentOnTrackerIssue(ctx, &pb.CommentOnTrackerIssueRequest{
		Username: "alice", Connection: "default", Number: 1,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument (empty body)", status.Code(err))
	}
}

// TestCommentOnTrackerIssue_StampsSanitizesAndAudits is the happy path:
// a run-scoped caller's comment reaches the provider sanitized and
// stamped with its run identity, and an audit row is written.
func TestCommentOnTrackerIssue_StampsSanitizesAndAudits(t *testing.T) {
	const user = "tracker-rpc-comment-happy"
	provider := &fakeWriterProvider{}
	s, ctx := setUpWriterConnection(t, user, provider)
	s.auditStore = mustTestAuditStore(t)

	resp, err := s.CommentOnTrackerIssue(ctx, &pb.CommentOnTrackerIssueRequest{
		Username: user, Connection: "default", Number: 7, Body: "/close\nlgtm",
	})
	if err != nil {
		t.Fatalf("CommentOnTrackerIssue: %v", err)
	}
	if resp.Comment == nil {
		t.Fatal("response has no comment")
	}
	if strings.Contains(provider.commentBody, "\n/close") {
		t.Errorf("comment body sent upstream = %q, want the GitLab quick-action line neutralized", provider.commentBody)
	}
	if !strings.Contains(provider.commentBody, "run-abc123") {
		t.Errorf("comment body = %q, want it to carry the run's stamp (run-abc123)", provider.commentBody)
	}

	rows, _, err := s.auditStore.Query(context.Background(), audit.QueryParams{Username: user, Action: "tracker.comment", Limit: 10})
	if err != nil {
		t.Fatalf("audit Query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("audit rows for tracker.comment = %d, want 1", len(rows))
	}
	if !strings.Contains(rows[0].Detail, "run-abc123") {
		t.Errorf("audit detail = %q, want it to carry run_id", rows[0].Detail)
	}
}

// TestCommentOnTrackerIssue_OperatorIdentity_NoRunID pins the fallback
// for a caller with no run_id claim (a human/CI token via the CLI):
// stamped as "operator/<username>", never left blank.
func TestCommentOnTrackerIssue_OperatorIdentity_NoRunID(t *testing.T) {
	const user = "tracker-rpc-comment-operator"
	provider := &fakeWriterProvider{}
	s, _ := setUpWriterConnection(t, user, provider)
	operatorCtx := kmsKeyTestCtx(user, "member", "tracker:write") // no run_id

	if _, err := s.CommentOnTrackerIssue(operatorCtx, &pb.CommentOnTrackerIssueRequest{
		Username: user, Connection: "default", Number: 7, Body: "status update",
	}); err != nil {
		t.Fatalf("CommentOnTrackerIssue: %v", err)
	}
	// The visible signature line truncates the run-id-short segment to
	// 12 chars, so check the hidden marker instead — it always carries
	// the full, untruncated value.
	if !strings.Contains(provider.commentBody, "skill=operator") || !strings.Contains(provider.commentBody, "run="+user) {
		t.Errorf("comment body = %q, want a marker with skill=operator run=%s", provider.commentBody, user)
	}
}

// ---- ClaimTrackerIssue ---------------------------------------------------

func TestClaimTrackerIssue_NoClaimLocksConfigured(t *testing.T) {
	s := &ContainerServer{trackerStore: mustTestTrackerStore(t)}
	ctx := kmsKeyTestCtx("alice", "member", "tracker:write")
	_, err := s.ClaimTrackerIssue(ctx, &pb.ClaimTrackerIssueRequest{
		Username: "alice", Connection: "default", Number: 1,
	})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable (no ClaimLocks configured)", status.Code(err))
	}
}

// TestClaimTrackerIssue_HappyPath exercises the RPC wiring around
// tracker.ClaimTrackerIssue (the algorithm itself is covered exhaustively
// by internal/tracker/claim_test.go): scope/tenant checks, resolving the
// writer connection, acquiring the per-issue lock, and mapping the result
// onto the response and an audit row.
func TestClaimTrackerIssue_HappyPath(t *testing.T) {
	const user = "tracker-rpc-claim-happy"
	provider := &fakeWriterProvider{
		fakeReaderProvider: fakeReaderProvider{
			issue: tracker.Issue{Number: 9, State: pb.TrackerIssueState_TRACKER_ISSUE_STATE_OPEN},
		},
	}
	s, ctx := setUpWriterConnection(t, user, provider)
	s.auditStore = mustTestAuditStore(t)

	resp, err := s.ClaimTrackerIssue(ctx, &pb.ClaimTrackerIssueRequest{
		Username: user, Connection: "default", Number: 9,
	})
	if err != nil {
		t.Fatalf("ClaimTrackerIssue: %v", err)
	}
	if !resp.Claimed {
		t.Errorf("Claimed = false, want true (no existing claim)")
	}
	if !provider.assignCalled {
		t.Error("AssignIfUnassigned was never called")
	}
	if !strings.Contains(provider.commentBody, "run-abc123") {
		t.Errorf("claim comment = %q, want it to carry the run's stamp", provider.commentBody)
	}

	rows, _, err := s.auditStore.Query(context.Background(), audit.QueryParams{Username: user, Action: "tracker.claim", Limit: 10})
	if err != nil {
		t.Fatalf("audit Query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("audit rows for tracker.claim = %d, want 1", len(rows))
	}
	if !strings.Contains(rows[0].Detail, `"claimed":true`) {
		t.Errorf("audit detail = %q, want claimed:true", rows[0].Detail)
	}
}

// TestClaimTrackerIssue_AlreadyClaimedByForeignRun pins that the RPC
// surfaces tracker.ClaimTrackerIssue's refusal outcome faithfully: no
// run registry is wired on this ContainerServer, so runResolver() falls
// back to noRunsLiveResolver — "run-other"'s claim reads as not-live but
// is still fresh (posted "now"), so it's still refused.
func TestClaimTrackerIssue_AlreadyClaimedByForeignRun(t *testing.T) {
	const user = "tracker-rpc-claim-foreign"
	provider := &fakeWriterProvider{
		fakeReaderProvider: fakeReaderProvider{
			issue: tracker.Issue{
				Number: 9,
				Comments: []tracker.Comment{
					{
						CreatedAt: time.Now(),
						Body:      tracker.Stamp(tracker.Identity{RunID: "run-other", SkillID: "s"}, tracker.KindClaim),
					},
				},
			},
		},
	}
	s, ctx := setUpWriterConnection(t, user, provider)

	resp, err := s.ClaimTrackerIssue(ctx, &pb.ClaimTrackerIssueRequest{
		Username: user, Connection: "default", Number: 9,
	})
	if err != nil {
		t.Fatalf("ClaimTrackerIssue: %v", err)
	}
	if resp.Claimed {
		t.Error("Claimed = true, want false (a fresh foreign claim exists)")
	}
	if resp.AlreadyClaimedByRunId != "run-other" {
		t.Errorf("AlreadyClaimedByRunId = %q, want run-other", resp.AlreadyClaimedByRunId)
	}
	if provider.assignCalled {
		t.Error("AssignIfUnassigned must not be called when a foreign claim already holds the issue")
	}
}

// ---- SetTrackerIssueLabels ------------------------------------------------

func TestSetTrackerIssueLabels_RejectsEmptyRequest(t *testing.T) {
	s := &ContainerServer{trackerStore: mustTestTrackerStore(t)}
	ctx := kmsKeyTestCtx("alice", "member", "tracker:write")
	_, err := s.SetTrackerIssueLabels(ctx, &pb.SetTrackerIssueLabelsRequest{
		Username: "alice", Connection: "default", Number: 1,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument (no labels to add or remove)", status.Code(err))
	}
}

func TestSetTrackerIssueLabels_TrackerReadScopeInsufficient(t *testing.T) {
	s := &ContainerServer{}
	ctx := kmsKeyTestCtx("alice", "member", "tracker:read")
	_, err := s.SetTrackerIssueLabels(ctx, &pb.SetTrackerIssueLabelsRequest{
		Username: "alice", Connection: "default", Number: 1, AddLabels: []string{"bug"},
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied (tracker:read must not grant a write verb)", status.Code(err))
	}
}

func TestSetTrackerIssueLabels_HappyPath(t *testing.T) {
	const user = "tracker-rpc-labels-happy"
	provider := &fakeWriterProvider{}
	s, ctx := setUpWriterConnection(t, user, provider)
	s.auditStore = mustTestAuditStore(t)

	if _, err := s.SetTrackerIssueLabels(ctx, &pb.SetTrackerIssueLabelsRequest{
		Username: user, Connection: "default", Number: 3,
		AddLabels: []string{"triaged"}, RemoveLabels: []string{"needs-triage"},
	}); err != nil {
		t.Fatalf("SetTrackerIssueLabels: %v", err)
	}
	if len(provider.labelsAdd) != 1 || provider.labelsAdd[0] != "triaged" {
		t.Errorf("labelsAdd = %v, want [triaged]", provider.labelsAdd)
	}
	if len(provider.labelsRemove) != 1 || provider.labelsRemove[0] != "needs-triage" {
		t.Errorf("labelsRemove = %v, want [needs-triage]", provider.labelsRemove)
	}

	rows, _, err := s.auditStore.Query(context.Background(), audit.QueryParams{Username: user, Action: "tracker.set_labels", Limit: 10})
	if err != nil {
		t.Fatalf("audit Query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("audit rows for tracker.set_labels = %d, want 1", len(rows))
	}
	if !strings.Contains(rows[0].Detail, "triaged") {
		t.Errorf("audit detail = %q, want it to carry the added label", rows[0].Detail)
	}
}
