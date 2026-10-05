package server

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/tracker"
	trackergithub "github.com/footprintai/containarium/internal/tracker/github"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// An ambiguous upstream create (#2045): the forge accepts the POST, then
// answers only after the HTTP client has given up. The issue exists
// upstream but the daemon never learned its number. The RPC must audit
// the attempt as outcome-unknown, return a distinct error that tells the
// agent not to retry blindly, and keep the attempt counted against
// max_children_per_run so a retry cannot file past the cap.

// slowForge is a fake GitHub that records every accepted create and, for
// the first one only, holds the response until the client gives up.
type slowForge struct {
	srv     *httptest.Server
	creates atomic.Int32
}

func newSlowForge(t *testing.T) *slowForge {
	t.Helper()
	f := &slowForge{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/issues") {
			http.NotFound(w, r)
			return
		}
		_, _ = io.Copy(io.Discard, r.Body) // read the whole create...
		n := f.creates.Add(1)              // ...and file it
		if n == 1 {
			select { // ...but answer too late (the body is drained, so
			// the server notices the client hanging up)
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintf(w, `{"number":%d,"title":"t","state":"open"}`, 600+n)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// slowForgeProvider sends CreateIssue through the real GitHub adapter to
// the slow forge, with a short client timeout standing in for the
// production one; every other verb stays on the in-memory fake.
type slowForgeProvider struct {
	*fakeWriterProvider
	gh   *trackergithub.Adapter
	base string
}

func (p *slowForgeProvider) CreateIssue(ctx context.Context, conn tracker.Conn, n tracker.NewIssue) (tracker.Issue, error) {
	conn.BaseURL = p.base
	return p.gh.CreateIssue(ctx, conn, n)
}

func setUpSlowForge(t *testing.T, user string, policy *pb.TrackerPolicy) (*ContainerServer, *slowForge, context.Context, context.Context) {
	t.Helper()
	fake := &fakeWriterProvider{}
	s, runCtx, operatorCtx := setUpCreateConnection(t, user, fake, policy)
	s.auditStore = mustTestAuditStore(t)
	forge := newSlowForge(t)
	s.trackerDescribers = fakeDescriberSet(&slowForgeProvider{
		fakeWriterProvider: fake,
		gh:                 trackergithub.New(&http.Client{Timeout: 200 * time.Millisecond}),
		base:               forge.srv.URL,
	})

	pool, err := pgxpool.New(context.Background(), os.Getenv("CONTAINARIUM_TEST_DSN"))
	if err != nil {
		t.Fatalf("connect Postgres: %v", err)
	}
	defer pool.Close()
	for _, q := range []string{
		"DELETE FROM tracker_lineage_reservations WHERE username = $1",
		"DELETE FROM audit_logs WHERE username = $1",
	} {
		if _, err := pool.Exec(context.Background(), q, user); err != nil {
			t.Fatalf("clean fixture (%s): %v", q, err)
		}
	}
	return s, forge, runCtx, operatorCtx
}

func outcomeUnknownAuditRows(t *testing.T, s *ContainerServer, user string) []audit.AuditEntry {
	t.Helper()
	rows, _, err := s.auditStore.Query(context.Background(), audit.QueryParams{Username: user, Action: auditActionIssueCreateOutcomeUnknown, Limit: 10})
	if err != nil {
		t.Fatalf("audit Query: %v", err)
	}
	return rows
}

func assertOutcomeUnknownError(t *testing.T, err error) {
	t.Helper()
	if status.Code(err) != codes.Unknown {
		t.Fatalf("code = %v (%v), want Unknown (outcome unknown)", status.Code(err), err)
	}
	msg := status.Convert(err).Message()
	for _, want := range []string{ErrorReasonUpstreamCreateOutcomeUnknown, "do not retry"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message = %q, want it to contain %q", msg, want)
		}
	}
}

func TestCreateTrackerIssue_AmbiguousUpstreamCreateIsAuditedAndCapped(t *testing.T) {
	const user = "tracker-rpc-create-outcome-unknown"
	s, forge, runCtx, _ := setUpSlowForge(t, user, &pb.TrackerPolicy{MaxChildrenPerRun: 1})

	_, err := s.CreateTrackerIssue(runCtx, createReq(user, 42, "scope:architecture"))
	assertOutcomeUnknownError(t, err)

	rows := outcomeUnknownAuditRows(t, s, user)
	if len(rows) != 1 {
		t.Fatalf("%s audit rows = %d, want 1", auditActionIssueCreateOutcomeUnknown, len(rows))
	}
	for _, want := range []string{
		`"run_id":"` + createTestRunID + `"`,
		`"parent_number":42`,
		`"depth":1`,
		`"project":"acme/widgets"`,
		`"title":"Design the thing"`,
		`"slot_retained":true`,
	} {
		if !strings.Contains(rows[0].Detail, want) {
			t.Errorf("audit detail = %s, want it to contain %s", rows[0].Detail, want)
		}
	}
	if strings.Contains(rows[0].Detail, "ghp_x") {
		t.Errorf("audit detail = %s, MUST NOT contain the credential value", rows[0].Detail)
	}

	// The blind retry: the forge would answer this one promptly, but the
	// ambiguous attempt still holds the run's only fan-out slot.
	_, err = s.CreateTrackerIssue(runCtx, createReq(user, 42, "scope:architecture"))
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("retry after outcome unknown: code = %v (%v), want ResourceExhausted", status.Code(err), err)
	}
	if n := forge.creates.Load(); n != 1 {
		t.Errorf("issues created on the forge = %d, want 1 (the retry must not reach it)", n)
	}
}

// The operator path has no lineage and no fan-out cap, but the same
// ambiguity applies: audited, and the distinct error.
func TestCreateTrackerIssue_OperatorAmbiguousUpstreamCreateIsAudited(t *testing.T) {
	const user = "tracker-rpc-create-outcome-unknown-op"
	s, _, _, operatorCtx := setUpSlowForge(t, user, nil)

	_, err := s.CreateTrackerIssue(operatorCtx, createReq(user, 0, "scope:architecture"))
	assertOutcomeUnknownError(t, err)
	rows := outcomeUnknownAuditRows(t, s, user)
	if len(rows) != 1 {
		t.Fatalf("%s audit rows = %d, want 1", auditActionIssueCreateOutcomeUnknown, len(rows))
	}
	if !strings.Contains(rows[0].Detail, `"slot_retained":false`) {
		t.Errorf("audit detail = %s, want slot_retained:false for an operator token", rows[0].Detail)
	}
}
