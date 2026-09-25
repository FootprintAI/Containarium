package tracker

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
)

// Integration-style tests against a real Postgres, same convention as
// internal/secrets' store tests: t.Skip in CI-without-DSN, runnable
// locally with CONTAINARIUM_TEST_DSN set (see internal/secrets/store_test.go
// for the docker run command), and executed for real by the
// store-integration CI lane.

func newTrackerTestStore(t *testing.T) (*Store, context.Context) {
	t.Helper()
	dsn := os.Getenv("CONTAINARIUM_TEST_DSN")
	if dsn == "" {
		t.Skip("set CONTAINARIUM_TEST_DSN to run this against Postgres (the store-integration lane does)")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect Postgres: %v", err)
	}
	t.Cleanup(pool.Close)
	store, err := NewStore(ctx, pool)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return store, ctx
}

func TestTrackerStore_CRUDRoundTrip(t *testing.T) {
	store, ctx := newTrackerTestStore(t)
	const user = "tracker-store-crud"
	_, _ = store.pool.Exec(ctx, "DELETE FROM tracker_connections WHERE username = $1", user)

	created, err := store.Set(ctx, Connection{
		Username:         user,
		Name:             "default",
		Provider:         pb.TrackerProvider_TRACKER_PROVIDER_GITHUB,
		Project:          "acme/widgets",
		CredentialSecret: "GH_TOKEN",
	})
	if err != nil {
		t.Fatalf("Set (create): %v", err)
	}
	if created.CreatedAt.IsZero() || created.UpdatedAt.IsZero() {
		t.Errorf("Set (create) left timestamps zero: %+v", created)
	}

	got, err := store.Get(ctx, user, "default")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Provider != pb.TrackerProvider_TRACKER_PROVIDER_GITHUB || got.Project != "acme/widgets" || got.CredentialSecret != "GH_TOKEN" {
		t.Errorf("Get = %+v, want provider=GITHUB project=acme/widgets credential_secret=GH_TOKEN", got)
	}

	// Update (same username+name, different fields) — Set is an upsert.
	updated, err := store.Set(ctx, Connection{
		Username:         user,
		Name:             "default",
		Provider:         pb.TrackerProvider_TRACKER_PROVIDER_GITLAB,
		BaseURL:          "https://gitlab.example.com",
		Project:          "acme/widgets-v2",
		CredentialSecret: "GL_TOKEN",
	})
	if err != nil {
		t.Fatalf("Set (update): %v", err)
	}
	if updated.Provider != pb.TrackerProvider_TRACKER_PROVIDER_GITLAB || updated.Project != "acme/widgets-v2" {
		t.Errorf("Set (update) = %+v, want provider=GITLAB project=acme/widgets-v2", updated)
	}
	if !updated.CreatedAt.Equal(created.CreatedAt) {
		t.Errorf("Set (update) CreatedAt = %v, want unchanged %v", updated.CreatedAt, created.CreatedAt)
	}

	list, err := store.List(ctx, user)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || list[0].Name != "default" {
		t.Errorf("List = %+v, want exactly one connection named default", list)
	}

	if err := store.Delete(ctx, user, "default"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Get(ctx, user, "default"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Delete err = %v, want ErrNotFound", err)
	}
	if err := store.Delete(ctx, user, "default"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete (already gone) err = %v, want ErrNotFound", err)
	}
}

func TestGet_OtherTenantsConnection_NotFound(t *testing.T) {
	store, ctx := newTrackerTestStore(t)
	const owner = "tracker-store-tenant-owner"
	const other = "tracker-store-tenant-other"
	_, _ = store.pool.Exec(ctx, "DELETE FROM tracker_connections WHERE username IN ($1, $2)", owner, other)

	if _, err := store.Set(ctx, Connection{
		Username: owner, Name: "default",
		Provider: pb.TrackerProvider_TRACKER_PROVIDER_GITHUB,
		Project:  "acme/widgets", CredentialSecret: "GH_TOKEN",
	}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	if _, err := store.Get(ctx, other, "default"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get by a different tenant err = %v, want ErrNotFound", err)
	}
	otherList, err := store.List(ctx, other)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(otherList) != 0 {
		t.Errorf("List(%q) = %+v, want empty (owned by %q)", other, otherList, owner)
	}
}

func TestTrackerStore_UnknownProviderString_RejectedByCheckConstraint(t *testing.T) {
	store, ctx := newTrackerTestStore(t)
	const user = "tracker-store-bad-provider"
	_, _ = store.pool.Exec(ctx, "DELETE FROM tracker_connections WHERE username = $1", user)

	// providerToString already refuses to send anything but "github" /
	// "gitlab" through Set — this test proves the CHECK constraint itself
	// is a real backstop, by inserting a bogus value directly.
	_, err := store.pool.Exec(ctx,
		`INSERT INTO tracker_connections (username, name, provider, project, credential_secret) VALUES ($1, $2, $3, $4, $5)`,
		user, "default", "bitbucket", "acme/widgets", "BB_TOKEN")
	if err == nil {
		t.Fatal("insert with provider='bitbucket' succeeded, want a CHECK constraint violation")
	}
}

func TestSet_UnspecifiedProvider_Rejected(t *testing.T) {
	store, ctx := newTrackerTestStore(t)
	const user = "tracker-store-unspecified-provider"
	_, _ = store.pool.Exec(ctx, "DELETE FROM tracker_connections WHERE username = $1", user)

	_, err := store.Set(ctx, Connection{
		Username: user, Name: "default",
		Project: "acme/widgets", CredentialSecret: "GH_TOKEN",
		// Provider left at its zero value (UNSPECIFIED).
	})
	if err == nil {
		t.Fatal("Set with UNSPECIFIED provider succeeded, want an error")
	}
}

func TestSetCredentialExpiry(t *testing.T) {
	store, ctx := newTrackerTestStore(t)
	const user = "tracker-store-cred-expiry"
	_, _ = store.pool.Exec(ctx, "DELETE FROM tracker_connections WHERE username = $1", user)

	created, err := store.Set(ctx, Connection{
		Username: user, Name: "default",
		Provider: pb.TrackerProvider_TRACKER_PROVIDER_GITHUB,
		Project:  "acme/widgets", CredentialSecret: "GH_TOKEN",
	})
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if !created.CredentialExpiresAt.IsZero() {
		t.Errorf("CredentialExpiresAt on create = %v, want zero (unknown until described)", created.CredentialExpiresAt)
	}

	expiry := time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC)
	if err := store.SetCredentialExpiry(ctx, user, "default", expiry); err != nil {
		t.Fatalf("SetCredentialExpiry: %v", err)
	}
	got, err := store.Get(ctx, user, "default")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.CredentialExpiresAt.Equal(expiry) {
		t.Errorf("CredentialExpiresAt = %v, want %v", got.CredentialExpiresAt, expiry)
	}

	// A subsequent Set (e.g. rotating the project) must not clobber the
	// expiry SetCredentialExpiry just wrote — it isn't a client-supplied
	// field.
	if _, err := store.Set(ctx, Connection{
		Username: user, Name: "default",
		Provider: pb.TrackerProvider_TRACKER_PROVIDER_GITHUB,
		Project:  "acme/widgets-v2", CredentialSecret: "GH_TOKEN",
	}); err != nil {
		t.Fatalf("Set (update): %v", err)
	}
	afterUpdate, err := store.Get(ctx, user, "default")
	if err != nil {
		t.Fatalf("Get after update: %v", err)
	}
	if !afterUpdate.CredentialExpiresAt.Equal(expiry) {
		t.Errorf("CredentialExpiresAt after unrelated Set = %v, want unchanged %v", afterUpdate.CredentialExpiresAt, expiry)
	}

	// Clearing back to zero (unknown) stores NULL, not the zero time.
	if err := store.SetCredentialExpiry(ctx, user, "default", time.Time{}); err != nil {
		t.Fatalf("SetCredentialExpiry (clear): %v", err)
	}
	cleared, err := store.Get(ctx, user, "default")
	if err != nil {
		t.Fatalf("Get after clear: %v", err)
	}
	if !cleared.CredentialExpiresAt.IsZero() {
		t.Errorf("CredentialExpiresAt after clear = %v, want zero", cleared.CredentialExpiresAt)
	}

	if err := store.SetCredentialExpiry(ctx, user, "does-not-exist", expiry); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SetCredentialExpiry on missing connection err = %v, want ErrNotFound", err)
	}
}

// TestTrackerStore_PolicyRoundTrip (#2024): TrackerPolicy is stored as
// protojson in a JSONB column and read back through the generated
// decoder — a Set with a policy round-trips it field for field, a Set
// without one stores NULL and reads back nil (the server applies the
// documented defaults to nil).
func TestTrackerStore_PolicyRoundTrip(t *testing.T) {
	store, ctx := newTrackerTestStore(t)
	const user = "tracker-store-policy"
	_, _ = store.pool.Exec(ctx, "DELETE FROM tracker_connections WHERE username = $1", user)

	pol := &pb.TrackerPolicy{
		LabelAllowList: []string{"scope:*", "triaged"}, AutoChain: true,
		MaxDepth: 2, MaxChildrenPerRun: 4, RunTimeoutSeconds: 120,
	}
	if _, err := store.Set(ctx, Connection{
		Username: user, Name: "default",
		Provider: pb.TrackerProvider_TRACKER_PROVIDER_GITHUB,
		Project:  "acme/widgets", CredentialSecret: "GH_TOKEN",
		Policy: pol,
	}); err != nil {
		t.Fatalf("Set (with policy): %v", err)
	}
	got, err := store.Get(ctx, user, "default")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !proto.Equal(got.Policy, pol) {
		t.Errorf("Get policy = %v, want %v", got.Policy, pol)
	}
	list, err := store.List(ctx, user)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || !proto.Equal(list[0].Policy, pol) {
		t.Errorf("List = %+v, want one connection carrying the policy", list)
	}

	// Set without a policy clears it (Set replaces every field).
	if _, err := store.Set(ctx, Connection{
		Username: user, Name: "default",
		Provider: pb.TrackerProvider_TRACKER_PROVIDER_GITHUB,
		Project:  "acme/widgets", CredentialSecret: "GH_TOKEN",
	}); err != nil {
		t.Fatalf("Set (no policy): %v", err)
	}
	cleared, err := store.Get(ctx, user, "default")
	if err != nil {
		t.Fatalf("Get after clear: %v", err)
	}
	if cleared.Policy != nil {
		t.Errorf("policy after Set without one = %v, want nil", cleared.Policy)
	}
}

// TestLineage_DepthAndChildrenCount (#2024): depth derives from the
// parent's own lineage row (a human-created issue has no row → depth 0),
// per-run child counting, and RecordChild's guards — both checked
// inside the same transaction as the insert and BEFORE the create
// callback (the upstream call) runs.
func TestLineage_DepthAndChildrenCount(t *testing.T) {
	store, ctx := newTrackerTestStore(t)
	const user = "tracker-store-lineage"
	_, _ = store.pool.Exec(ctx, "DELETE FROM tracker_issue_lineage WHERE username = $1", user)

	if d, err := store.IssueDepth(ctx, user, "default", 100); err != nil || d != 0 {
		t.Fatalf("IssueDepth(human-created #100) = %d, %v; want 0, nil", d, err)
	}

	child, err := store.RecordChild(ctx, Lineage{Username: user, Connection: "default", ParentNumber: 100, CreatedByRun: "run-1"}, 3, 5,
		func(context.Context) (int64, error) { return 101, nil })
	if err != nil {
		t.Fatalf("RecordChild(#101 under #100): %v", err)
	}
	if child.ChildNumber != 101 || child.Depth != 1 {
		t.Errorf("recorded = %+v, want child=101 depth=1", child)
	}
	grandchild, err := store.RecordChild(ctx, Lineage{Username: user, Connection: "default", ParentNumber: 101, CreatedByRun: "run-2"}, 3, 5,
		func(context.Context) (int64, error) { return 102, nil })
	if err != nil {
		t.Fatalf("RecordChild(#102 under #101): %v", err)
	}
	if grandchild.Depth != 2 {
		t.Errorf("grandchild depth = %d, want 2", grandchild.Depth)
	}
	if d, _ := store.IssueDepth(ctx, user, "default", 101); d != 1 {
		t.Errorf("IssueDepth(#101) = %d, want 1", d)
	}
	if d, _ := store.IssueDepth(ctx, user, "default", 102); d != 2 {
		t.Errorf("IssueDepth(#102) = %d, want 2", d)
	}
	if n, err := store.ChildrenCount(ctx, user, "default", "run-1"); err != nil || n != 1 {
		t.Errorf("ChildrenCount(run-1) = %d, %v; want 1", n, err)
	}

	// Fan-out: run-1 already has 1 child; max 1 → rejected before the
	// callback (which would be the upstream call) is ever invoked.
	called := false
	_, err = store.RecordChild(ctx, Lineage{Username: user, Connection: "default", ParentNumber: 100, CreatedByRun: "run-1"}, 3, 1,
		func(context.Context) (int64, error) { called = true; return 103, nil })
	if !errors.Is(err, ErrFanoutExceeded) {
		t.Errorf("RecordChild over fan-out err = %v, want ErrFanoutExceeded", err)
	}
	if called {
		t.Error("create callback ran despite the fan-out cap — the cap must be checked before any upstream call")
	}

	// Depth: a child of #102 would be depth 3; max 2 → rejected, not called.
	called = false
	_, err = store.RecordChild(ctx, Lineage{Username: user, Connection: "default", ParentNumber: 102, CreatedByRun: "run-3"}, 2, 5,
		func(context.Context) (int64, error) { called = true; return 104, nil })
	if !errors.Is(err, ErrDepthExceeded) {
		t.Errorf("RecordChild over depth err = %v, want ErrDepthExceeded", err)
	}
	if called {
		t.Error("create callback ran despite the depth cap")
	}

	// A failing create leaves no row behind.
	boom := errors.New("upstream down")
	if _, err := store.RecordChild(ctx, Lineage{Username: user, Connection: "default", ParentNumber: 100, CreatedByRun: "run-4"}, 3, 5,
		func(context.Context) (int64, error) { return 0, boom }); !errors.Is(err, boom) {
		t.Errorf("RecordChild with failing create err = %v, want the create error", err)
	}
	if n, _ := store.ChildrenCount(ctx, user, "default", "run-4"); n != 0 {
		t.Errorf("ChildrenCount(run-4) after failed create = %d, want 0 (rolled back)", n)
	}

	// Zero caps mean unlimited.
	if _, err := store.RecordChild(ctx, Lineage{Username: user, Connection: "default", ParentNumber: 102, CreatedByRun: "run-1"}, 0, 0,
		func(context.Context) (int64, error) { return 105, nil }); err != nil {
		t.Errorf("RecordChild with zero caps: %v, want allowed", err)
	}
}

// TestRecordChild_ContextCancelledAfterUpstreamCreate (review of #2034,
// blocking): once the upstream create has succeeded, the issue exists on
// the forge — the lineage row must still be recorded even if the caller's
// context is cancelled in that window, or the child goes uncounted for
// fan-out, reads as depth 0, and a retry files a duplicate.
func TestRecordChild_ContextCancelledAfterUpstreamCreate(t *testing.T) {
	store, _ := newTrackerTestStore(t)
	const user = "tracker-store-lineage-cancel"
	bg := context.Background()
	_, _ = store.pool.Exec(bg, "DELETE FROM tracker_issue_lineage WHERE username = $1", user)

	ctx, cancel := context.WithCancel(bg)
	defer cancel()
	rec, err := store.RecordChild(ctx, Lineage{Username: user, Connection: "default", ParentNumber: 10, CreatedByRun: "run-c"}, 3, 5,
		func(context.Context) (int64, error) {
			cancel() // the forge accepted the create; the caller then goes away
			return 11, nil
		})
	if err != nil {
		t.Fatalf("RecordChild after upstream success with a cancelled context: %v, want the row recorded anyway", err)
	}
	if rec.ChildNumber != 11 || rec.Depth != 1 {
		t.Errorf("recorded = %+v, want child=11 depth=1", rec)
	}
	if n, _ := store.ChildrenCount(bg, user, "default", "run-c"); n != 1 {
		t.Errorf("ChildrenCount(run-c) = %d, want 1 — the created child must count toward fan-out", n)
	}
	if d, _ := store.IssueDepth(bg, user, "default", 11); d != 1 {
		t.Errorf("IssueDepth(#11) = %d, want 1", d)
	}
}

// TestRecordChild_RecordingFailureNamesTheCreatedIssue: if the lineage
// insert genuinely fails after the upstream create succeeded, the error
// is a *LineageRecordError carrying the created issue's number, so the
// caller can report it instead of retrying blind.
func TestRecordChild_RecordingFailureNamesTheCreatedIssue(t *testing.T) {
	store, ctx := newTrackerTestStore(t)
	const user = "tracker-store-lineage-recfail"
	_, _ = store.pool.Exec(ctx, "DELETE FROM tracker_issue_lineage WHERE username = $1", user)
	// Occupy child #777's primary key so the post-create insert conflicts.
	if _, err := store.pool.Exec(ctx, `INSERT INTO tracker_issue_lineage (username, connection, child_number, parent_number, created_by_run, depth)
		VALUES ($1, 'default', 777, 1, 'run-other', 1)`, user); err != nil {
		t.Fatalf("seed conflicting row: %v", err)
	}

	_, err := store.RecordChild(ctx, Lineage{Username: user, Connection: "default", ParentNumber: 10, CreatedByRun: "run-r"}, 3, 5,
		func(context.Context) (int64, error) { return 777, nil })
	var recErr *LineageRecordError
	if !errors.As(err, &recErr) {
		t.Fatalf("err = %v, want a *LineageRecordError", err)
	}
	if recErr.ChildNumber != 777 {
		t.Errorf("LineageRecordError.ChildNumber = %d, want 777 (the issue that now exists upstream)", recErr.ChildNumber)
	}
}

// TestRecordChild_FanoutCapHoldsUnderConcurrency (review of #2034): 12
// concurrent creates from one run against max_children_per_run=3 yield
// exactly 3 upstream calls and 3 rows. Run with -race.
func TestRecordChild_FanoutCapHoldsUnderConcurrency(t *testing.T) {
	store, ctx := newTrackerTestStore(t)
	const user = "tracker-store-lineage-race"
	_, _ = store.pool.Exec(ctx, "DELETE FROM tracker_issue_lineage WHERE username = $1", user)

	var upstreamCalls atomic.Int64
	var wg sync.WaitGroup
	errs := make([]error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = store.RecordChild(ctx, Lineage{Username: user, Connection: "default", ParentNumber: 1, CreatedByRun: "run-race"}, 3, 3,
				func(context.Context) (int64, error) { return 1000 + upstreamCalls.Add(1), nil })
		}(i)
	}
	wg.Wait()

	if got := upstreamCalls.Load(); got != 3 {
		t.Errorf("upstream create calls = %d, want exactly 3", got)
	}
	if n, _ := store.ChildrenCount(ctx, user, "default", "run-race"); n != 3 {
		t.Errorf("lineage rows = %d, want exactly 3", n)
	}
	var capped int
	for _, err := range errs {
		switch {
		case err == nil:
		case errors.Is(err, ErrFanoutExceeded):
			capped++
		default:
			t.Errorf("unexpected error: %v", err)
		}
	}
	if capped != 9 {
		t.Errorf("fan-out rejections = %d, want 9", capped)
	}
}
