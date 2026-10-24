//go:build integration

// Real-Postgres coverage for the purge of the hash-chained audit_logs (#2878,
// #2420): rows are written through audit.Store so they form a real chain, a
// purge runs through the sweeper exactly as the daemon runs it, and what must
// hold afterwards is that the chain still verifies from its stored base, the
// anchored row and everything after it are untouched, and a legal hold or a
// missing anchor stops the purge.
//
//	CONTAINARIUM_TEST_DSN=postgres://... go test -tags=integration ./internal/retention/pgstore/
package pgstore_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/retention"
	"github.com/footprintai/containarium/internal/retention/pgstore"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

const (
	gwClass   = pb.RetentionClass_RETENTION_CLASS_GATEWAY_LOGS
	sessClass = pb.RetentionClass_RETENTION_CLASS_SESSION_TRANSCRIPTS
)

// chainEnv is a database with a real audit chain, the retention store, and a
// sweeper wired to the chain source the way the daemon wires it.
type chainEnv struct {
	ctx    context.Context
	pool   *pgxpool.Pool
	audit  *audit.Store
	store  *pgstore.Store
	source *pgstore.ChainSource
	sweep  *retention.Sweeper
	audits int
}

type chainRow struct {
	action string
	age    int // days old
	org    string
}

// newChainEnv writes rows in order (so ids ascend with the chain) and sets both
// chained classes to a 90-day window unless the caller changes them. The
// anchor function is left unset; tests set it.
func newChainEnv(t *testing.T, rows []chainRow) *chainEnv {
	t.Helper()
	pool := sourcesPool(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS audit_logs, audit_chain_base`); err != nil {
		t.Fatal(err)
	}
	as, err := audit.NewStore(ctx, pool)
	if err != nil {
		t.Fatalf("audit store: %v", err)
	}
	for i, r := range rows {
		if err := as.Log(ctx, &audit.AuditEntry{
			Timestamp: time.Now().AddDate(0, 0, -r.age), Username: "u", Action: r.action,
			ResourceType: "x", ResourceID: fmt.Sprintf("r-%d", i), OrgID: r.org, StatusCode: 200,
		}); err != nil {
			t.Fatalf("log %d: %v", i, err)
		}
	}
	st, err := pgstore.New(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetPolicy(ctx, []*pb.RetentionWindow{{Class: gwClass, Days: 90}, {Class: sessClass, Days: 90}}, "admin", nil); err != nil {
		t.Fatal(err)
	}
	e := &chainEnv{ctx: ctx, pool: pool, audit: as, store: st, source: pgstore.NewChainSource(pool)}
	e.sweep = retention.NewSweeper(st, nil, retention.ChainAndBundles())
	e.sweep.AddPrefixSource(e.source)
	e.sweep.SetAuditor(func(context.Context, *pb.RetentionReport) error { e.audits++; return nil })
	return e
}

// anchorAt makes the anchor the row at id, with its real hash.
func (e *chainEnv) anchorAt(t *testing.T, id int64) {
	t.Helper()
	h, found, err := e.audit.RowHashAt(e.ctx, id)
	if err != nil || !found {
		t.Fatalf("no row %d to anchor: found=%v err=%v", id, found, err)
	}
	e.source.SetAnchor(func(context.Context) (pgstore.Anchor, bool, error) {
		return pgstore.Anchor{Checkpoint: id, Root: h}, true, nil
	})
}

func (e *chainEnv) enforce(t *testing.T) *pb.RetentionReport {
	t.Helper()
	if _, err := e.store.SetMode(e.ctx, pb.RetentionMode_RETENTION_MODE_ENFORCE, "admin", nil); err != nil {
		t.Fatal(err)
	}
	rep, err := e.sweep.Sweep(e.ctx)
	if err != nil {
		t.Fatalf("enforced Sweep: %v", err)
	}
	return rep
}

func (e *chainEnv) ids(t *testing.T) (min, max, n int64) {
	t.Helper()
	if err := e.pool.QueryRow(e.ctx, `SELECT coalesce(min(id),0), coalesce(max(id),0), count(*) FROM audit_logs`).Scan(&min, &max, &n); err != nil {
		t.Fatal(err)
	}
	return
}

func (e *chainEnv) verify(t *testing.T) {
	t.Helper()
	if bad, err := e.audit.VerifyChainSinceID(e.ctx, 0, 1000); err != nil || bad != 0 {
		t.Fatalf("audit verify after the purge: firstBad=%d err=%v", bad, err)
	}
}

func entry(t *testing.T, rep *pb.RetentionReport, c pb.RetentionClass) *pb.RetentionStoreReport {
	t.Helper()
	for _, s := range rep.GetStores() {
		if s.GetClass() == c && s.GetStore() == "audit_logs" {
			return s
		}
	}
	t.Fatalf("report has no %v/audit_logs: %v", c, rep.GetStores())
	return nil
}

// expiredThenFresh is 20 rows past the 90-day window followed by 10 inside it,
// a mix of gateway-log and session actions.
func expiredThenFresh() []chainRow {
	var rows []chainRow
	for i := 0; i < 20; i++ {
		a := "api_access"
		if i%3 == 0 {
			a = "ssh_login"
		}
		rows = append(rows, chainRow{a, 200, ""})
	}
	for i := 0; i < 10; i++ {
		rows = append(rows, chainRow{"api_access", 1, ""})
	}
	return rows
}

func TestChain_PurgesTheExpiredPrefixBelowTheAnchorAndVerificationStillPasses(t *testing.T) {
	e := newChainEnv(t, expiredThenFresh())
	e.anchorAt(t, 15)

	rep := e.enforce(t)

	min, max, n := e.ids(t)
	if min != 15 || max != 30 || n != 16 {
		t.Fatalf("after the purge ids are %d..%d (%d rows), want 15..30 (16 rows): everything below the anchor, nothing at or above it", min, max, n)
	}
	e.verify(t)
	base, ok, err := e.audit.ChainBase(e.ctx)
	if err != nil || !ok || base.ID != 14 || base.RowsPurged != 14 {
		t.Fatalf("chain base = %+v ok=%v err=%v, want id 14 with 14 rows purged", base, ok, err)
	}
	gw, sess := entry(t, rep, gwClass), entry(t, rep, sessClass)
	if gw.GetRemoved()+sess.GetRemoved() != 14 || gw.GetChainBase().GetBaseId() != 14 || !rep.GetEnforced() {
		t.Errorf("report removed gw/sess = %d/%d base=%v enforced=%v, want 14 in total and base 14", gw.GetRemoved(), sess.GetRemoved(), gw.GetChainBase(), rep.GetEnforced())
	}
	if sess.GetRemoved() == 0 || gw.GetRemoved() == 0 {
		t.Errorf("both classes had rows in the prefix, got gw=%d sess=%d", gw.GetRemoved(), sess.GetRemoved())
	}
	if e.audits != 1 {
		t.Errorf("a purge wrote %d audit entries, want exactly 1", e.audits)
	}
	// The anchored row itself is still there, so the anchor still verifies.
	if res, err := e.audit.VerifyChainAgainstAnchor(e.ctx, fixed{15, mustHash(t, e, 15)}); err != nil || !res.OK() {
		t.Fatalf("verify-anchor after the purge: %+v err=%v", res, err)
	}
	// A new audit row still chains from the retained tail.
	if err := e.audit.Log(e.ctx, &audit.AuditEntry{Username: "u", Action: "after", StatusCode: 200}); err != nil {
		t.Fatal(err)
	}
	e.verify(t)
}

type fixed struct {
	cp   int64
	root string
}

func (fixed) PublishRoot(context.Context, int64, string) error { return nil }
func (f fixed) LastPublished(context.Context) (int64, string, bool, error) {
	return f.cp, f.root, true, nil
}

func mustHash(t *testing.T, e *chainEnv, id int64) string {
	t.Helper()
	h, ok, err := e.audit.RowHashAt(e.ctx, id)
	if err != nil || !ok {
		t.Fatalf("row %d: found=%v err=%v", id, ok, err)
	}
	return h
}

func TestChain_NoRowAtOrAboveTheAnchorIsEverRemoved(t *testing.T) {
	// Every row is far past its window, so only the anchor stops the purge.
	var rows []chainRow
	for i := 0; i < 30; i++ {
		rows = append(rows, chainRow{"api_access", 400, ""})
	}
	e := newChainEnv(t, rows)
	e.anchorAt(t, 12)
	e.enforce(t)
	if min, max, n := e.ids(t); min != 12 || max != 30 || n != 19 {
		t.Fatalf("ids %d..%d (%d rows), want 12..30 (19 rows): the anchored row and all after it stay", min, max, n)
	}

	// An anchor at the very first row leaves nothing below it to remove.
	e = newChainEnv(t, rows)
	e.anchorAt(t, 1)
	e.enforce(t)
	if _, _, n := e.ids(t); n != 30 {
		t.Fatalf("with the anchor at the first row %d rows remain, want all 30", 30-n)
	}
	if _, ok, _ := e.audit.ChainBase(e.ctx); ok {
		t.Error("nothing was purged, so there must be no chain base")
	}
}

func TestChain_NothingIsRemovedWithoutAnAnchor(t *testing.T) {
	e := newChainEnv(t, expiredThenFresh())
	// No anchor function set at all.
	rep := e.enforce(t)
	if _, _, n := e.ids(t); n != 30 {
		t.Fatalf("%d rows remain without an anchor, want all 30", n)
	}
	if got := entry(t, rep, gwClass); !strings.Contains(got.GetNote(), "anchor") {
		t.Errorf("the entry should say why nothing was purged, got note %q", got.GetNote())
	}

	// An anchor function that reports nothing published behaves the same.
	e.source.SetAnchor(func(context.Context) (pgstore.Anchor, bool, error) { return pgstore.Anchor{}, false, nil })
	e.enforce(t)
	if _, _, n := e.ids(t); n != 30 {
		t.Fatalf("%d rows remain with an empty anchor, want all 30", n)
	}

	// An unreadable anchor fails closed, too.
	e.source.SetAnchor(func(context.Context) (pgstore.Anchor, bool, error) {
		return pgstore.Anchor{}, false, fmt.Errorf("bucket 403")
	})
	e.enforce(t)
	if _, _, n := e.ids(t); n != 30 {
		t.Fatalf("%d rows remain with an unreadable anchor, want all 30", n)
	}
}

func TestChain_AnchoredRowThatNoLongerMatchesItsAnchorBlocksThePurge(t *testing.T) {
	e := newChainEnv(t, expiredThenFresh())
	e.source.SetAnchor(func(context.Context) (pgstore.Anchor, bool, error) {
		return pgstore.Anchor{Checkpoint: 15, Root: "what-was-anchored"}, true, nil
	})
	rep := e.enforce(t)
	if _, _, n := e.ids(t); n != 30 {
		t.Fatalf("%d rows remain after a purge against a mismatching anchor, want all 30: a purge must not destroy the evidence verify-anchor would use", n)
	}
	if got := entry(t, rep, gwClass); !strings.Contains(got.GetNote(), "verify-anchor") {
		t.Errorf("note = %q, want it to point at audit verify-anchor", got.GetNote())
	}
}

func TestChain_DryRunReportsWhatWouldGoAndDeletesNothing(t *testing.T) {
	e := newChainEnv(t, expiredThenFresh())
	e.anchorAt(t, 15)

	rep, err := e.sweep.Sweep(e.ctx) // the default mode is DRY_RUN
	if err != nil {
		t.Fatal(err)
	}
	if _, _, n := e.ids(t); n != 30 {
		t.Fatalf("a DRY_RUN sweep left %d rows, want all 30", n)
	}
	gw, sess := entry(t, rep, gwClass), entry(t, rep, sessClass)
	if gw.GetEligible()+sess.GetEligible() != 14 || gw.GetOlderThanCutoff()+sess.GetOlderThanCutoff() != 20 {
		t.Errorf("eligible %d+%d older %d+%d, want 14 eligible of 20 older in total",
			gw.GetEligible(), sess.GetEligible(), gw.GetOlderThanCutoff(), sess.GetOlderThanCutoff())
	}
	if gw.GetRemoved() != 0 || rep.GetEnforced() || e.audits != 0 {
		t.Errorf("dry run removed %d, enforced=%v, audits=%d, want none", gw.GetRemoved(), rep.GetEnforced(), e.audits)
	}
	if !strings.Contains(gw.GetNote(), "anchor") {
		t.Errorf("note = %q, want it to name the anchor that bounds the purge", gw.GetNote())
	}
}

func TestChain_ALongerSessionWindowKeepsTheWholePrefixBehindIt(t *testing.T) {
	// Row 1 is a 200-day-old SSH login; the session window is 365 days, so it
	// is not expired, and the purge is a prefix: nothing after it can go
	// either, however old.
	rows := []chainRow{{"ssh_login", 200, ""}}
	for i := 0; i < 19; i++ {
		rows = append(rows, chainRow{"api_access", 200, ""})
	}
	rows = append(rows, chainRow{"api_access", 1, ""})
	e := newChainEnv(t, rows)
	if _, err := e.store.SetPolicy(e.ctx, []*pb.RetentionWindow{{Class: sessClass, Days: 365}}, "admin", nil); err != nil {
		t.Fatal(err)
	}
	e.anchorAt(t, 20)
	e.enforce(t)
	if _, _, n := e.ids(t); n != 21 {
		t.Fatalf("%d rows remain, want all 21: an unexpired session row at the front blocks the prefix", n)
	}
}

func TestChain_ALegalHoldStopsThePrefixAtTheOldestHeldOrOrglessRow(t *testing.T) {
	t.Run("org-less rows are held while any hold is active (Q21)", func(t *testing.T) {
		e := newChainEnv(t, expiredThenFresh()) // every row has no org
		e.anchorAt(t, 15)
		if _, err := e.store.SetHold(e.ctx, "org-a", "case", "admin", nil); err != nil {
			t.Fatal(err)
		}
		e.enforce(t)
		if _, _, n := e.ids(t); n != 30 {
			t.Fatalf("%d rows remain, want all 30: with a hold active nothing org-less may be purged", n)
		}
	})
	t.Run("a held org's oldest row bounds the purge", func(t *testing.T) {
		var rows []chainRow
		for i := 0; i < 30; i++ {
			org := "org-b"
			if i == 7 { // id 8
				org = "org-a"
			}
			rows = append(rows, chainRow{"api_access", 200, org})
		}
		e := newChainEnv(t, rows)
		e.anchorAt(t, 25)
		if _, err := e.store.SetHold(e.ctx, "org-a", "case", "admin", nil); err != nil {
			t.Fatal(err)
		}
		rep := e.enforce(t)
		min, max, _ := e.ids(t)
		if min != 8 || max != 30 {
			t.Fatalf("ids %d..%d, want 8..30: the purge stops at the held org's oldest row (id 8)", min, max)
		}
		e.verify(t)
		if got := entry(t, rep, gwClass); got.GetChainBase().GetBaseId() != 7 {
			t.Errorf("base = %v, want id 7", got.GetChainBase())
		}

		// Once the hold is released the rest of the prefix goes on the next sweep.
		if _, err := e.store.ReleaseHold(e.ctx, "org-a", "admin", nil); err != nil {
			t.Fatal(err)
		}
		e.enforce(t)
		if min, _, _ := e.ids(t); min != 25 {
			t.Fatalf("after the release the purge stops at the anchor: min id %d, want 25", min)
		}
		e.verify(t)
	})
}

func TestChain_RemovePrefixWaitsForAHoldThatIsBeingPlaced(t *testing.T) {
	e := newChainEnv(t, expiredThenFresh())
	e.anchorAt(t, 15)
	tx, err := e.pool.Begin(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(e.ctx) }()
	if _, err := tx.Exec(e.ctx, `INSERT INTO retention_legal_holds (org_id, reason, set_by, set_at) VALUES ('org-a', 'case', 'admin', now())`); err != nil {
		t.Fatal(err)
	}

	type result struct {
		res retention.PrefixRemoval
		err error
	}
	done := make(chan result, 1)
	go func() {
		ctx, cancel := context.WithTimeout(e.ctx, 20*time.Second)
		defer cancel()
		cut := time.Now().AddDate(0, 0, -90)
		res, err := e.source.RemovePrefix(ctx, map[pb.RetentionClass]time.Time{gwClass: cut, sessClass: cut}, nil, 1000)
		done <- result{res, err}
	}()
	select {
	case r := <-done:
		t.Fatalf("RemovePrefix returned (%+v, %v) while a hold was being placed; it must wait for that transaction", r.res, r.err)
	case <-time.After(500 * time.Millisecond):
	}
	if err := tx.Commit(e.ctx); err != nil {
		t.Fatal(err)
	}
	if r := <-done; r.err != nil {
		t.Fatalf("RemovePrefix: %v", r.err)
	}
	// The hold committed first, and the rows have no org, so they are held.
	if _, _, n := e.ids(t); n != 30 {
		t.Fatalf("%d rows remain, want all 30: the hold committed before the delete ran", n)
	}
}

func TestChain_ASecondPurgeMovesTheBaseForwardAndAccumulates(t *testing.T) {
	e := newChainEnv(t, expiredThenFresh())
	e.anchorAt(t, 10)
	e.enforce(t)
	e.anchorAt(t, 18)
	e.enforce(t)

	base, ok, err := e.audit.ChainBase(e.ctx)
	if err != nil || !ok || base.ID != 17 || base.RowsPurged != 17 {
		t.Fatalf("base = %+v ok=%v err=%v, want id 17 and 17 rows purged in total", base, ok, err)
	}
	if min, _, _ := e.ids(t); min != 18 {
		t.Fatalf("min id %d, want 18", min)
	}
	e.verify(t)
}

func TestChain_AMissingHoldsTableRemovesNothing(t *testing.T) {
	e := newChainEnv(t, expiredThenFresh())
	e.anchorAt(t, 15)
	if _, err := e.pool.Exec(e.ctx, `DROP TABLE retention_legal_holds`); err != nil {
		t.Fatal(err)
	}
	cut := time.Now().AddDate(0, 0, -90)
	res, err := e.source.RemovePrefix(e.ctx, map[pb.RetentionClass]time.Time{gwClass: cut, sessClass: cut}, nil, 1000)
	if err != nil || len(res.RemovedByClass) != 0 && res.RemovedByClass[gwClass]+res.RemovedByClass[sessClass] != 0 || !strings.Contains(res.Skipped, "retention_legal_holds") {
		t.Fatalf("RemovePrefix without a holds table = (%+v, %v), want nothing removed and a Skipped reason naming the table", res, err)
	}
	if _, _, n := e.ids(t); n != 30 {
		t.Fatalf("%d rows remain, want all 30", n)
	}
}
