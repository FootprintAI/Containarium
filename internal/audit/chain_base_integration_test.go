//go:build integration

// Real-Postgres coverage for verification after a retention purge (#2878): a
// purge removes a prefix of the hash chain and moves the chain base, and
// `audit verify` must start from that base without losing the ability to
// detect tampering of what is left.
//
//	CONTAINARIUM_TEST_DSN=postgres://... go test -tags=integration ./internal/audit/
package audit

import (
	"context"
	"strings"
	"testing"
)

// simulatePurge removes the first n rows and moves the base to the last of
// them in one transaction, the way the retention sweeper does. It returns the
// base it wrote.
func simulatePurge(t *testing.T, s *Store, n int) ChainBase {
	t.Helper()
	ctx := context.Background()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var id int64
	var hash string
	if err := tx.QueryRow(ctx,
		`SELECT id, row_hash FROM audit_logs ORDER BY id ASC OFFSET $1 LIMIT 1`, n-1).Scan(&id, &hash); err != nil {
		t.Fatalf("pick base row: %v", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM audit_logs WHERE id <= $1`, id); err != nil {
		t.Fatalf("delete prefix: %v", err)
	}
	if err := WriteChainBase(ctx, tx, id, hash, int64(n)); err != nil {
		t.Fatalf("WriteChainBase: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return ChainBase{ID: id, Hash: hash, RowsPurged: int64(n)}
}

func TestChainBase_VerifyStartsFromTheBaseAfterAPrefixPurge(t *testing.T) {
	ctx := context.Background()
	s := auditTestStore(t)
	logN(t, s, 30)
	base := simulatePurge(t, s, 10)

	got, ok, err := s.ChainBase(ctx)
	if err != nil || !ok || got.ID != base.ID || got.Hash != base.Hash {
		t.Fatalf("ChainBase = %+v ok=%v err=%v, want id=%d hash=%q", got, ok, err, base.ID, base.Hash)
	}
	// The default verify starts at genesis (fromID 0). Without the base the
	// first retained row's prev_hash would be reported as a broken chain.
	firstBad, err := s.VerifyChainSinceID(ctx, 0, 1000)
	if err != nil || firstBad != 0 {
		t.Fatalf("a purged chain must verify from its base: firstBad=%d err=%v", firstBad, err)
	}
	// A from-id inside the purged range is clamped to the base, not an error.
	if firstBad, err := s.VerifyChainSinceID(ctx, base.ID-3, 1000); err != nil || firstBad != 0 {
		t.Fatalf("a from-id below the base must start at the base: firstBad=%d err=%v", firstBad, err)
	}
}

func TestChainBase_TamperingAfterAPurgeIsStillDetected(t *testing.T) {
	ctx := context.Background()
	s := auditTestStore(t)
	logN(t, s, 30)
	simulatePurge(t, s, 10)

	var victim int64
	if err := s.pool.QueryRow(ctx,
		`UPDATE audit_logs SET username = 'mallory' WHERE id = (SELECT id FROM audit_logs ORDER BY id ASC OFFSET 7 LIMIT 1) RETURNING id`,
	).Scan(&victim); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	firstBad, err := s.VerifyChainSinceID(ctx, 0, 1000)
	if err == nil || firstBad != victim {
		t.Fatalf("an edited retained row must be reported: firstBad=%d (want %d) err=%v", firstBad, victim, err)
	}
}

func TestChainBase_ABaseThatDoesNotMatchTheFirstRetainedRowIsDetected(t *testing.T) {
	ctx := context.Background()
	s := auditTestStore(t)
	logN(t, s, 30)
	base := simulatePurge(t, s, 10)

	// A base whose hash is not the first retained row's prev_hash: either the
	// base was edited or rows between it and the retained chain are gone.
	if _, err := s.pool.Exec(ctx, `UPDATE audit_chain_base SET base_hash = $1`, strings.Repeat("0", 64)); err != nil {
		t.Fatal(err)
	}
	var first int64
	if err := s.pool.QueryRow(ctx, `SELECT min(id) FROM audit_logs`).Scan(&first); err != nil {
		t.Fatal(err)
	}
	firstBad, err := s.VerifyChainSinceID(ctx, 0, 1000)
	if err == nil || firstBad != first {
		t.Fatalf("a wrong base must fail at the first retained row %d: firstBad=%d err=%v (base id %d)", first, firstBad, err, base.ID)
	}
}

func TestChainBase_RowsDeletedBeyondTheBaseAreStillDetected(t *testing.T) {
	ctx := context.Background()
	s := auditTestStore(t)
	logN(t, s, 30)
	simulatePurge(t, s, 10)

	// Deleting a retained row (not a prefix) leaves a gap the base cannot
	// explain.
	if _, err := s.pool.Exec(ctx,
		`DELETE FROM audit_logs WHERE id = (SELECT id FROM audit_logs ORDER BY id ASC OFFSET 5 LIMIT 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.VerifyChainSinceID(ctx, 0, 1000); err == nil {
		t.Fatal("removing a retained row left the purged chain verifying clean")
	}
}

func TestChainBase_RowHashAtTheBaseIsTheBaseHash(t *testing.T) {
	ctx := context.Background()
	s := auditTestStore(t)
	logN(t, s, 30)
	base := simulatePurge(t, s, 10)

	// The row is gone, but the anchor check compares an anchored root at that
	// checkpoint with what the database holds; the base still holds it.
	hash, found, err := s.RowHashAt(ctx, base.ID)
	if err != nil || !found || hash != base.Hash {
		t.Fatalf("RowHashAt(base) = %q found=%v err=%v, want the base hash", hash, found, err)
	}
	// Below the base nothing is held any more.
	if _, found, err := s.RowHashAt(ctx, base.ID-1); err != nil || found {
		t.Fatalf("RowHashAt(below base) found=%v err=%v, want not found", found, err)
	}
}

func TestChainBase_TheBaseNeverMovesBackwards(t *testing.T) {
	ctx := context.Background()
	s := auditTestStore(t)
	logN(t, s, 30)
	simulatePurge(t, s, 10)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := WriteChainBase(ctx, tx, 3, "x", 1); err == nil {
		t.Fatal("WriteChainBase moved the base backwards")
	}
}

// publishReal anchors the real hash of each row through the tee, file first.
func publishReal(t *testing.T, s *Store, f *anchorFixture, ids ...int64) {
	t.Helper()
	for _, id := range ids {
		h, found, err := s.RowHashAt(context.Background(), id)
		if err != nil || !found {
			t.Fatalf("no row %d to anchor: found=%v err=%v", id, found, err)
		}
		if err := f.tee.PublishRoot(context.Background(), id, h); err != nil {
			t.Fatalf("PublishRoot(%d): %v", id, err)
		}
	}
}

func TestVerifyAnchorsAgainstBucket_AfterARealPurge(t *testing.T) {
	ctx := context.Background()
	s := auditTestStore(t)
	logN(t, s, 40)
	f := newAnchorFixture(t, 0)
	publishReal(t, s, f, 5, 10, 20, 30, 40)
	simulatePurge(t, s, 15) // base = 15: checkpoints 5 and 10 lose their rows

	r, err := VerifyAnchorsAgainstBucket(ctx, s, f.file, f.bucket)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !r.OK() {
		t.Fatalf("a legitimately purged chain must pass the bucket comparison, got failures=%v", r.Failures)
	}
	if r.CheckedCheckpoints != 3 || r.BelowChainBase != 2 || r.LatestCheckpoint != 40 {
		t.Errorf("checked/below/latest = %d/%d/%d, want 3/2/40", r.CheckedCheckpoints, r.BelowChainBase, r.LatestCheckpoint)
	}
	// The file-only path ends at the latest checkpoint, which the purge kept.
	if res, err := s.VerifyChainAgainstAnchor(ctx, f.file); err != nil || !res.OK() {
		t.Fatalf("verify-anchor against the local file after a purge: %+v err=%v", res, err)
	}

	// Rewriting a retained, anchored row is still caught.
	if _, err := s.pool.Exec(ctx, `UPDATE audit_logs SET row_hash = 'forged' WHERE id = 20`); err != nil {
		t.Fatal(err)
	}
	r, err = VerifyAnchorsAgainstBucket(ctx, s, f.file, f.bucket)
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(r.Failures, FindingDatabaseRootDiffers, 20) {
		t.Fatalf("a rewritten anchored row must still fail after a purge, got %v", findingKinds(r.Failures))
	}
}
