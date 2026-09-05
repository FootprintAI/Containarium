//go:build integration

// Integration coverage for the audit hash chain's persistence (#1300).
//
// docs/ISO27001-COMPLIANCE.md cites internal/audit as the evidence for
// A.8.15. The chain's *computation* is well covered — hash_chain_test.go
// exercises computeRowHash and VerifyChain as pure functions. Its
// *persistence* was covered nowhere: whether rows are written in order,
// whether prev_hash is threaded correctly across real inserts, whether
// concurrent appenders fork the chain, and whether tampering is actually
// detected by the query that reads it back.
//
// That is the half an auditor cares about, and the half the control is
// claimed on.
//
//	CONTAINARIUM_TEST_DSN=postgres://... go test -tags=integration ./internal/audit/
package audit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func auditTestStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("CONTAINARIUM_TEST_DSN")
	if dsn == "" {
		t.Fatal("CONTAINARIUM_TEST_DSN is unset. Failing rather than skipping: a skipped test " +
			"and a passing one are indistinguishable, which is how this gap survived.")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)

	// Each test starts from an empty chain, so the first row's prev_hash is
	// the genesis value rather than whatever a previous test left.
	if _, err := pool.Exec(context.Background(), `DROP TABLE IF EXISTS audit_logs`); err != nil {
		t.Fatalf("reset: %v", err)
	}
	s, err := NewStore(context.Background(), pool)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return s
}

func logN(t *testing.T, s *Store, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		err := s.Log(context.Background(), &AuditEntry{
			Username:     "alice",
			Action:       "container_create",
			ResourceType: "container",
			ResourceID:   fmt.Sprintf("alice-%d", i),
			SourceIP:     "10.0.0.1",
			StatusCode:   200,
		})
		if err != nil {
			t.Fatalf("log %d: %v", i, err)
		}
	}
}

// The chain a real sequence of writes produces must verify. This is the
// baseline the other cases are measured against — if it does not hold,
// nothing below means anything.
func TestAuditChain_WrittenRowsVerify(t *testing.T) {
	s := auditTestStore(t)
	logN(t, s, 25)

	firstBad, err := s.VerifyChainSinceID(context.Background(), 0, 1000)
	if err != nil {
		t.Fatalf("chain does not verify after %d ordinary writes: firstBad=%d err=%v", 25, firstBad, err)
	}
	if firstBad != 0 {
		t.Errorf("firstBad = %d, want 0 for an intact chain", firstBad)
	}
}

// Log takes SELECT ... FOR UPDATE on the chain tail so two appenders cannot
// read the same prev_hash and fork. Only a real database can show that;
// nothing about the hash function is involved.
func TestAuditChain_ConcurrentAppendersDoNotFork(t *testing.T) {
	s := auditTestStore(t)

	const writers, each = 8, 6
	start := make(chan struct{})
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			<-start
			for i := 0; i < each; i++ {
				_ = s.Log(context.Background(), &AuditEntry{
					Username:     fmt.Sprintf("user-%d", w),
					Action:       "container_create",
					ResourceType: "container",
					ResourceID:   fmt.Sprintf("c-%d-%d", w, i),
					StatusCode:   200,
				})
			}
		}(w)
	}
	close(start)
	wg.Wait()

	firstBad, err := s.VerifyChainSinceID(context.Background(), 0, 1000)
	if err != nil {
		t.Fatalf("concurrent appends forked the chain at row %d: %v\n"+
			"Each row's prev_hash must be the previous row's row_hash; two appenders reading the "+
			"same tail produce two rows claiming the same predecessor.", firstBad, err)
	}
}

// The point of the chain: an edited row is detectable. If tampering does not
// fail verification, the control is decorative.
func TestAuditChain_TamperedRowIsDetected(t *testing.T) {
	ctx := context.Background()
	s := auditTestStore(t)
	logN(t, s, 10)

	// Change a field that is inside the hash, leaving row_hash alone — what
	// an edit through SQL looks like.
	var victim int64
	if err := s.pool.QueryRow(ctx,
		`UPDATE audit_logs SET username = 'mallory' WHERE id = (SELECT id FROM audit_logs ORDER BY id ASC OFFSET 4 LIMIT 1) RETURNING id`,
	).Scan(&victim); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	firstBad, err := s.VerifyChainSinceID(ctx, 0, 1000)
	if err == nil {
		t.Fatal("an edited audit row verified clean — the tamper-evidence this control is " +
			"claimed on does not hold")
	}
	if firstBad != victim {
		t.Errorf("reported row %d as first bad, want the edited row %d", firstBad, victim)
	}
}

// Deleting a row breaks the linkage even though every surviving row is
// internally consistent — the case a per-row checksum would miss and a chain
// is supposed to catch.
func TestAuditChain_DeletedRowIsDetected(t *testing.T) {
	ctx := context.Background()
	s := auditTestStore(t)
	logN(t, s, 10)

	if _, err := s.pool.Exec(ctx,
		`DELETE FROM audit_logs WHERE id = (SELECT id FROM audit_logs ORDER BY id ASC OFFSET 5 LIMIT 1)`,
	); err != nil {
		t.Fatalf("delete: %v", err)
	}

	if _, err := s.VerifyChainSinceID(ctx, 0, 1000); err == nil {
		t.Fatal("removing an audit row left the chain verifying clean — an operator could delete " +
			"the record of an action and nothing would show it")
	}
}

// --- #1706: anchoring against a privileged rewrite ----------------------

// rewriteAndRecomputeForward simulates the exact attack #1706 describes: an
// operator with Postgres write access edits a row, then recomputes
// row_hash/prev_hash forward through every row after it — exactly what
// Log's own hashing logic would produce, so internal consistency
// (VerifyChain/VerifyChainSinceID) cannot tell it apart from a row that was
// never touched.
func rewriteAndRecomputeForward(t *testing.T, s *Store, tamperID int64) {
	t.Helper()
	ctx := context.Background()

	if _, err := s.pool.Exec(ctx,
		`UPDATE audit_logs SET username = 'mallory' WHERE id = $1`, tamperID,
	); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, timestamp, username, action, resource_type, resource_id,
		       detail, source_ip, status_code, actor, delegation_chain,
		       token_id, org_id, run_id, hash_version
		FROM audit_logs WHERE id >= $1 ORDER BY id ASC
	`, tamperID)
	if err != nil {
		t.Fatalf("read forward: %v", err)
	}
	type fwdRow struct {
		id          int64
		entry       AuditEntry
		hashVersion int16
	}
	var toFix []fwdRow
	for rows.Next() {
		var r fwdRow
		if err := rows.Scan(&r.id, &r.entry.Timestamp, &r.entry.Username, &r.entry.Action,
			&r.entry.ResourceType, &r.entry.ResourceID, &r.entry.Detail, &r.entry.SourceIP,
			&r.entry.StatusCode, &r.entry.Actor, &r.entry.DelegationChain, &r.entry.TokenID,
			&r.entry.OrgID, &r.entry.RunID, &r.hashVersion); err != nil {
			rows.Close()
			t.Fatalf("scan forward row: %v", err)
		}
		toFix = append(toFix, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate forward rows: %v", err)
	}

	var prevHash string
	err = s.pool.QueryRow(ctx,
		`SELECT row_hash FROM audit_logs WHERE id < $1 ORDER BY id DESC LIMIT 1`, tamperID,
	).Scan(&prevHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			prevHash = HashEmpty
		} else {
			t.Fatalf("read predecessor hash: %v", err)
		}
	}

	for _, r := range toFix {
		newHash, err := computeRowHash(&r.entry, prevHash, r.hashVersion)
		if err != nil {
			t.Fatalf("recompute hash for id=%d: %v", r.id, err)
		}
		if _, err := s.pool.Exec(ctx,
			`UPDATE audit_logs SET row_hash = $1, prev_hash = $2 WHERE id = $3`,
			newHash, prevHash, r.id,
		); err != nil {
			t.Fatalf("rewrite forward at id=%d: %v", r.id, err)
		}
		prevHash = newHash
	}
}

func rowIDAtOffset(t *testing.T, s *Store, offset int) int64 {
	t.Helper()
	var id int64
	if err := s.pool.QueryRow(context.Background(),
		`SELECT id FROM audit_logs ORDER BY id ASC OFFSET $1 LIMIT 1`, offset,
	).Scan(&id); err != nil {
		t.Fatalf("row id at offset %d: %v", offset, err)
	}
	return id
}

func TestStore_RowHashAt(t *testing.T) {
	ctx := context.Background()
	s := auditTestStore(t)
	logN(t, s, 3)

	target := rowIDAtOffset(t, s, 1)
	hash, found, err := s.RowHashAt(ctx, target)
	if err != nil {
		t.Fatalf("RowHashAt: %v", err)
	}
	if !found || hash == "" {
		t.Fatalf("RowHashAt(%d) = (%q, %v), want a non-empty hash and found=true", target, hash, found)
	}

	_, found, err = s.RowHashAt(ctx, target+1_000_000)
	if err != nil {
		t.Fatalf("RowHashAt(missing): %v", err)
	}
	if found {
		t.Error("found = true for a row id that was never inserted")
	}
}

func TestVerifyChainAgainstAnchor_NoAnchorYet(t *testing.T) {
	ctx := context.Background()
	s := auditTestStore(t)
	logN(t, s, 3)

	sink, err := NewFileSink(filepath.Join(t.TempDir(), "anchors.jsonl"))
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	if _, err := s.VerifyChainAgainstAnchor(ctx, sink); !errors.Is(err, ErrNoAnchor) {
		t.Fatalf("err = %v, want ErrNoAnchor", err)
	}
}

func TestVerifyChainAgainstAnchor_CleanChainVerifiesOK(t *testing.T) {
	ctx := context.Background()
	s := auditTestStore(t)
	logN(t, s, 10)

	tail := rowIDAtOffset(t, s, 9)
	tailHash, found, err := s.RowHashAt(ctx, tail)
	if err != nil || !found {
		t.Fatalf("RowHashAt(tail): found=%v err=%v", found, err)
	}
	sink, err := NewFileSink(filepath.Join(t.TempDir(), "anchors.jsonl"))
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	if err := sink.PublishRoot(ctx, tail, tailHash); err != nil {
		t.Fatalf("PublishRoot: %v", err)
	}

	result, err := s.VerifyChainAgainstAnchor(ctx, sink)
	if err != nil {
		t.Fatalf("VerifyChainAgainstAnchor: %v", err)
	}
	if !result.OK() {
		t.Errorf("result = %+v, want OK() true for an untampered chain", result)
	}
}

// The money test: a privileged rewrite-and-recompute-forward is INVISIBLE
// to internal-consistency verification (proving the premise of #1706), and
// CAUGHT by anchor verification (proving the fix).
func TestVerifyChainAgainstAnchor_DetectsRewriteRecomputedForward(t *testing.T) {
	ctx := context.Background()
	s := auditTestStore(t)
	logN(t, s, 10)

	tamperID := rowIDAtOffset(t, s, 2) // an early row, well before the tail
	tail := rowIDAtOffset(t, s, 9)

	tailHash, found, err := s.RowHashAt(ctx, tail)
	if err != nil || !found {
		t.Fatalf("RowHashAt(tail) before attack: found=%v err=%v", found, err)
	}
	sink, err := NewFileSink(filepath.Join(t.TempDir(), "anchors.jsonl"))
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	if err := sink.PublishRoot(ctx, tail, tailHash); err != nil {
		t.Fatalf("PublishRoot: %v", err)
	}

	rewriteAndRecomputeForward(t, s, tamperID)

	// Prove the premise: internal-only verification is fooled.
	if firstBad, verr := s.VerifyChainSinceID(ctx, 0, 1000); verr != nil || firstBad != 0 {
		t.Fatalf("internal verify caught the attack (firstBad=%d err=%v) — test setup is wrong, "+
			"this must pass clean for the anchor check below to prove anything", firstBad, verr)
	}

	// Prove the fix: anchor verification is not fooled.
	result, err := s.VerifyChainAgainstAnchor(ctx, sink)
	if err != nil {
		t.Fatalf("VerifyChainAgainstAnchor: %v", err)
	}
	if result.OK() {
		t.Fatal("VerifyChainAgainstAnchor reported OK after a rewrite-and-recompute attack — " +
			"this is the exact gap #1706 exists to close")
	}
	if result.AnchorRoot == result.CurrentRoot {
		t.Errorf("AnchorRoot == CurrentRoot (%s) after tampering a row before the anchored checkpoint — want them to differ",
			abbrev(result.AnchorRoot))
	}
}

// Deleting the anchored row itself (not just editing it) is a variant of the
// same attack, and must also be caught: RowHashAt reports found=false, which
// VerifyChainAgainstAnchor surfaces as CurrentRoot="" — never equal to a
// real anchored hash.
func TestVerifyChainAgainstAnchor_DetectsDeletedCheckpoint(t *testing.T) {
	ctx := context.Background()
	s := auditTestStore(t)
	logN(t, s, 5)

	tail := rowIDAtOffset(t, s, 4)
	tailHash, found, err := s.RowHashAt(ctx, tail)
	if err != nil || !found {
		t.Fatalf("RowHashAt(tail): found=%v err=%v", found, err)
	}
	sink, err := NewFileSink(filepath.Join(t.TempDir(), "anchors.jsonl"))
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	if err := sink.PublishRoot(ctx, tail, tailHash); err != nil {
		t.Fatalf("PublishRoot: %v", err)
	}

	if _, err := s.pool.Exec(ctx, `DELETE FROM audit_logs WHERE id = $1`, tail); err != nil {
		t.Fatalf("delete anchored row: %v", err)
	}

	result, err := s.VerifyChainAgainstAnchor(ctx, sink)
	if err != nil {
		t.Fatalf("VerifyChainAgainstAnchor: %v", err)
	}
	if result.OK() {
		t.Fatal("VerifyChainAgainstAnchor reported OK after the anchored row was deleted")
	}
	if result.CurrentRoot != "" {
		t.Errorf("CurrentRoot = %q, want empty (row no longer exists)", result.CurrentRoot)
	}
}

// AnchorManager wired to the real store: proves the periodic loop actually
// advances a real Postgres-backed chain's checkpoint, not just the fakes in
// anchor_test.go.
func TestAnchorManager_PublishesAgainstRealStore(t *testing.T) {
	ctx := context.Background()
	s := auditTestStore(t)
	logN(t, s, 5)

	sink, err := NewFileSink(filepath.Join(t.TempDir(), "anchors.jsonl"))
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	m := NewAnchorManager(s, sink, AnchorOptions{})
	m.tick(ctx)

	tail := rowIDAtOffset(t, s, 4)
	cp, root, ok, err := sink.LastPublished(ctx)
	if err != nil || !ok {
		t.Fatalf("LastPublished: ok=%v err=%v", ok, err)
	}
	if cp != tail {
		t.Errorf("published checkpoint = %d, want the chain tail %d", cp, tail)
	}
	wantHash, found, err := s.RowHashAt(ctx, tail)
	if err != nil || !found {
		t.Fatalf("RowHashAt(tail): found=%v err=%v", found, err)
	}
	if root != wantHash {
		t.Errorf("published root = %s, want %s", abbrev(root), abbrev(wantHash))
	}
}
