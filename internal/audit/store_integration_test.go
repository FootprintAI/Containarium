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
	"fmt"
	"os"
	"sync"
	"testing"

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
