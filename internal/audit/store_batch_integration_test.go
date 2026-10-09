//go:build integration

package audit

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// #2415 — Store.LogBatch and the dedupe_key column, against a real Postgres.

func batchEntries(n, offset int) []BatchEntry {
	out := make([]BatchEntry, n)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("sess-%d", offset+i)
		out[i] = BatchEntry{
			Entry: AuditEntry{
				Timestamp:    time.Unix(1_700_000_000+int64(offset+i), 0),
				Username:     "alice",
				Action:       "ssh_session_open",
				ResourceType: "ssh_session",
				ResourceID:   id,
				SourceIP:     "203.0.113.7",
			},
			DedupeKey: "sshsession:" + id + ":open",
		}
	}
	return out
}

func mustVerify(t *testing.T, s *Store) {
	t.Helper()
	firstBad, err := s.VerifyChainSinceID(context.Background(), 0, 1000)
	if err != nil || firstBad != 0 {
		t.Fatalf("chain does not verify: firstBad=%d err=%v", firstBad, err)
	}
}

// rowCount counts rows rather than reading MaxRowID: ON CONFLICT DO NOTHING
// consumes a BIGSERIAL value per skipped duplicate, so ids have gaps (as they
// already do after any rolled-back insert). The chain links by prev_hash, not
// id contiguity, so gaps are harmless; the row count is what matters.
func rowCount(t *testing.T, s *Store) int64 {
	t.Helper()
	var n int64
	if err := s.pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_logs`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestLogBatch_FreshEntriesInsertAndVerify(t *testing.T) {
	s := auditTestStore(t)
	outs, err := s.LogBatch(context.Background(), batchEntries(10, 0))
	if err != nil {
		t.Fatal(err)
	}
	for i, o := range outs {
		if o != BatchInserted {
			t.Fatalf("outcome[%d] = %v, want BatchInserted", i, o)
		}
	}
	if got := rowCount(t, s); got != 10 {
		t.Fatalf("rows = %d, want 10", got)
	}
	mustVerify(t, s)
}

func TestLogBatch_ReplayIsNoOp(t *testing.T) {
	s := auditTestStore(t)
	b := batchEntries(8, 0)
	if _, err := s.LogBatch(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	outs, err := s.LogBatch(context.Background(), batchEntries(8, 0))
	if err != nil {
		t.Fatal(err)
	}
	for i, o := range outs {
		if o != BatchDuplicate {
			t.Fatalf("replay outcome[%d] = %v, want BatchDuplicate", i, o)
		}
	}
	if got := rowCount(t, s); got != 8 {
		t.Fatalf("rows after replay = %d, want 8 (unchanged)", got)
	}
	mustVerify(t, s)
}

// A duplicate must be skipped before it can become anyone's predecessor: the
// row after a duplicate chains to the last INSERTED row.
func TestLogBatch_MixedBatchKeepsChainLinear(t *testing.T) {
	s := auditTestStore(t)
	if _, err := s.LogBatch(context.Background(), batchEntries(3, 0)); err != nil { // sess-0..2
		t.Fatal(err)
	}
	// order: new(100), dup(1), dup(2), new(101)
	n := batchEntries(2, 100) // sess-100, sess-101
	d := batchEntries(2, 1)   // sess-1, sess-2 (already stored)
	mixed := []BatchEntry{n[0], d[0], d[1], n[1]}
	outs, err := s.LogBatch(context.Background(), mixed)
	if err != nil {
		t.Fatal(err)
	}
	want := []BatchOutcome{BatchInserted, BatchDuplicate, BatchDuplicate, BatchInserted}
	for i := range want {
		if outs[i] != want[i] {
			t.Fatalf("outcome[%d] = %v, want %v (all: %v)", i, outs[i], want[i], outs)
		}
	}
	if got := rowCount(t, s); got != 5 {
		t.Fatalf("rows = %d, want 5", got)
	}
	mustVerify(t, s)
}

func TestLogBatch_DuplicateWithinSameBatch(t *testing.T) {
	s := auditTestStore(t)
	b := batchEntries(1, 0)
	b = append(b, b[0])
	outs, err := s.LogBatch(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	if outs[0] != BatchInserted || outs[1] != BatchDuplicate {
		t.Fatalf("outcomes = %v, want [Inserted Duplicate]", outs)
	}
	mustVerify(t, s)
}

// Any storage error must roll the whole batch back.
func TestLogBatch_FailureCommitsNothing(t *testing.T) {
	s := auditTestStore(t)
	b := batchEntries(5, 0)
	// A NUL byte is rejected by Postgres TEXT, failing the 4th insert.
	b[3].Entry.Detail = "bad\x00detail"
	if _, err := s.LogBatch(context.Background(), b); err == nil {
		t.Fatal("expected an error from the poisoned entry")
	}
	if got := rowCount(t, s); got != 0 {
		t.Fatalf("rows = %d, want 0 (batch must be atomic)", got)
	}
	// And the keys must be reusable afterwards.
	if _, err := s.LogBatch(context.Background(), batchEntries(5, 0)); err != nil {
		t.Fatalf("clean retry after rollback: %v", err)
	}
	mustVerify(t, s)
}

func TestLogBatch_EmptyBatch(t *testing.T) {
	s := auditTestStore(t)
	outs, err := s.LogBatch(context.Background(), nil)
	if err != nil || len(outs) != 0 {
		t.Fatalf("empty batch: outs=%v err=%v", outs, err)
	}
}

func TestLogBatch_ConcurrentWithLogDoesNotFork(t *testing.T) {
	s := auditTestStore(t)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for w := 0; w < 4; w++ {
		wg.Add(2)
		go func(w int) {
			defer wg.Done()
			<-start
			for i := 0; i < 5; i++ {
				_, _ = s.LogBatch(context.Background(), batchEntries(5, w*1000+i*10))
			}
		}(w)
		go func(w int) {
			defer wg.Done()
			<-start
			for i := 0; i < 10; i++ {
				_ = s.Log(context.Background(), &AuditEntry{Username: "u", Action: "x", ResourceID: fmt.Sprintf("%d-%d", w, i)})
			}
		}(w)
	}
	close(start)
	wg.Wait()
	mustVerify(t, s)
}

func TestDedupeKey_LogWritesNullAndIdenticalRowsDoNotCollide(t *testing.T) {
	s := auditTestStore(t)
	e := AuditEntry{Username: "a", Action: "x", ResourceID: "same", Timestamp: time.Unix(1_700_000_000, 0)}
	for i := 0; i < 3; i++ {
		c := e
		if err := s.Log(context.Background(), &c); err != nil {
			t.Fatalf("plain Log #%d: %v", i, err)
		}
	}
	var nonNull int
	if err := s.pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_logs WHERE dedupe_key IS NOT NULL`).Scan(&nonNull); err != nil {
		t.Fatal(err)
	}
	if nonNull != 0 {
		t.Fatalf("Log wrote %d non-NULL dedupe_key rows, want 0", nonNull)
	}
	mustVerify(t, s)
}

// Upgrading a table that already has chained rows must leave them verifiable.
func TestDedupeKey_MigrationOnExistingRows(t *testing.T) {
	s := auditTestStore(t)
	logN(t, s, 5)
	if _, err := s.pool.Exec(context.Background(), `DROP INDEX IF EXISTS idx_audit_logs_dedupe_key; ALTER TABLE audit_logs DROP COLUMN dedupe_key`); err != nil {
		t.Fatal(err)
	}
	if err := s.initSchema(context.Background()); err != nil {
		t.Fatalf("re-running initSchema on a populated table: %v", err)
	}
	if err := s.initSchema(context.Background()); err != nil {
		t.Fatalf("initSchema must be idempotent: %v", err)
	}
	mustVerify(t, s)
	if _, err := s.LogBatch(context.Background(), batchEntries(2, 0)); err != nil {
		t.Fatal(err)
	}
	mustVerify(t, s)
}
