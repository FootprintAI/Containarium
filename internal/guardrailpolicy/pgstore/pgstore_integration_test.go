//go:build integration

// Postgres coverage for the guardrail policy store (#2368). The in-memory
// store runs the same contract in the unit suite; this file adds what only a
// database can show: the revision survives a restart, concurrent Sets get
// distinct revisions, and a read error, an undecodable stored policy or a
// missing singleton row is never "not configured".
//
//	CONTAINARIUM_TEST_DSN=postgres://... go test -tags=integration ./internal/guardrailpolicy/pgstore/
package pgstore

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"

	"github.com/footprintai/containarium/internal/guardrailpolicy"
	"github.com/footprintai/containarium/internal/guardrailpolicy/storetest"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func policyPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("CONTAINARIUM_TEST_DSN")
	if dsn == "" {
		t.Fatal("CONTAINARIUM_TEST_DSN is unset. Failing rather than skipping, so a lane that " +
			"loses its database reports it instead of going quietly green.")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(context.Background(), `DROP TABLE IF EXISTS guardrail_policy`); err != nil {
		t.Fatalf("reset: %v", err)
	}
	return pool
}

func pgStore(t *testing.T, pool *pgxpool.Pool) *Store {
	t.Helper()
	s, err := New(context.Background(), pool)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestGuardrailPolicyPGStore_Contract(t *testing.T) {
	storetest.RunStoreContract(t, func(t *testing.T) guardrailpolicy.Store { return pgStore(t, policyPool(t)) })
}

// TestGuardrailPolicyPGStore_RevisionSurvivesRestart: a second store over the same
// database (a restarted daemon re-running the schema bootstrap) reads the
// stored policy and continues the revision sequence rather than restarting it.
func TestGuardrailPolicyPGStore_RevisionSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	pool := policyPool(t)
	first := pgStore(t, pool)
	for i := 0; i < 2; i++ {
		if _, err := first.Set(ctx, storetest.Policy(int32(i)), []*pb.GuardrailTrustedSigner{storetest.Signer(t, 3, "k")}, "admin-a"); err != nil {
			t.Fatalf("Set: %v", err)
		}
	}
	before, err := first.Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	restarted := pgStore(t, pool)
	after, err := restarted.Get(ctx)
	if err != nil {
		t.Fatalf("Get after restart: %v", err)
	}
	if !proto.Equal(before, after) {
		t.Fatalf("after restart = %v, want %v", after, before)
	}
	res, err := restarted.Set(ctx, storetest.Policy(5), nil, "admin-b")
	if err != nil {
		t.Fatalf("Set after restart: %v", err)
	}
	if res.Current.GetRevision() != 3 || res.Previous.GetRevision() != 2 {
		t.Fatalf("after restart Set = rev %d (prev %d), want 3 (prev 2)", res.Current.GetRevision(), res.Previous.GetRevision())
	}
}

// TestGuardrailPolicyPGStore_ConcurrentSetsGetDistinctRevisions: N racing Sets, the
// first of them against an empty table, produce revisions 1..N with no
// duplicate, and each one's Previous is the revision right below it.
func TestGuardrailPolicyPGStore_ConcurrentSetsGetDistinctRevisions(t *testing.T) {
	ctx := context.Background()
	s := pgStore(t, policyPool(t))
	const n = 8
	var wg sync.WaitGroup
	results := make([]*guardrailpolicy.SetResult, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = s.Set(ctx, storetest.Policy(int32(i)), nil, "admin-a")
		}(i)
	}
	wg.Wait()
	seen := map[int64]bool{}
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("Set %d: %v", i, errs[i])
		}
		rev := results[i].Current.GetRevision()
		if seen[rev] {
			t.Fatalf("revision %d assigned twice", rev)
		}
		seen[rev] = true
		if got := results[i].Previous.GetRevision(); got != rev-1 {
			t.Fatalf("Set at revision %d reported previous %d, want %d", rev, got, rev-1)
		}
	}
	for rev := int64(1); rev <= n; rev++ {
		if !seen[rev] {
			t.Fatalf("revisions = %v, want exactly 1..%d", seen, n)
		}
	}
}

// TestGuardrailPolicyPGStore_ReadErrorIsNotNotConfigured: with the database gone, Get
// fails with an error that is NOT guardrailpolicy.ErrNotConfigured, so no consumer can read
// an outage as "no policy".
func TestGuardrailPolicyPGStore_ReadErrorIsNotNotConfigured(t *testing.T) {
	ctx := context.Background()
	dsn := os.Getenv("CONTAINARIUM_TEST_DSN")
	pool := policyPool(t)
	s := pgStore(t, pool)
	if _, err := s.Get(ctx); !errors.Is(err, guardrailpolicy.ErrNotConfigured) {
		t.Fatalf("Get on a fresh table = %v, want guardrailpolicy.ErrNotConfigured", err)
	}
	// A separate pool so closing it does not break the Cleanup of the first.
	gone, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	broken := &Store{pool: gone}
	gone.Close()
	_, err = broken.Get(ctx)
	if err == nil || errors.Is(err, guardrailpolicy.ErrNotConfigured) {
		t.Fatalf("Get with the database unreachable = %v, want a read error distinct from guardrailpolicy.ErrNotConfigured", err)
	}
}

// requireDamagedError fails unless err is a real error, distinct from
// guardrailpolicy.ErrNotConfigured: a damaged table must never read as "no policy".
func requireDamagedError(t *testing.T, op string, err error) {
	t.Helper()
	if err == nil || errors.Is(err, guardrailpolicy.ErrNotConfigured) {
		t.Fatalf("%s on a damaged table = %v, want an error distinct from guardrailpolicy.ErrNotConfigured", op, err)
	}
}

// TestGuardrailPolicyPGStore_CorruptStoredPolicyIsAnError: a policy column
// that does not decode fails both Get and Set (Set must not overwrite what
// it could not read), and the row is left as it was.
func TestGuardrailPolicyPGStore_CorruptStoredPolicyIsAnError(t *testing.T) {
	ctx := context.Background()
	pool := policyPool(t)
	s := pgStore(t, pool)
	if _, err := s.Set(ctx, storetest.Policy(1), nil, "admin-a"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	// Field 1, length 5, one byte of payload: a truncated message.
	corrupt := []byte{0x0a, 0x05, 0x01}
	if _, err := pool.Exec(ctx, `UPDATE guardrail_policy SET policy = $1 WHERE id = 1`, corrupt); err != nil {
		t.Fatalf("corrupt the row: %v", err)
	}
	_, err := s.Get(ctx)
	requireDamagedError(t, "Get", err)
	_, err = s.Set(ctx, storetest.Policy(2), nil, "admin-b")
	requireDamagedError(t, "Set", err)

	var (
		revision int64
		raw      []byte
	)
	if err := pool.QueryRow(ctx, `SELECT revision, policy FROM guardrail_policy WHERE id = 1`).Scan(&revision, &raw); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if revision != 1 || string(raw) != string(corrupt) {
		t.Fatalf("after the refused Set: revision %d, policy %x; want revision 1 and the bytes untouched", revision, raw)
	}
}

// TestGuardrailPolicyPGStore_MissingRowIsAnError: the bootstrap seeds the
// singleton row, so a missing row is a damaged table. Get and Set both fail;
// neither treats it as "not configured", and Set does not recreate the row.
func TestGuardrailPolicyPGStore_MissingRowIsAnError(t *testing.T) {
	ctx := context.Background()
	pool := policyPool(t)
	s := pgStore(t, pool)
	if _, err := pool.Exec(ctx, `DELETE FROM guardrail_policy WHERE id = 1`); err != nil {
		t.Fatalf("delete the row: %v", err)
	}
	_, err := s.Get(ctx)
	requireDamagedError(t, "Get", err)
	_, err = s.Set(ctx, storetest.Policy(1), nil, "admin-a")
	requireDamagedError(t, "Set", err)

	var rows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM guardrail_policy`).Scan(&rows); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != 0 {
		t.Fatalf("rows after the refused Set = %d, want 0", rows)
	}
}
