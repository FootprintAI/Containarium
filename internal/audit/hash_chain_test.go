package audit

import (
	"strings"
	"testing"
	"time"
)

// Phase 4.5 — hash-chain verification logic. These tests cover
// the pure-Go side (computeRowHash + VerifyChain). The DB-bound
// integration is exercised by the integration suite (requires a
// live Postgres).

func entry(ts int64, user, action, detail string) AuditEntry {
	return AuditEntry{
		Timestamp:    time.Unix(0, ts),
		Username:     user,
		Action:       action,
		ResourceType: "api",
		ResourceID:   "GET /v1/x",
		Detail:       detail,
		SourceIP:     "10.0.0.1",
		StatusCode:   200,
	}
}

func TestComputeRowHash_Deterministic(t *testing.T) {
	e := entry(123, "alice", "api_get", "duration=5s")
	h1 := computeRowHash(&e, "")
	h2 := computeRowHash(&e, "")
	if h1 != h2 {
		t.Fatalf("same entry produced different hashes: %s vs %s", h1, h2)
	}
	if len(h1) != 64 {
		t.Fatalf("SHA-256 hex should be 64 chars, got %d", len(h1))
	}
}

func TestComputeRowHash_DistinctFieldsProduceDistinctHashes(t *testing.T) {
	base := entry(123, "alice", "api_get", "duration=5s")
	hBase := computeRowHash(&base, "")

	// Each field change must perturb the hash.
	cases := []struct {
		name  string
		tweak func(e *AuditEntry)
	}{
		{"username", func(e *AuditEntry) { e.Username = "bob" }},
		{"action", func(e *AuditEntry) { e.Action = "api_post" }},
		{"detail", func(e *AuditEntry) { e.Detail = "duration=6s" }},
		{"status_code", func(e *AuditEntry) { e.StatusCode = 500 }},
		{"resource_id", func(e *AuditEntry) { e.ResourceID = "GET /v1/y" }},
		{"source_ip", func(e *AuditEntry) { e.SourceIP = "10.0.0.2" }},
		{"timestamp", func(e *AuditEntry) { e.Timestamp = time.Unix(0, 124) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := base
			tc.tweak(&e)
			if computeRowHash(&e, "") == hBase {
				t.Fatalf("changing %s did not perturb the hash", tc.name)
			}
		})
	}
}

func TestComputeRowHash_PrevHashIncluded(t *testing.T) {
	e := entry(123, "alice", "api_get", "duration=5s")
	hA := computeRowHash(&e, "prev-a")
	hB := computeRowHash(&e, "prev-b")
	if hA == hB {
		t.Fatal("different prev_hash must produce different row_hash")
	}
}

func TestComputeRowHash_LengthPrefixingPreventsCollision(t *testing.T) {
	// Two entries where one field's value bleeds into the next
	// would collide if we just concatenated. Length-prefixing
	// makes them distinct.
	a := entry(1, "alice", "api_get", "x")
	a.ResourceID = "GET /foo"
	b := entry(1, "alice", "api_get", "x")
	b.ResourceID = "GET /foox"
	// Adjust so the concat-without-length-prefix would be equal.
	a.SourceIP = "x10.0.0.1"
	b.SourceIP = "10.0.0.1"
	if computeRowHash(&a, "") == computeRowHash(&b, "") {
		t.Fatal("length-prefixing must prevent boundary-shift collisions")
	}
}

func TestVerifyChain_IntactChainReturnsZero(t *testing.T) {
	es := buildChain(t,
		entry(1, "alice", "api_get", "d=1"),
		entry(2, "alice", "api_post", "d=2"),
		entry(3, "bob", "api_delete", "d=3"),
	)
	got, err := VerifyChain(es, "")
	if err != nil {
		t.Fatalf("intact chain: %v", err)
	}
	if got != 0 {
		t.Fatalf("got firstBad=%d, want 0 on intact chain", got)
	}
}

func TestVerifyChain_TamperedFieldDetected(t *testing.T) {
	es := buildChain(t,
		entry(1, "alice", "api_get", "d=1"),
		entry(2, "alice", "api_post", "d=2"),
		entry(3, "bob", "api_delete", "d=3"),
	)
	// Tamper: change row 2's detail without updating its hash.
	es[1].Detail = "tampered=yes"

	got, err := VerifyChain(es, "")
	if err == nil {
		t.Fatal("tampered row should produce an error")
	}
	if got != es[1].ID {
		t.Fatalf("firstBad=%d, want %d", got, es[1].ID)
	}
	if !strings.Contains(err.Error(), "row_hash mismatch") {
		t.Fatalf("error should name the mismatch: %v", err)
	}
}

func TestVerifyChain_TamperedPrevHashDetected(t *testing.T) {
	es := buildChain(t,
		entry(1, "alice", "api_get", "d=1"),
		entry(2, "alice", "api_post", "d=2"),
		entry(3, "bob", "api_delete", "d=3"),
	)
	// Tamper: substitute row 2's prev_hash with the empty value
	// (as if row 1 had been deleted but row 2's hash recomputed).
	es[1].PrevHash = ""

	got, err := VerifyChain(es, "")
	if err == nil {
		t.Fatal("prev_hash mismatch should produce an error")
	}
	if got != es[1].ID {
		t.Fatalf("firstBad=%d, want %d", got, es[1].ID)
	}
	if !strings.Contains(err.Error(), "prev_hash mismatch") {
		t.Fatalf("error should name the prev_hash mismatch: %v", err)
	}
}

func TestVerifyChain_WrongExpectedRootDetected(t *testing.T) {
	es := buildChain(t,
		entry(1, "alice", "api_get", "d=1"),
	)
	// Caller claims the chain started somewhere else.
	got, err := VerifyChain(es, "some-other-root-hash")
	if err == nil {
		t.Fatal("wrong root should be detected")
	}
	if got != es[0].ID {
		t.Fatalf("firstBad=%d, want %d", got, es[0].ID)
	}
}

func TestVerifyChain_EmptyEntriesReturnsZero(t *testing.T) {
	got, err := VerifyChain(nil, "")
	if err != nil {
		t.Fatalf("empty chain: %v", err)
	}
	if got != 0 {
		t.Fatalf("empty chain firstBad=%d, want 0", got)
	}
}

// buildChain stitches a slice of entries into a proper hash chain
// (each row's prev_hash = previous row's row_hash). Test helper —
// mirrors what the Store does inside its transaction.
func buildChain(t *testing.T, es ...AuditEntry) []ChainEntry {
	t.Helper()
	out := make([]ChainEntry, len(es))
	prev := HashEmpty
	for i, e := range es {
		hash := computeRowHash(&e, prev)
		out[i] = ChainEntry{
			AuditEntry: e,
			RowHash:    hash,
			PrevHash:   prev,
		}
		out[i].ID = int64(i + 1)
		prev = hash
	}
	return out
}
