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

func mustHash(t *testing.T, e *AuditEntry, prevHash string, version int16) string {
	t.Helper()
	h, err := computeRowHash(e, prevHash, version)
	if err != nil {
		t.Fatalf("computeRowHash: %v", err)
	}
	return h
}

func TestComputeRowHash_Deterministic(t *testing.T) {
	e := entry(123, "alice", "api_get", "duration=5s")
	h1 := mustHash(t, &e, "", CurrentHashVersion)
	h2 := mustHash(t, &e, "", CurrentHashVersion)
	if h1 != h2 {
		t.Fatalf("same entry produced different hashes: %s vs %s", h1, h2)
	}
	if len(h1) != 64 {
		t.Fatalf("SHA-256 hex should be 64 chars, got %d", len(h1))
	}
}

func TestComputeRowHash_DistinctFieldsProduceDistinctHashes(t *testing.T) {
	base := entry(123, "alice", "api_get", "duration=5s")
	hBase := mustHash(t, &base, "", CurrentHashVersion)

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
		{"actor", func(e *AuditEntry) { e.Actor = "human-alice" }},
		{"delegation_chain", func(e *AuditEntry) { e.DelegationChain = `{"sub":"human-alice"}` }},
		{"token_id", func(e *AuditEntry) { e.TokenID = "jti-123" }},
		{"org_id", func(e *AuditEntry) { e.OrgID = "org-1" }},
		{"run_id", func(e *AuditEntry) { e.RunID = "run-1" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := base
			tc.tweak(&e)
			if mustHash(t, &e, "", CurrentHashVersion) == hBase {
				t.Fatalf("changing %s did not perturb the hash", tc.name)
			}
		})
	}
}

func TestComputeRowHash_PrevHashIncluded(t *testing.T) {
	e := entry(123, "alice", "api_get", "duration=5s")
	hA := mustHash(t, &e, "prev-a", CurrentHashVersion)
	hB := mustHash(t, &e, "prev-b", CurrentHashVersion)
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
	if mustHash(t, &a, "", CurrentHashVersion) == mustHash(t, &b, "", CurrentHashVersion) {
		t.Fatal("length-prefixing must prevent boundary-shift collisions")
	}
}

// #1678 — hash-version-specific behavior.

// TestComputeRowHash_Version1IgnoresNewFields pins the backward-compat
// contract: HashVersion1's digest must be blind to the #1678 attribution
// fields, so a legitimately pre-migration row (whose stored hash never
// included them) keeps verifying no matter what those columns' zero values
// happen to be.
func TestComputeRowHash_Version1IgnoresNewFields(t *testing.T) {
	base := entry(1, "alice", "api_get", "d=1")
	withAttribution := base
	withAttribution.Actor = "human-alice"
	withAttribution.TokenID = "jti-123"
	withAttribution.OrgID = "org-1"
	withAttribution.RunID = "run-1"
	withAttribution.DelegationChain = `{"sub":"human-alice"}`

	hBase := mustHash(t, &base, "prev", HashVersion1)
	hWith := mustHash(t, &withAttribution, "prev", HashVersion1)
	if hBase != hWith {
		t.Fatalf("HashVersion1 must ignore attribution fields: base=%s with=%s", hBase, hWith)
	}
}

// TestComputeRowHash_Version2IncludesNewFields is the mirror check: under
// CurrentHashVersion, the same fields DO perturb the hash (already covered
// per-field by TestComputeRowHash_DistinctFieldsProduceDistinctHashes, this
// just pins the version number explicitly).
func TestComputeRowHash_Version2IncludesNewFields(t *testing.T) {
	base := entry(1, "alice", "api_get", "d=1")
	withActor := base
	withActor.Actor = "human-alice"

	if mustHash(t, &base, "prev", HashVersion2) == mustHash(t, &withActor, "prev", HashVersion2) {
		t.Fatal("HashVersion2 must include the actor field")
	}
}

func TestComputeRowHash_UnknownVersionErrors(t *testing.T) {
	e := entry(1, "alice", "api_get", "d=1")
	if _, err := computeRowHash(&e, "", 99); err == nil {
		t.Fatal("expected an error for an unrecognized hash_version")
	}
}

func TestVerifyChain_IntactChainReturnsZero(t *testing.T) {
	es := buildChain(t, CurrentHashVersion,
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
	es := buildChain(t, CurrentHashVersion,
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
	es := buildChain(t, CurrentHashVersion,
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
	es := buildChain(t, CurrentHashVersion, entry(1, "alice", "api_get", "d=1"))
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

// TestVerifyChain_MixedVersionChainVerifies is the #1678 migration-safety
// AC: a chain containing a pre-migration (HashVersion1) row followed by a
// post-migration (HashVersion2) row must verify as a whole. VerifyChain
// must apply each row's OWN stored hash_version — always using
// CurrentHashVersion here would recompute the v1 row's hash under the
// wrong (larger) field set and wrongly report it as tampered.
func TestVerifyChain_MixedVersionChainVerifies(t *testing.T) {
	pre := entry(1, "alice", "api_get", "d=1") // a real pre-migration row: attribution fields are all zero-value
	preHash := mustHash(t, &pre, HashEmpty, HashVersion1)

	post := entry(2, "alice", "api_post", "d=2")
	post.Actor = "human-alice"
	post.TokenID = "jti-123"
	postHash := mustHash(t, &post, preHash, HashVersion2)

	entries := []ChainEntry{
		{AuditEntry: pre, RowHash: preHash, PrevHash: HashEmpty, HashVersion: HashVersion1},
		{AuditEntry: post, RowHash: postHash, PrevHash: preHash, HashVersion: HashVersion2},
	}
	entries[0].ID = 1
	entries[1].ID = 2

	got, err := VerifyChain(entries, HashEmpty)
	if err != nil {
		t.Fatalf("mixed-version chain should verify intact: %v", err)
	}
	if got != 0 {
		t.Fatalf("firstBad=%d, want 0", got)
	}
}

// TestVerifyChain_RejectsUnknownHashVersion covers a row whose hash_version
// doesn't match any known scheme (corruption, or a future version this
// build doesn't understand yet) — must fail closed, not silently pass.
func TestVerifyChain_RejectsUnknownHashVersion(t *testing.T) {
	e := entry(1, "alice", "api_get", "d=1")
	entries := []ChainEntry{
		{AuditEntry: e, RowHash: "irrelevant", PrevHash: HashEmpty, HashVersion: 99},
	}
	entries[0].ID = 1

	got, err := VerifyChain(entries, HashEmpty)
	if err == nil {
		t.Fatal("unknown hash_version should produce an error, not pass silently")
	}
	if got != 1 {
		t.Fatalf("firstBad=%d, want 1", got)
	}
}

// buildChain stitches a slice of entries into a proper hash chain
// (each row's prev_hash = previous row's row_hash), all written at the
// given hash version. Test helper — mirrors what the Store does inside its
// transaction.
func buildChain(t *testing.T, version int16, es ...AuditEntry) []ChainEntry {
	t.Helper()
	out := make([]ChainEntry, len(es))
	prev := HashEmpty
	for i, e := range es {
		hash := mustHash(t, &e, prev, version)
		out[i] = ChainEntry{
			AuditEntry:  e,
			RowHash:     hash,
			PrevHash:    prev,
			HashVersion: version,
		}
		out[i].ID = int64(i + 1)
		prev = hash
	}
	return out
}
