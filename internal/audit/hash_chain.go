package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// Phase 4.5 — audit-log tamper-evidence via hash chain.
//
// Each audit_logs row gets two new columns:
//   - row_hash:  SHA-256 of (this row's fields || prev_hash).
//   - prev_hash: the previous row's row_hash (empty for the
//                first row in the chain).
//
// A row tampered with after insert won't match its own row_hash,
// and every row after it has the wrong prev_hash — so a single
// edit anywhere in the table is detectable by walking the chain.
//
// The chain doesn't prove the log is COMPLETE (an attacker could
// delete the suffix of rows and leave the head intact), but it
// proves nothing has been MODIFIED or INSERTED — which is the
// threat audit C-MED-5+ flags. Append-only forensics (push the
// chain root to an external sink periodically) detects deletions
// on top of this; that's tracked separately.

const (
	// HashEmpty is the value used as the previous hash for the
	// very first row in the chain. Anything constant would work;
	// "" matches Postgres's TEXT default and reads obvious in a
	// row dump.
	HashEmpty = ""
)

// computeRowHash returns the SHA-256 hex of the canonical
// serialization of an AuditEntry's user-visible fields followed
// by the previous row's hash. The serialization is length-
// prefixed so a field containing the separator can't collide
// with a different field shape.
//
// The ID is NOT included (it's assigned by BIGSERIAL at insert
// time and an attacker could replay an old row at a different ID
// — including it would create false-positives on legitimate
// renumbering during db restore). The timestamp IS included with
// nanosecond precision; clock-skew within a single daemon is
// bounded.
func computeRowHash(e *AuditEntry, prevHash string) string {
	h := sha256.New()
	// Length-prefixed field serialization. lenN is decimal,
	// terminated by ':', then the raw bytes. Trivial to parse,
	// impossible to ambiguously rearrange.
	writeField(h, strconv.FormatInt(e.Timestamp.UnixNano(), 10))
	writeField(h, e.Username)
	writeField(h, e.Action)
	writeField(h, e.ResourceType)
	writeField(h, e.ResourceID)
	writeField(h, e.Detail)
	writeField(h, e.SourceIP)
	writeField(h, strconv.Itoa(e.StatusCode))
	writeField(h, prevHash)
	return hex.EncodeToString(h.Sum(nil))
}

func writeField(h interface{ Write([]byte) (int, error) }, s string) {
	prefix := strconv.Itoa(len(s)) + ":"
	_, _ = h.Write([]byte(prefix))
	_, _ = h.Write([]byte(s))
}

// VerifyChain replays the hash chain over `entries` (which must
// be in ascending insert order — see VerifySinceID for the
// query side). Returns the ID of the first row whose stored
// row_hash doesn't match its computed value, or 0 if the chain
// is intact. Returns -1 on internal error.
//
// `expectedRoot` is the prev_hash the first row should reference
// (empty string for chain start; a prior tail's hash if you're
// verifying a tail segment).
func VerifyChain(entries []ChainEntry, expectedRoot string) (firstBad int64, err error) {
	prev := expectedRoot
	for i := range entries {
		e := &entries[i]
		if e.PrevHash != prev {
			return e.ID, fmt.Errorf("row %d prev_hash mismatch: stored=%q expected=%q (chain broken at or before this row)",
				e.ID, e.PrevHash, prev)
		}
		want := computeRowHash(&e.AuditEntry, e.PrevHash)
		if e.RowHash != want {
			return e.ID, fmt.Errorf("row %d row_hash mismatch: stored=%q computed=%q (this row was modified after insert)",
				e.ID, abbrev(e.RowHash), abbrev(want))
		}
		prev = e.RowHash
	}
	return 0, nil
}

// ChainEntry augments AuditEntry with the two hash-chain columns,
// for verification consumers. The base Log/Query path returns
// plain AuditEntry — most callers don't care about chain state.
type ChainEntry struct {
	AuditEntry
	RowHash  string
	PrevHash string
}

func abbrev(h string) string {
	if len(h) <= 16 {
		return h
	}
	return strings.Join([]string{h[:8], h[len(h)-8:]}, "..")
}
