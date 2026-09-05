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
// threat audit C-MED-5+ flags. It also can't, by itself, catch a
// privileged attacker who rewrites a row AND correctly recomputes
// every hash after it — that produces a chain that IS internally
// consistent. anchor.go closes that gap (#1706): the chain's tip is
// periodically published to an external sink Postgres can't rewrite,
// and VerifyChainAgainstAnchor checks against it.

const (
	// HashEmpty is the value used as the previous hash for the
	// very first row in the chain. Anything constant would work;
	// "" matches Postgres's TEXT default and reads obvious in a
	// row dump.
	HashEmpty = ""
)

// Hash-chain schema versions (#1678). A row's stored hash_version says
// which field set computeRowHash used to build its digest — VerifyChain
// looks this up PER ROW rather than always using CurrentHashVersion, so a
// chain spanning the #1678 migration (some rows written before it, some
// after) still verifies as a whole. Recomputing an old row's hash under a
// newer field set would never match what was actually stored — that would
// corrupt the tamper-evidence the chain exists for, exactly the
// "schedule risk" #1678 called out before any of this was written.
const (
	// HashVersion1 is the original Phase 4.5 eight-field digest. Every row
	// written before #1678 is backfilled to this version by initSchema's
	// `ADD COLUMN hash_version SMALLINT NOT NULL DEFAULT 1` — Postgres
	// applies a column default to existing rows in place, so no backfill
	// migration script is needed.
	HashVersion1 int16 = 1

	// HashVersion2 adds actor, delegation_chain, token_id, org_id and
	// run_id to the digest (#1678: audit attribution).
	HashVersion2 int16 = 2

	// CurrentHashVersion is the version every newly-written row uses.
	CurrentHashVersion = HashVersion2
)

// computeRowHash returns the SHA-256 hex of the canonical serialization of
// an AuditEntry's user-visible fields followed by the previous row's hash.
// The serialization is length-prefixed so a field containing the separator
// can't collide with a different field shape.
//
// The ID is NOT included (it's assigned by BIGSERIAL at insert time and an
// attacker could replay an old row at a different ID — including it would
// create false-positives on legitimate renumbering during db restore). The
// timestamp IS included with nanosecond precision; clock-skew within a
// single daemon is bounded.
//
// version selects which field set is hashed (see the HashVersion*
// constants) — a stored row's own hash_version, not always
// CurrentHashVersion, so VerifyChain can replay a mixed-version chain
// correctly. Returns an error for an unrecognized version rather than
// silently hashing under the wrong field set, which would make every row
// after a corruption look intact.
func computeRowHash(e *AuditEntry, prevHash string, version int16) (string, error) {
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
	switch version {
	case HashVersion1:
		// Original eight-field digest; nothing further.
	case HashVersion2:
		writeField(h, e.Actor)
		writeField(h, e.DelegationChain)
		writeField(h, e.TokenID)
		writeField(h, e.OrgID)
		writeField(h, e.RunID)
	default:
		return "", fmt.Errorf("audit: unrecognized hash_version %d", version)
	}
	writeField(h, prevHash)
	return hex.EncodeToString(h.Sum(nil)), nil
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
		want, herr := computeRowHash(&e.AuditEntry, e.PrevHash, e.HashVersion)
		if herr != nil {
			return e.ID, fmt.Errorf("row %d: %w", e.ID, herr)
		}
		if e.RowHash != want {
			return e.ID, fmt.Errorf("row %d row_hash mismatch: stored=%q computed=%q (this row was modified after insert)",
				e.ID, abbrev(e.RowHash), abbrev(want))
		}
		prev = e.RowHash
	}
	return 0, nil
}

// ChainEntry augments AuditEntry with the hash-chain columns, for
// verification consumers. The base Log/Query path returns plain
// AuditEntry — most callers don't care about chain state.
type ChainEntry struct {
	AuditEntry
	RowHash     string
	PrevHash    string
	HashVersion int16
}

func abbrev(h string) string {
	if len(h) <= 16 {
		return h
	}
	return strings.Join([]string{h[:8], h[len(h)-8:]}, "..")
}
