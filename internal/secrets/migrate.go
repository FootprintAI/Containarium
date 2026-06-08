package secrets

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	corecrypto "github.com/footprintai/containarium/pkg/core/secrets"
)

// Phase 4.1 Phase-D — legacy → envelope migration (audit
// C-HIGH-6). Rewrites pre-KMS rows (wrapped_dek IS NULL)
// through the envelope path so the entire deployment runs
// on KMS-mediated decryption. Operator-driven: typically
// scheduled after the daemon is rolled with WithKMS
// enabled, and run repeatedly until VerifyEnvelopeCoverage
// reports 100%.
//
// Properties:
//
//   - Idempotent: rows already in envelope form
//     (wrapped_dek IS NOT NULL) are skipped. Re-running
//     the migration after a partial run resumes where it
//     left off — there's no checkpoint to track.
//   - Atomic per row: each row is rewritten in a single
//     UPDATE; failures don't leave the row half-migrated.
//   - Verifies before committing: the new envelope form
//     is decrypted in a separate operation and byte-
//     compared to the original plaintext. A mismatch
//     ROLLS BACK the row's UPDATE and is reported as an
//     error in the result — never quietly accepted.
//   - Bounded memory: pages through rows in batches so
//     large deployments don't OOM.

// MigrateOptions controls the migration's pacing.
type MigrateOptions struct {
	// BatchSize is the number of rows scanned per page.
	// Lower → smaller transactions, less memory; higher →
	// fewer round-trips. Default 100.
	BatchSize int

	// MaxRows caps the total rows processed in one call.
	// 0 = unlimited. Useful for chunking a huge backlog
	// across maintenance windows.
	MaxRows int

	// DryRun, when true, walks the rows and verifies each
	// would round-trip cleanly but does NOT issue any
	// UPDATE. Use to confirm the migration is safe before
	// committing.
	DryRun bool
}

// MigrateResult summarizes what the migration did.
type MigrateResult struct {
	Scanned     int // rows we looked at
	Migrated    int // rows successfully rewritten to envelope
	AlreadyDone int // rows already in envelope form (skipped)
	Failed      int // rows that errored mid-migration
	StartedAt   time.Time
	CompletedAt time.Time
	Errors      []MigrationError
}

// MigrationError names a row that failed and why.
type MigrationError struct {
	Username string
	Name     string
	Err      string
}

// ErrMigrateNoKMS is returned when MigrateLegacyToEnvelope
// is called on a Store without a KMSClient — there's
// nothing to migrate TO.
var ErrMigrateNoKMS = errors.New("secrets: cannot migrate to envelope without WithKMS")

// MigrateLegacyToEnvelope rewrites legacy rows in batches.
// See package-level doc for properties + safety contract.
func (s *Store) MigrateLegacyToEnvelope(ctx context.Context, opts MigrateOptions) (MigrateResult, error) {
	if s.kms == nil {
		return MigrateResult{}, ErrMigrateNoKMS
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 100
	}

	res := MigrateResult{StartedAt: time.Now()}
	defer func() { res.CompletedAt = time.Now() }()

	for {
		if opts.MaxRows > 0 && res.Scanned >= opts.MaxRows {
			break
		}
		batchLimit := opts.BatchSize
		if opts.MaxRows > 0 {
			remaining := opts.MaxRows - res.Scanned
			if remaining < batchLimit {
				batchLimit = remaining
			}
		}

		rows, err := s.fetchLegacyBatch(ctx, batchLimit)
		if err != nil {
			return res, fmt.Errorf("fetch legacy batch: %w", err)
		}
		if len(rows) == 0 {
			break // no more legacy rows
		}

		for _, r := range rows {
			res.Scanned++
			migrateErr := s.migrateOne(ctx, r, opts.DryRun)
			switch {
			case migrateErr == nil:
				res.Migrated++
			case errors.Is(migrateErr, errAlreadyEnvelope):
				res.AlreadyDone++
			default:
				res.Failed++
				res.Errors = append(res.Errors, MigrationError{
					Username: r.username, Name: r.name, Err: migrateErr.Error(),
				})
				log.Printf("[secrets-migrate] %s/%s failed: %v", r.username, r.name, migrateErr)
			}
		}
	}
	return res, nil
}

// VerifyEnvelopeCoverage reports how many legacy vs
// envelope rows are in the table. Used by operators to
// confirm 100% coverage before retiring the master key
// (Phase E).
type CoverageReport struct {
	Total    int
	Legacy   int
	Envelope int
}

// VerifyEnvelopeCoverage counts rows by encryption mode.
// A deployment that's never enabled KMS reports
// Envelope=0; a fully-migrated one reports Legacy=0.
func (s *Store) VerifyEnvelopeCoverage(ctx context.Context) (CoverageReport, error) {
	const q = `
		SELECT
			COUNT(*)                                    AS total,
			COUNT(*) FILTER (WHERE wrapped_dek IS NULL) AS legacy,
			COUNT(*) FILTER (WHERE wrapped_dek IS NOT NULL) AS envelope
		FROM secrets
	`
	var c CoverageReport
	if err := s.pool.QueryRow(ctx, q).Scan(&c.Total, &c.Legacy, &c.Envelope); err != nil {
		return c, fmt.Errorf("coverage query: %w", err)
	}
	return c, nil
}

// --- internal plumbing ---

type legacyRow struct {
	username string
	name     string
	nonce    []byte
	ct       []byte
}

func (s *Store) fetchLegacyBatch(ctx context.Context, limit int) ([]legacyRow, error) {
	const q = `
		SELECT username, name, nonce, ciphertext
		FROM secrets
		WHERE wrapped_dek IS NULL
		ORDER BY username, name
		LIMIT $1
	`
	rs, err := s.pool.Query(ctx, q, limit)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []legacyRow
	for rs.Next() {
		var r legacyRow
		if err := rs.Scan(&r.username, &r.name, &r.nonce, &r.ct); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rs.Err()
}

var errAlreadyEnvelope = errors.New("row is already in envelope form (concurrent migrator?)")

// migrateOne decrypts a legacy row via the master-key
// path, re-encrypts via the envelope path, verifies the
// round-trip, and writes back. All-or-nothing per row.
func (s *Store) migrateOne(ctx context.Context, r legacyRow, dryRun bool) error {
	// Decrypt via legacy path. AAD is bound to
	// (username, name); a tampered or unexpected row
	// fails GCM here.
	plaintext, err := s.cipher.Decrypt(r.username, r.name, r.nonce, r.ct)
	if err != nil {
		return fmt.Errorf("legacy decrypt: %w", err)
	}
	defer corecrypto.ZeroBytes(plaintext)

	// Re-encrypt via envelope path.
	newNonce, newCT, wrappedDEK, kekID, err := s.encryptForStorage(ctx, r.username, r.name, plaintext)
	if err != nil {
		return fmt.Errorf("envelope encrypt: %w", err)
	}

	// Verify: the new (nonce, ct, wrapped_dek, kek_id)
	// tuple must round-trip to the same plaintext we
	// just pulled. Without this check, a bug in the
	// envelope encrypt path would silently corrupt every
	// migrated secret.
	verifyPT, err := s.decryptFromStorage(ctx, r.username, r.name, newNonce, newCT, wrappedDEK, kekID)
	if err != nil {
		return fmt.Errorf("envelope round-trip verify failed: %w", err)
	}
	if !bytes.Equal(verifyPT, plaintext) {
		corecrypto.ZeroBytes(verifyPT)
		return errors.New("envelope round-trip produced different plaintext — refusing to commit")
	}
	corecrypto.ZeroBytes(verifyPT)

	if dryRun {
		return nil
	}

	// Atomic per-row UPDATE. The WHERE wrapped_dek IS
	// NULL guard means a concurrent migrator that
	// already promoted this row gets an "already
	// envelope" no-op (rows affected = 0).
	const q = `
		UPDATE secrets
		SET nonce = $1, ciphertext = $2, wrapped_dek = $3, kek_id = $4, updated_at = NOW()
		WHERE username = $5 AND name = $6 AND wrapped_dek IS NULL
	`
	tag, err := s.pool.Exec(ctx, q, newNonce, newCT, wrappedDEK, kekID, r.username, r.name)
	if err != nil {
		return fmt.Errorf("update row: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errAlreadyEnvelope
	}
	return nil
}
