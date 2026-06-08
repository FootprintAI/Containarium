package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	internalsecrets "github.com/footprintai/containarium/internal/secrets"
	corecrypto "github.com/footprintai/containarium/pkg/core/secrets"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"
)

// Phase 4.1 Phase-D — operator-facing CLI for the
// legacy → envelope migration (audit C-HIGH-6). The
// daemon's Set/Get already dispatches per-row (Phase B),
// so this tool is purely a backfill — it walks existing
// legacy rows and rewrites them through the envelope
// path. Idempotent and resumable; safe to interrupt and
// re-run.
//
// Direct DB access by design: the daemon doesn't need an
// RPC for this. Operators with DB credentials run the
// migration from a maintenance host alongside the
// existing backup / restore tooling. Once 100% coverage
// is reported, the master-key retirement (Phase E) is a
// separate operator decision.

var (
	migrateBatchSize int
	migrateMaxRows   int
	migrateDryRun    bool
	migrateMasterKey string
)

var secretsMigrateCmd = &cobra.Command{
	Use:   "migrate-to-envelope",
	Short: "Backfill legacy secrets rows through the envelope encryption path (Phase 4.1)",
	Long: `Rewrite pre-Phase-4.1 secrets rows so they use the envelope
encryption path. The daemon already writes new secrets through the
envelope path when KMS is configured; this tool migrates the rows
that were written before KMS was enabled.

Properties:
  • Idempotent — already-envelope rows are skipped.
  • Resumable — interrupting and re-running picks up where it
    left off.
  • Per-row atomic — failures don't leave a row half-migrated.
  • Verifies before committing — the new envelope ciphertext must
    round-trip to the same plaintext as the legacy row, or the
    UPDATE is rolled back and the row is reported as a failure.

Run this with the same Postgres credentials and master key the
daemon uses, against the same database. The Phase-A InProcKMS
backend (default) wraps DEKs under the master key — cryptographic-
ally equivalent to legacy in terms of protection, but produces
the envelope-shaped row that future KMS backends (Phase C+) can
re-wrap into.`,
	Example: `  # Dry run — verifies every legacy row would migrate cleanly,
  # without writing.
  containarium secrets migrate-to-envelope --dry-run

  # Real run; default batch size 100.
  containarium secrets migrate-to-envelope

  # Chunked across maintenance windows (cap each run to 10k rows).
  containarium secrets migrate-to-envelope --max-rows 10000`,
	RunE: runSecretsMigrate,
}

var secretsCoverageCmd = &cobra.Command{
	Use:   "envelope-coverage",
	Short: "Report how many secrets rows are envelope vs legacy (Phase 4.1)",
	Long: `Counts the rows in the secrets table by encryption mode. Use to
confirm migration progress and to decide when it's safe to retire
the master key (Phase E — operator-driven).

A deployment that's never enabled KMS reports Envelope=0; a
fully-migrated one reports Legacy=0.`,
	RunE: runSecretsCoverage,
}

func init() {
	secretsCmd.AddCommand(secretsMigrateCmd)
	secretsCmd.AddCommand(secretsCoverageCmd)

	secretsMigrateCmd.Flags().IntVar(&migrateBatchSize, "batch-size", 100, "Rows scanned per Postgres query")
	secretsMigrateCmd.Flags().IntVar(&migrateMaxRows, "max-rows", 0, "Cap on total rows processed (0 = no cap)")
	secretsMigrateCmd.Flags().BoolVar(&migrateDryRun, "dry-run", false, "Walk and verify rows without writing")
	secretsMigrateCmd.Flags().StringVar(&migrateMasterKey, "master-key-file", "/etc/containarium/secrets.key", "Path to the daemon's master key file (mode 0400)")
}

func runSecretsMigrate(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	store, cleanup, err := openSecretsStoreWithKMS(ctx, migrateMasterKey)
	if err != nil {
		return err
	}
	defer cleanup()

	res, err := store.MigrateLegacyToEnvelope(ctx, internalsecrets.MigrateOptions{
		BatchSize: migrateBatchSize,
		MaxRows:   migrateMaxRows,
		DryRun:    migrateDryRun,
	})
	if err != nil {
		return err
	}

	mode := "MIGRATE"
	if migrateDryRun {
		mode = "DRY-RUN"
	}
	fmt.Printf("\n%s — completed in %s\n", mode, res.CompletedAt.Sub(res.StartedAt).Round(time.Millisecond))
	fmt.Printf("  scanned:       %d\n", res.Scanned)
	fmt.Printf("  migrated:      %d\n", res.Migrated)
	fmt.Printf("  already done:  %d\n", res.AlreadyDone)
	fmt.Printf("  failed:        %d\n", res.Failed)
	if len(res.Errors) > 0 {
		fmt.Fprintf(os.Stderr, "\nFailed rows:\n")
		for _, e := range res.Errors {
			fmt.Fprintf(os.Stderr, "  %s/%s — %s\n", e.Username, e.Name, e.Err)
		}
		// Non-zero exit so wrapper scripts notice.
		return fmt.Errorf("%d rows failed migration", res.Failed)
	}
	return nil
}

func runSecretsCoverage(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	store, cleanup, err := openSecretsStoreWithKMS(ctx, migrateMasterKey)
	if err != nil {
		return err
	}
	defer cleanup()

	c, err := store.VerifyEnvelopeCoverage(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("\nSecrets envelope-encryption coverage:\n")
	fmt.Printf("  total:    %d\n", c.Total)
	fmt.Printf("  legacy:   %d\n", c.Legacy)
	fmt.Printf("  envelope: %d\n", c.Envelope)
	if c.Total > 0 {
		pct := float64(c.Envelope) / float64(c.Total) * 100
		fmt.Printf("  coverage: %.1f%%\n", pct)
	}
	if c.Legacy == 0 && c.Total > 0 {
		fmt.Printf("\nAll rows are envelope-encoded. Master-key retirement (Phase E) is safe.\n")
	}
	return nil
}

// openSecretsStoreWithKMS wires a Store using the KMS
// backend the env selects (CONTAINARIUM_KMS_BACKEND). The
// daemon uses the same selector, so the migration writes
// rows with the same kek_id shape that the daemon will
// later read.
//
// If the env points at a real backend (vault) but it's
// misconfigured, this returns an error rather than
// silently falling back to InProc — the operator running
// the migration explicitly chose a backend; mis-routing
// the migration to InProc would produce rows the daemon
// then can't decrypt.
//
// If the env is unset / "none", the migration refuses to
// run — there's nothing to migrate INTO. Operators must
// pick at least "inproc" to backfill rows.
func openSecretsStoreWithKMS(ctx context.Context, masterKeyPath string) (*internalsecrets.Store, func(), error) {
	masterKey, _, err := corecrypto.LoadOrCreateMasterKey(masterKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load master key: %w", err)
	}
	cipher, err := corecrypto.NewCipher(masterKey)
	if err != nil {
		return nil, nil, fmt.Errorf("build cipher: %w", err)
	}
	kms, kmsDesc, err := corecrypto.LoadKMSClient(masterKey)
	if err != nil {
		return nil, nil, fmt.Errorf("load KMS backend: %w", err)
	}
	if kms == nil {
		return nil, nil, fmt.Errorf(`migration requires a KMS backend; set CONTAINARIUM_KMS_BACKEND=inproc|vault (current: %s)`, kmsDesc)
	}
	fmt.Fprintf(os.Stderr, "[migrate] KMS backend: %s\n", kmsDesc)

	dsn := getPostgresConnString()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, nil, fmt.Errorf("connect postgres: %w", err)
	}
	store, err := internalsecrets.NewStore(ctx, pool, cipher, internalsecrets.WithKMS(kms))
	if err != nil {
		pool.Close()
		return nil, nil, fmt.Errorf("open store: %w", err)
	}
	return store, func() { pool.Close() }, nil
}
