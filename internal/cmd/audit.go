//go:build !windows

package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"
)

// Phase 4.5 follow-up — operator-facing audit CLI. The
// runbook references `containarium audit query` and
// `audit verify`; this file makes those commands real
// (they weren't shipped before).
//
// Both commands take the direct Postgres path rather than
// going through the daemon's REST API. Rationale: the
// daemon's audit-log routes are read-only on the wire and
// audit retention is a maintenance task, not a runtime
// API. Operators with DB credentials run these locally
// alongside the migration tools.

var (
	// `audit query` flags
	auditQueryUsername string
	auditQueryAction   string
	auditQueryResource string
	auditQueryFrom     string
	auditQueryTo       string
	auditQueryLimit    int
	auditQueryRaw      bool

	// `audit verify` flags
	auditVerifyFromID int64
	auditVerifyBatch  int
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Inspect and verify the audit log",
	Long: `Query historical audit-log entries and verify the tamper-evidence
hash chain.

Direct Postgres access — needs CONTAINARIUM_POSTGRES_URL /
_URL_FILE / _PASSWORD_FILE configured the same way the daemon
reads it. See the operator runbook for the full DSN options.`,
}

var auditQueryCmd = &cobra.Command{
	Use:   "query",
	Short: "Query audit log entries with filters",
	Long: `Returns audit log rows matching the given filters, most-recent
first. Filters compose with AND — leave flags unset to match
everything in that dimension.

The timestamp / action / username / resource columns are
indexed, so even an unfiltered query against a multi-million-
row table returns within a few seconds.`,
	Example: `  # Everything an admin did in the last hour
  containarium audit query --username ops \
      --from "$(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)" \
      --limit 100

  # All token revocations this month
  containarium audit query --action token_revoke \
      --from "$(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)"

  # Tab-separated for grep/awk piping
  containarium audit query --action create_container --raw | awk '{print $2}'`,
	RunE: runAuditQuery,
}

var auditVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify the audit-log tamper-evidence hash chain",
	Long: `Walks the audit log's row_hash chain forward from --from-id
(or the chain start by default) and reports the first row
whose hash doesn't match its stored value. A break indicates
the row was edited after insert OR a row was inserted
between two existing rows.

The chain doesn't prove the log is COMPLETE (an attacker
could delete the suffix); it proves nothing has been
MODIFIED or INSERTED. Append-only forensics (external
sink for the chain root) catches deletion, tracked
separately.

A clean verify reports "intact" and the highest ID seen.`,
	Example: `  # Verify from the chain start
  containarium audit verify

  # Verify from a specific ID (faster on large tables)
  containarium audit verify --from-id 100000

  # Smaller batch size for low-memory hosts
  containarium audit verify --batch 200`,
	RunE: runAuditVerify,
}

func init() {
	rootCmd.AddCommand(auditCmd)
	auditCmd.AddCommand(auditQueryCmd)
	auditCmd.AddCommand(auditVerifyCmd)

	auditQueryCmd.Flags().StringVar(&auditQueryUsername, "username", "", "Filter by username (exact match)")
	auditQueryCmd.Flags().StringVar(&auditQueryAction, "action", "", "Filter by action (exact match, e.g. create_container)")
	auditQueryCmd.Flags().StringVar(&auditQueryResource, "resource-type", "", "Filter by resource type (e.g. container, secret, api)")
	auditQueryCmd.Flags().StringVar(&auditQueryFrom, "from", "", "Start of time range (RFC3339)")
	auditQueryCmd.Flags().StringVar(&auditQueryTo, "to", "", "End of time range (RFC3339)")
	auditQueryCmd.Flags().IntVar(&auditQueryLimit, "limit", 50, "Max rows to return (server caps at 1000)")
	auditQueryCmd.Flags().BoolVar(&auditQueryRaw, "raw", false, "Tab-separated output for grep/awk piping")

	auditVerifyCmd.Flags().Int64Var(&auditVerifyFromID, "from-id", 0, "Verify forward from this row ID (0 = chain start)")
	auditVerifyCmd.Flags().IntVar(&auditVerifyBatch, "batch", 1000, "Rows fetched per pass (memory-bound)")
}

// openAuditStore connects to Postgres using the same DSN
// resolution chain the daemon uses (URL_FILE → URL → auto-
// detect default with PASSWORD_FILE/PASSWORD/default).
// Returns a cleanup that closes the pool.
func openAuditStore(ctx context.Context) (*audit.Store, func(), error) {
	dsn := getPostgresConnString()
	if dsn == "" {
		return nil, nil, fmt.Errorf("no postgres DSN configured; set CONTAINARIUM_POSTGRES_URL_FILE or CONTAINARIUM_POSTGRES_URL")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, nil, fmt.Errorf("connect postgres: %w", err)
	}
	store, err := audit.NewStore(ctx, pool)
	if err != nil {
		pool.Close()
		return nil, nil, fmt.Errorf("open audit store: %w", err)
	}
	return store, func() { pool.Close() }, nil
}

func runAuditQuery(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	store, cleanup, err := openAuditStore(ctx)
	if err != nil {
		return err
	}
	defer cleanup()

	params := audit.QueryParams{
		Username:     auditQueryUsername,
		Action:       auditQueryAction,
		ResourceType: auditQueryResource,
		Limit:        auditQueryLimit,
	}
	if auditQueryFrom != "" {
		t, err := time.Parse(time.RFC3339, auditQueryFrom)
		if err != nil {
			return fmt.Errorf("--from must be RFC3339: %w", err)
		}
		params.From = t
	}
	if auditQueryTo != "" {
		t, err := time.Parse(time.RFC3339, auditQueryTo)
		if err != nil {
			return fmt.Errorf("--to must be RFC3339: %w", err)
		}
		params.To = t
	}

	rows, total, err := store.Query(ctx, params)
	if err != nil {
		return err
	}

	if auditQueryRaw {
		// Tab-separated: timestamp\tusername\taction\tresource_type\tresource_id\tstatus\tdetail
		for _, r := range rows {
			fmt.Printf("%s\t%s\t%s\t%s\t%s\t%d\t%s\n",
				r.Timestamp.UTC().Format(time.RFC3339),
				r.Username, r.Action, r.ResourceType, r.ResourceID, r.StatusCode,
				sanitizeDetailForCLI(r.Detail),
			)
		}
		return nil
	}

	if len(rows) == 0 {
		fmt.Println("(no audit rows match)")
		return nil
	}
	fmt.Printf("\n%d row(s) shown of %d total matching\n\n", len(rows), total)
	fmt.Printf("%-22s  %-14s  %-22s  %-32s  %4s  %s\n",
		"TIMESTAMP", "USERNAME", "ACTION", "RESOURCE", "CODE", "DETAIL")
	for _, r := range rows {
		resource := r.ResourceType
		if r.ResourceID != "" {
			resource = r.ResourceType + ":" + r.ResourceID
		}
		fmt.Printf("%-22s  %-14s  %-22s  %-32s  %4d  %s\n",
			r.Timestamp.UTC().Format("2006-01-02T15:04:05Z"),
			truncateAudit(r.Username, 14),
			truncateAudit(r.Action, 22),
			truncateAudit(resource, 32),
			r.StatusCode,
			truncateAudit(sanitizeDetailForCLI(r.Detail), 80),
		)
	}
	return nil
}

func runAuditVerify(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	store, cleanup, err := openAuditStore(ctx)
	if err != nil {
		return err
	}
	defer cleanup()

	// Snapshot the table's max ID once. The chain only
	// grows (no UPDATE/DELETE on hash columns), so the
	// upper bound captured here stays valid even if new
	// rows append during the verify.
	maxID, err := store.MaxRowID(ctx)
	if err != nil {
		return err
	}
	if maxID == 0 {
		fmt.Println("\n  ✓ Audit log is empty (nothing to verify)")
		fmt.Println()
		return nil
	}

	// VerifyChainSinceID returns at most `batch` rows per
	// call so memory stays bounded. The store currently
	// doesn't return the highest ID it scanned; we
	// approximate "done" by advancing fromID by `batch`
	// each iteration until we pass the snapshot maxID.
	// This over-scans by at most one batch in the worst
	// case, which is acceptable for an idempotent verify.
	fromID := auditVerifyFromID
	for fromID < maxID {
		firstBad, err := store.VerifyChainSinceID(ctx, fromID, auditVerifyBatch)
		if err != nil {
			return fmt.Errorf("verify chain: %w", err)
		}
		if firstBad != 0 {
			fmt.Fprintf(os.Stderr, "\n  ✗ Chain BROKEN at row id=%d\n\n", firstBad)
			fmt.Fprintf(os.Stderr, "  Investigate: rows before %d are trusted; that row and everything after are suspect.\n", firstBad)
			fmt.Fprintf(os.Stderr, "  Likely causes: direct DB write bypassing the daemon, restore from a partial backup, or schema migration drift.\n\n")
			return fmt.Errorf("chain broken at id=%d", firstBad)
		}
		fromID += int64(auditVerifyBatch)
	}

	fmt.Printf("\n  ✓ Audit-log chain intact (verified through id=%d)\n\n", maxID)
	return nil
}

// sanitizeDetailForCLI strips newlines from the detail
// column so each row stays on its own line in the table
// output. The audit redactor already scrubs secrets at
// insert time (Phase 4.4), so we don't need to scrub
// again — just normalize whitespace for display.
func sanitizeDetailForCLI(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	return s
}

func truncateAudit(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n < 4 {
		return s[:n]
	}
	return s[:n-1] + "…"
}
