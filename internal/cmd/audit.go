//go:build !windows && !containarium_client

package cmd

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
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
	auditQueryRunID    string
	auditQueryFrom     string
	auditQueryTo       string
	auditQueryLimit    int
	auditQueryRaw      bool

	// `audit verify` flags
	auditVerifyFromID int64
	auditVerifyBatch  int

	// `audit verify-anchor` flags
	auditAnchorPath   string
	auditAnchorBucket string
	// auditAnchorTSATrustBundle enables the RFC 3161 token check (#2728).
	auditAnchorTSATrustBundle string
)

// defaultAuditAnchorPath mirrors internal/server's constant of the same
// name (#1706) — duplicated rather than imported so this CLI keeps its
// stated direct-Postgres-only dependency shape rather than pulling in the
// daemon package for one path string.
const defaultAuditAnchorPath = "/var/lib/containarium/audit-anchors.jsonl"

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

The timestamp / action / username / resource / run id columns
are indexed, so even an unfiltered query against a
multi-million-row table returns within a few seconds.`,
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
with database access could rewrite a row and recompute every
hash after it, or delete the tail outright — either preserves
internal consistency). It proves nothing has been MODIFIED or
INSERTED as long as nobody can also rewrite the rows after the
edit. See 'audit verify-anchor' for the check that catches a
privileged rewrite-and-recompute, which this command cannot.

A clean verify reports "intact" and the highest ID seen.`,
	Example: `  # Verify from the chain start
  containarium audit verify

  # Verify from a specific ID (faster on large tables)
  containarium audit verify --from-id 100000

  # Smaller batch size for low-memory hosts
  containarium audit verify --batch 200`,
	RunE: runAuditVerify,
}

var auditVerifyAnchorCmd = &cobra.Command{
	Use:   "verify-anchor",
	Short: "Verify the audit chain against its last externally-anchored root",
	Long: `'audit verify' proves internal consistency: every row's hash matches
what its own fields (and the previous row's hash) compute to.
It CANNOT catch an operator with Postgres write access who
edits a row and then correctly recomputes every hash after it
— that produces a chain that is internally consistent by
construction, because the attacker used the same hashing rule
the daemon does.

This command closes that gap (#1706). The daemon periodically
publishes the chain's current tip to an external file the
database cannot rewrite (see CONTAINARIUM_AUDIT_ANCHOR_PATH /
CONTAINARIUM_AUDIT_ANCHOR_INTERVAL on the daemon). This command
re-reads the row at that anchored checkpoint from the database
right now and compares: if it doesn't match what was anchored,
that row (or an earlier one) was rewritten after anchoring — no
matter how correctly the chain was recomputed forward. It also
re-runs the ordinary internal-consistency check for everything
AFTER the checkpoint, since a break there is a different failure
(tampering since the last anchor) that comparing one hash value
can't see.

A privileged rewrite of a row anchored less than one anchoring
interval ago is undetectable until the daemon's next anchor
publishes a checkpoint past it — that window is inherent to
periodic anchoring, not a bug in this check.

With --anchor-bucket (or CONTAINARIUM_AUDIT_ANCHOR_BUCKET, the same
variable the daemon reads) the check also uses the daemon's copy of
the anchors in a GCS bucket, which a host-root attacker cannot
delete or overwrite while the bucket's retention policy is locked.
Every bucket checkpoint is compared with the database and with the
local file. A checkpoint above the database's highest row id, one
whose content does not match its name, one the local file lacks, or
one whose root differs is a failure (non-zero exit). Checkpoints
only the local file holds are still compared with the database
(a mismatch is a failure) and warned about, since the bucket does
not vouch for them. A bucket without a locked retention policy is a
warning (exit 0).

With --anchor-tsa-trust-bundle (or
CONTAINARIUM_AUDIT_ANCHOR_TSA_TRUST_BUNDLE) the check also uses the
RFC 3161 timestamp tokens the daemon stored next to the anchor file
(<anchor-path>.tsa/), which a timestamp authority signed over each
anchor record. A token that does not verify, is not signed by a TSA
chaining to the bundle at the token's time, covers a different record
than the local file holds (the line was edited), or has no local
record is a failure (non-zero exit). Every local checkpoint is also
compared with the database. A checkpoint with no token is a warning
(exit 0). The check is offline: it needs the bundle, not the TSA.

With neither a bucket nor a trust bundle configured, behaviour is
unchanged.`,
	Example: `  # Default anchor path (same as the daemon's default)
  containarium audit verify-anchor

  # Non-default anchor location
  containarium audit verify-anchor --anchor-path /mnt/forensics/audit-anchors.jsonl

  # Also check against the daemon's external anchor bucket
  containarium audit verify-anchor --anchor-bucket gs://<bucket>/<prefix>

  # Also check the RFC 3161 timestamp tokens against the TSA's root
  containarium audit verify-anchor --anchor-tsa-trust-bundle /etc/containarium/tsa-roots.pem`,
	RunE: runAuditVerifyAnchor,
}

func init() {
	rootCmd.AddCommand(auditCmd)
	auditCmd.AddCommand(auditQueryCmd)
	auditCmd.AddCommand(auditVerifyCmd)
	auditCmd.AddCommand(auditVerifyAnchorCmd)

	auditVerifyAnchorCmd.Flags().StringVar(&auditAnchorPath, "anchor-path", "",
		"Path to the anchor file (default: $CONTAINARIUM_AUDIT_ANCHOR_PATH, or the daemon's own default)")
	auditVerifyAnchorCmd.Flags().StringVar(&auditAnchorBucket, "anchor-bucket", "",
		"Also check against the anchors in this bucket, gs://<bucket>[/<prefix>] (default: $CONTAINARIUM_AUDIT_ANCHOR_BUCKET; unset checks the local file only)")
	auditVerifyAnchorCmd.Flags().StringVar(&auditAnchorTSATrustBundle, "anchor-tsa-trust-bundle", "",
		"Also check the RFC 3161 timestamp tokens in <anchor-path>.tsa/ against this PEM bundle of TSA root certificates (default: $CONTAINARIUM_AUDIT_ANCHOR_TSA_TRUST_BUNDLE; unset skips the token check)")

	auditQueryCmd.Flags().StringVar(&auditQueryUsername, "username", "", "Filter by username (exact match)")
	auditQueryCmd.Flags().StringVar(&auditQueryAction, "action", "", "Filter by action (exact match, e.g. create_container)")
	auditQueryCmd.Flags().StringVar(&auditQueryResource, "resource-type", "", "Filter by resource type (e.g. container, secret, api)")
	auditQueryCmd.Flags().StringVar(&auditQueryRunID, "run-id", "", "Filter by run id (exact match, e.g. an agent skill run)")
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

// buildAuditQueryParams turns the `audit query` flag values into
// audit.QueryParams. Pulled out of runAuditQuery so the flag-to-filter
// wiring is unit-testable without a live Postgres connection (#1818).
func buildAuditQueryParams(username, action, resourceType, runID, from, to string, limit int) (audit.QueryParams, error) {
	params := audit.QueryParams{
		Username:     username,
		Action:       action,
		ResourceType: resourceType,
		RunID:        runID,
		Limit:        limit,
	}
	if from != "" {
		t, err := time.Parse(time.RFC3339, from)
		if err != nil {
			return audit.QueryParams{}, fmt.Errorf("--from must be RFC3339: %w", err)
		}
		params.From = t
	}
	if to != "" {
		t, err := time.Parse(time.RFC3339, to)
		if err != nil {
			return audit.QueryParams{}, fmt.Errorf("--to must be RFC3339: %w", err)
		}
		params.To = t
	}
	return params, nil
}

func runAuditQuery(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	store, cleanup, err := openAuditStore(ctx)
	if err != nil {
		return err
	}
	defer cleanup()

	params, err := buildAuditQueryParams(auditQueryUsername, auditQueryAction, auditQueryResource,
		auditQueryRunID, auditQueryFrom, auditQueryTo, auditQueryLimit)
	if err != nil {
		return err
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
	// After a retention purge (#2878) the rows before the stored base are gone;
	// start there instead of re-verifying the same first batch from every
	// from-id below it.
	base, purged, err := store.ChainBase(ctx)
	if err != nil {
		return err
	}
	fromID, baseNote := verifyStartID(fromID, base, purged)
	if baseNote != "" {
		fmt.Println("\n  " + baseNote)
	}
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

// verifyStartID is where `audit verify` starts: the requested row, or the chain
// base when a retention purge removed everything up to it. The note says so, so
// a clean result is not read as "verified from the first row ever written".
func verifyStartID(from int64, base audit.ChainBase, purged bool) (int64, string) {
	if !purged || from > base.ID {
		return from, ""
	}
	return base.ID, fmt.Sprintf("Rows up to id=%d were purged by retention (%d in total, last on %s); verifying from the stored chain base.",
		base.ID, base.RowsPurged, base.PurgedAt.UTC().Format("2006-01-02T15:04:05Z"))
}

func runAuditVerifyAnchor(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	store, cleanup, err := openAuditStore(ctx)
	if err != nil {
		return err
	}
	defer cleanup()

	path := auditAnchorPath
	if path == "" {
		path = os.Getenv("CONTAINARIUM_AUDIT_ANCHOR_PATH")
	}
	if path == "" {
		path = defaultAuditAnchorPath
	}
	sink, err := audit.NewFileSink(path)
	if err != nil {
		return fmt.Errorf("open anchor sink %q: %w", path, err)
	}

	bucketURI := resolveAnchorBucket(auditAnchorBucket)
	tsaBundle := resolveAnchorTSATrustBundle(auditAnchorTSATrustBundle)
	if bucketURI != "" || tsaBundle != "" {
		// Each configured external copy is checked; any failure fails the run.
		var errs []error
		if bucketURI != "" {
			errs = append(errs, runAuditVerifyAnchorBucket(ctx, store, sink, path, bucketURI))
		}
		if tsaBundle != "" {
			errs = append(errs, runAuditVerifyAnchorTSA(ctx, store, sink, path, tsaBundle))
		}
		return errors.Join(errs...)
	}

	result, err := store.VerifyChainAgainstAnchor(ctx, sink)
	if err != nil {
		if errors.Is(err, audit.ErrNoAnchor) {
			fmt.Printf("\n  ⚠ No anchor has been published yet at %s\n", path)
			fmt.Println("    Either the daemon has not run long enough to anchor once, or")
			fmt.Println("    CONTAINARIUM_AUDIT_ANCHOR_PATH doesn't match this daemon's setting.")
			fmt.Println()
			return nil
		}
		return fmt.Errorf("verify against anchor: %w", err)
	}

	if result.OK() {
		fmt.Printf("\n  ✓ Chain matches its anchor at checkpoint id=%d\n\n", result.Checkpoint)
		return nil
	}

	fmt.Fprintf(os.Stderr, "\n  ✗ Chain does NOT match its anchor at checkpoint id=%d\n\n", result.Checkpoint)
	if result.AnchorRoot != result.CurrentRoot {
		if result.CurrentRoot == "" {
			fmt.Fprintf(os.Stderr, "  Row id=%d, which was anchored, no longer exists — it was deleted.\n", result.Checkpoint)
		} else {
			fmt.Fprintf(os.Stderr, "  Row id=%d's hash has changed since it was anchored — that row, or an earlier\n", result.Checkpoint)
			fmt.Fprintf(os.Stderr, "  one, was rewritten after anchoring, even though 'audit verify' alone would not show it:\n")
			fmt.Fprintf(os.Stderr, "  a rewrite followed by a correctly recomputed chain looks internally consistent.\n\n")
		}
	}
	if result.FirstBadAfterCheckpoint != 0 {
		fmt.Fprintf(os.Stderr, "  Additionally, internal consistency breaks at row id=%d (after the checkpoint).\n\n", result.FirstBadAfterCheckpoint)
	}
	return fmt.Errorf("chain does not match its anchor at checkpoint id=%d", result.Checkpoint)
}

// resolveAnchorBucket returns the bucket URI to check: the flag, else
// $CONTAINARIUM_AUDIT_ANCHOR_BUCKET, else "" (no bucket: the local-file check
// is unchanged).
func resolveAnchorBucket(flag string) string {
	if v := strings.TrimSpace(flag); v != "" {
		return v
	}
	return strings.TrimSpace(os.Getenv("CONTAINARIUM_AUDIT_ANCHOR_BUCKET"))
}

// resolveAnchorTSATrustBundle returns the TSA trust bundle path: the flag,
// else $CONTAINARIUM_AUDIT_ANCHOR_TSA_TRUST_BUNDLE (the daemon reads the same
// variable), else "" (no token check).
func resolveAnchorTSATrustBundle(flag string) string {
	if v := strings.TrimSpace(flag); v != "" {
		return v
	}
	return strings.TrimSpace(os.Getenv("CONTAINARIUM_AUDIT_ANCHOR_TSA_TRUST_BUNDLE"))
}

// fixedRootSink presents one already-read (checkpoint, root) as a RootSink, so
// Store.VerifyChainAgainstAnchor can run its row-hash and tail-consistency
// check against a checkpoint the bucket check has validated.
type fixedRootSink struct {
	checkpoint int64
	root       string
}

func (fixedRootSink) PublishRoot(context.Context, int64, string) error {
	return errors.New("read-only anchor view")
}

func (f fixedRootSink) LastPublished(context.Context) (int64, string, bool, error) {
	return f.checkpoint, f.root, true, nil
}

// anchorChain is the database side of the bucket check: *audit.Store.
type anchorChain interface {
	audit.ChainStore
	VerifyChainAgainstAnchor(ctx context.Context, sink audit.RootSink) (audit.AnchorVerifyResult, error)
}

func runAuditVerifyAnchorBucket(ctx context.Context, chain anchorChain, local *audit.FileSink, localPath, uri string) error {
	bucket, err := audit.NewGCSAnchorSink(uri)
	if err != nil {
		return fmt.Errorf("open anchor bucket %q: %w", uri, err)
	}
	return verifyAnchorBucket(ctx, chain, local, localPath, bucket, os.Stdout, os.Stderr)
}

func verifyAnchorBucket(ctx context.Context, chain anchorChain, local *audit.FileSink, localPath string, bucket audit.AnchorBucket, out, errOut io.Writer) error {
	report, err := audit.VerifyAnchorsAgainstBucket(ctx, chain, local, bucket)
	if err != nil {
		if errors.Is(err, audit.ErrNoAnchor) {
			fmt.Fprintf(out, "\n  ⚠ No anchor has been published yet, locally (%s) or in %s\n\n", localPath, bucket.URI())
			return nil
		}
		return fmt.Errorf("verify against anchor bucket: %w", err)
	}

	// The chain after the highest verified checkpoint, in either copy, must
	// still be internally consistent, as in the local-file check.
	var firstBad int64
	if report.TailCheckpoint > 0 {
		res, err := chain.VerifyChainAgainstAnchor(ctx, fixedRootSink{checkpoint: report.TailCheckpoint, root: report.TailRoot})
		if err != nil {
			return fmt.Errorf("verify chain since the latest checkpoint: %w", err)
		}
		firstBad = res.FirstBadAfterCheckpoint
	}
	return printBucketAnchorReport(out, errOut, bucket.URI(), report, firstBad)
}

func runAuditVerifyAnchorTSA(ctx context.Context, chain anchorChain, local *audit.FileSink, localPath, bundlePath string) error {
	trust, err := audit.LoadTSATrustBundle(bundlePath)
	if err != nil {
		return err
	}
	return verifyAnchorTSA(ctx, chain, local, localPath, trust, os.Stdout, os.Stderr)
}

func verifyAnchorTSA(ctx context.Context, chain anchorChain, local *audit.FileSink, localPath string, trust *x509.CertPool, out, errOut io.Writer) error {
	dir := audit.TSATokenDir(localPath)
	report, err := audit.VerifyAnchorsAgainstTSA(ctx, chain, local, trust)
	if err != nil {
		if errors.Is(err, audit.ErrNoAnchor) {
			fmt.Fprintf(out, "\n  ⚠ No anchor has been published yet, locally (%s) or as a timestamp token (%s)\n\n", localPath, dir)
			return nil
		}
		return fmt.Errorf("verify against timestamp tokens: %w", err)
	}
	var firstBad int64
	if report.TailCheckpoint > 0 {
		res, err := chain.VerifyChainAgainstAnchor(ctx, fixedRootSink{checkpoint: report.TailCheckpoint, root: report.TailRoot})
		if err != nil {
			return fmt.Errorf("verify chain since the latest checkpoint: %w", err)
		}
		firstBad = res.FirstBadAfterCheckpoint
	}
	return printTSAAnchorReport(out, errOut, dir, report, firstBad)
}

// printTSAAnchorReport renders the token check like printBucketAnchorReport:
// ⚠ on stdout, ✗ on stderr, an error (non-zero exit) only on a failure.
func printTSAAnchorReport(out, errOut io.Writer, dir string, r audit.TSAAnchorReport, firstBadAfterLatest int64) error {
	fmt.Fprintln(out)
	for _, w := range r.Warnings {
		fmt.Fprintf(out, "  ⚠ %s\n", tsaFindingLine(w))
	}
	if len(r.Warnings) > 0 {
		fmt.Fprintln(out)
	}
	failed := len(r.Failures)
	if failed > 0 || firstBadAfterLatest != 0 {
		fmt.Fprintf(errOut, "  ✗ Timestamp token check (%s) FAILED\n\n", dir)
		for _, f := range r.Failures {
			fmt.Fprintf(errOut, "  ✗ %s\n", tsaFindingLine(f))
		}
		if firstBadAfterLatest != 0 {
			fmt.Fprintf(errOut, "  ✗ Internal consistency breaks at row id=%d (after the latest checkpoint).\n", firstBadAfterLatest)
			failed++
		}
		fmt.Fprintln(errOut)
		return fmt.Errorf("timestamp token check (%s) failed (%d problem(s))", dir, failed)
	}
	fmt.Fprintf(out, "  ✓ %d checkpoint(s) carry a valid timestamp token matching the local anchor file (latest id=%d); every local checkpoint matches the database\n\n",
		r.StampedCheckpoints, r.LatestStamped)
	return nil
}

func tsaFindingLine(f audit.TSAAnchorFinding) string {
	if f.Checkpoint == 0 {
		return f.Detail
	}
	return fmt.Sprintf("checkpoint id=%d: %s", f.Checkpoint, f.Detail)
}

// printBucketAnchorReport renders the bucket check: ⚠ lines on stdout, ✗
// lines on stderr. It returns an error (non-zero exit) when anything failed;
// warnings alone return nil.
func printBucketAnchorReport(out, errOut io.Writer, uri string, r audit.BucketAnchorReport, firstBadAfterLatest int64) error {
	fmt.Fprintln(out)
	for _, w := range r.Warnings {
		fmt.Fprintf(out, "  ⚠ %s\n", findingLine(w))
	}
	if len(r.Warnings) > 0 {
		fmt.Fprintln(out)
	}

	failed := len(r.Failures)
	if failed > 0 || firstBadAfterLatest != 0 {
		fmt.Fprintf(errOut, "  ✗ Anchor check against %s FAILED\n\n", uri)
		for _, f := range r.Failures {
			fmt.Fprintf(errOut, "  ✗ %s\n", findingLine(f))
		}
		if firstBadAfterLatest != 0 {
			fmt.Fprintf(errOut, "  ✗ Internal consistency breaks at row id=%d (after the latest checkpoint).\n", firstBadAfterLatest)
			failed++
		}
		fmt.Fprintln(errOut)
		return fmt.Errorf("anchor check against %s failed (%d problem(s))", uri, failed)
	}

	fmt.Fprintf(out, "  ✓ %d checkpoint(s) in %s match the database and the local anchor file (latest id=%d)\n\n",
		r.CheckedCheckpoints, uri, r.LatestCheckpoint)
	return nil
}

func findingLine(f audit.BucketAnchorFinding) string {
	if f.Checkpoint == 0 {
		return f.Detail
	}
	return fmt.Sprintf("checkpoint id=%d: %s", f.Checkpoint, f.Detail)
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
