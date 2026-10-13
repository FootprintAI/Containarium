//go:build !windows && !containarium_client

package cmd

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/internal/sentinel/sshsession"
	"github.com/spf13/cobra"
)

// envAuditIngestToken is the token's environment fallback, so a service
// manager can hand it over without it appearing in `ps`.
const envAuditIngestToken = "CONTAINARIUM_AUDIT_INGEST_TOKEN" // #nosec G101 -- env var name, not a credential

func init() {
	sentinelSSHSessionsCmd.AddCommand(newSentinelSSHSessionsShipCmd())
}

// staticTokens is a one-backend TokenSource for the standalone command.
type staticTokens struct{ backend, token string }

func (s staticTokens) TokenFor(b string) (string, bool, error) {
	if b == s.backend {
		return s.token, true, nil
	}
	return "", false, nil
}
func (s staticTokens) Backends() ([]string, error) { return []string{s.backend}, nil }

// sentinelShipperOptions are the in-process shipper's file locations.
type sentinelShipperOptions struct {
	RecordsFile, CheckpointFile, SentinelID, DefaultBackend string
}

// shipperSources are the sentinel-process state the shipper reads: where a
// login was routed, each backend's registered token, and each backend's URL.
type shipperSources struct {
	Resolver   sshsession.BackendResolver
	Tokens     sshsession.TokenSource
	BackendURL func(backendID string) (string, error)
}

// inProcessShipConfig assembles the multi-backend shipper configuration. The
// typed client is built here rather than in internal/sentinel because that
// package cannot import internal/client (it would form an import cycle in
// internal/client's test build).
func inProcessShipConfig(src shipperSources, opts sentinelShipperOptions) sshsession.ShipConfig {
	return sshsession.ShipConfig{
		RecordsFile:    opts.RecordsFile,
		CheckpointFile: opts.CheckpointFile,
		SentinelID:     opts.SentinelID,
		DefaultBackend: opts.DefaultBackend,
		Resolver:       src.Resolver,
		Tokens:         src.Tokens,
		NewClient: func(backendID, token string) (sshsession.IngestClient, error) {
			base, err := src.BackendURL(backendID)
			if err != nil {
				return nil, err
			}
			return client.NewHTTPClient(base, token)
		},
		Rejected: client.IsIngestRejected,
		Logf:     func(format string, args ...any) { log.Printf("[sentinel] ssh-session-shipper: "+format, args...) },
	}
}

// newSentinelSSHSessionsShipCmd builds `sentinel ssh-sessions ship`. It is a
// constructor (not package-level flag vars) so each invocation, and each
// test, gets fresh flag state.
func newSentinelSSHSessionsShipCmd() *cobra.Command {
	var (
		recordsFile, checkpointFile, url, token, tokenFile, backendID, sentinelID string
		once, reconcile                                                           bool
		orphanAfter, interval                                                     time.Duration
		batchSize                                                                 int
	)

	cmd := &cobra.Command{
		Use:   "ship",
		Short: "Ship SSH session records into a backend's tamper-evident audit store (containarium#2415)",
		Long: `Tail the sentinel's SSH session JSONL sink and ship every record to ONE
backend's audit chain through AuditService.IngestSSHSessionRecords, so front-door
logins get the same hash chain and external anchoring as the rest of the audit
log (verify with "containarium audit verify" on that backend).

This is the standalone, single-backend form of the shipper that already runs
inside "containarium sentinel" (which routes each record to the backend its
login reached). Use it for a one-off backfill, a replay from a copied sink, CI,
or a sentinel with a single backend.

Progress is checkpointed (byte offset + inode, survives restarts and rotation)
and advances only after the backend confirms a batch, so killing and
restarting loses nothing; the backend also deduplicates per (session, phase),
so re-running adds no rows.

  --once       run one pass and exit non-zero if anything could not be shipped.
  --reconcile  instead of tailing: find sessions with an "open" and no "close"
               older than --orphan-after (a plugin hard-kill leaves these) and
               ship a close_reason=unknown_orphan record for each. The sink is
               never rewritten and the checkpoint is not touched.

Standalone shipping sends EVERY record to the one --url backend, so use it
only for a sink that holds that backend's records (the sentinel's own shipper
routes per backend). It keeps its own checkpoint file for that reason.

The token is a JWT minted on that backend with the audit:ingest scope:
  containarium token generate --username sentinel-shipper --roles service \
      --scopes audit:ingest --expiry 2160h --secret-file /etc/containarium/jwt.secret

Examples:
  containarium sentinel ssh-sessions ship --once --url http://<backend>:8080 --token-file /etc/containarium/audit-ingest.token
  containarium sentinel ssh-sessions ship --reconcile --orphan-after 24h --url http://<backend>:8080 --token-file ...`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			tok, err := resolveShipToken(token, tokenFile)
			if err != nil {
				return err
			}
			if url == "" {
				return errors.New("--url is required (the backend's REST base URL)")
			}
			if reconcile && orphanAfter <= 0 {
				return errors.New("--orphan-after must be positive with --reconcile (0 would flag every live session)")
			}
			if sentinelID == "" {
				sentinelID, _ = os.Hostname()
			}

			cfg := sshsession.ShipConfig{
				RecordsFile:    recordsFile,
				CheckpointFile: checkpointFile,
				SentinelID:     sentinelID,
				BatchSize:      batchSize,
				DefaultBackend: backendID, // standalone: every record goes to this backend
				Tokens:         staticTokens{backend: backendID, token: tok},
				NewClient: func(_, token string) (sshsession.IngestClient, error) {
					return client.NewHTTPClient(url, token)
				},
				Rejected:    client.IsIngestRejected,
				OrphanAfter: orphanAfter,
				Logf:        func(f string, a ...any) { log.Printf("ssh-sessions ship: "+f, a...) },
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			out := cmd.OutOrStdout()

			switch {
			case reconcile:
				st, err := sshsession.Reconcile(ctx, cfg)
				fmt.Fprintf(out, "orphans_closed=%d skipped_unroutable=%d\n", st.OrphansClosed, st.SkippedUnroutable)
				return err
			case once:
				st, err := sshsession.ShipOnce(ctx, cfg)
				fmt.Fprintf(out, "shipped=%d duplicates=%d skipped_unroutable=%d skipped_malformed=%d rotated_file_missing=%d\n",
					st.Shipped, st.Duplicates, st.SkippedUnroutable, st.SkippedMalformed, st.RotatedFileMissing)
				return err
			default:
				err := sshsession.Ship(ctx, cfg, interval)
				if errors.Is(err, context.Canceled) {
					return nil
				}
				return err
			}
		},
	}

	f := cmd.Flags()
	f.StringVar(&recordsFile, "records-file", sshsession.DefaultRecordsFile, "Path to the SSH session records JSONL sink to ship")
	f.StringVar(&checkpointFile, "checkpoint-file", sshsession.DefaultStandaloneCheckpointFile, "Where to persist shipping progress (byte offset + inode); separate from the sentinel's in-process shipper, never share it")
	f.StringVar(&url, "url", "", "Backend REST base URL, e.g. http://<backend>:8080 (required)")
	f.StringVar(&token, "token", "", "audit:ingest JWT minted on that backend (prefer --token-file or $"+envAuditIngestToken+": a flag shows up in ps)")
	f.StringVar(&tokenFile, "token-file", "", "File containing the audit:ingest JWT")
	f.StringVar(&backendID, "backend-id", "default", "Name this backend is checkpointed under")
	f.StringVar(&sentinelID, "sentinel-id", "", "Identifier recorded in each row's detail (default: hostname)")
	f.BoolVar(&once, "once", false, "Run a single pass and exit (non-zero if any batch could not be shipped)")
	f.BoolVar(&reconcile, "reconcile", false, "Ship unknown_orphan closes for old opens with no close, instead of tailing")
	f.DurationVar(&orphanAfter, "orphan-after", sshsession.DefaultOrphanAfter, "With --reconcile: how old an unclosed open must be to count as an orphan")
	f.DurationVar(&interval, "interval", 5*time.Second, "Polling interval when running continuously")
	f.IntVar(&batchSize, "batch-size", sshsession.DefaultBatchSize, "Max records per ingest call")
	return cmd
}

// resolveShipToken enforces: at most one of --token/--token-file, falling
// back to the environment, and at least one source overall.
func resolveShipToken(token, tokenFile string) (string, error) {
	if token != "" && tokenFile != "" {
		return "", errors.New("pass exactly one of --token or --token-file, not both")
	}
	switch {
	case tokenFile != "":
		b, err := os.ReadFile(tokenFile) // #nosec G304 -- operator-supplied path
		if err != nil {
			return "", fmt.Errorf("read --token-file: %w", err)
		}
		token = string(b)
	case token == "":
		token = os.Getenv(envAuditIngestToken)
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return "", fmt.Errorf("an audit:ingest token is required: pass --token-file, --token, or set $%s", envAuditIngestToken)
	}
	return token, nil
}
