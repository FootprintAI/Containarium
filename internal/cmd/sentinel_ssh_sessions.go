//go:build !windows && !containarium_client

// `containarium sentinel ssh-sessions list`/`follow` — the CLI subcommand
// containarium#1980's own acceptance criteria called for but did not ship
// (split out as containarium#2004 to keep #1980's PR reviewable).
//
// Both subcommands read internal/sentinel/sshsession.Record directly off
// the local JSONL sink `containarium sentinel ssh-session-plugin` appends
// to (internal/cmd/sentinel_ssh_session_plugin.go) — no proto, no server
// round trip, since the sink is a local file the CLI and the plugin
// process both run against on the same host (see that command's own doc
// comment for why). This command is entirely read-only: it never opens
// the sink for writing and never touches the plugin process itself.
package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/footprintai/containarium/internal/sentinel/sshsession"
	"github.com/spf13/cobra"
)

var (
	sshSessionsFile      string
	sshSessionsSessionID string
	sshSessionsLogin     string
	sshSessionsJSON      bool
)

var sentinelSSHSessionsCmd = &cobra.Command{
	Use:   "ssh-sessions",
	Short: "List or follow structured SSH session lifecycle records (containarium#1980)",
	Long: `Reads the JSONL sink that "containarium sentinel ssh-session-plugin" (containarium#1980)
appends one record to per SSH session open/close event on this sentinel.

This command only reads that file locally — it never talks to sshpiperd or
the plugin process — so it works equally well against a live sink or a
copy of one pulled off a sentinel for offline review.`,
}

var sentinelSSHSessionsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List SSH session records, newest first",
	Long: `List SSH session lifecycle records from the sink, newest first.

Examples:
  containarium sentinel ssh-sessions list
  containarium sentinel ssh-sessions list --login alice
  containarium sentinel ssh-sessions list --session-id 3f2c9a1e-...  --json
  containarium sentinel ssh-sessions list --records-file /path/to/ssh-sessions.jsonl`,
	Args: cobra.NoArgs,
	RunE: runSentinelSSHSessionsList,
}

var sentinelSSHSessionsFollowCmd = &cobra.Command{
	Use:   "follow",
	Short: "Follow the sink for new SSH session records, like tail -f",
	Long: `Follow the sink for SSH session lifecycle records as they are appended,
similar to tail -f. Starts from the current end of the file (existing
history is NOT replayed) — pair with "list" first if you also want that.

Runs until interrupted (Ctrl-C / SIGTERM).

Examples:
  containarium sentinel ssh-sessions follow
  containarium sentinel ssh-sessions follow --login alice
  containarium sentinel ssh-sessions follow --json`,
	Args: cobra.NoArgs,
	RunE: runSentinelSSHSessionsFollow,
}

func init() {
	sentinelCmd.AddCommand(sentinelSSHSessionsCmd)
	sentinelSSHSessionsCmd.AddCommand(sentinelSSHSessionsListCmd)
	sentinelSSHSessionsCmd.AddCommand(sentinelSSHSessionsFollowCmd)

	for _, c := range []*cobra.Command{sentinelSSHSessionsListCmd, sentinelSSHSessionsFollowCmd} {
		c.Flags().StringVar(&sshSessionsFile, "records-file", sshsession.DefaultRecordsFile,
			"Path to the SSH session records JSONL sink to read")
		c.Flags().StringVar(&sshSessionsSessionID, "session-id", "", "Only show records for this session_id")
		c.Flags().StringVar(&sshSessionsLogin, "login", "", "Only show records for this login")
		c.Flags().BoolVar(&sshSessionsJSON, "json", false,
			"Output one JSON object per line (the sink's own record shape) instead of a table, for scripting")
	}
}

// resetSSHSessionsFlags restores the package-level flag vars between
// tests, mirroring internal/cmd/sentinel_pprof_test.go's
// resetSentinelPprofFlags for the same package-var-as-cobra-flag shape.
func resetSSHSessionsFlags() {
	sshSessionsFile = sshsession.DefaultRecordsFile
	sshSessionsSessionID = ""
	sshSessionsLogin = ""
	sshSessionsJSON = false
}

func sshSessionsFilter() sshsession.Filter {
	return sshsession.Filter{SessionID: sshSessionsSessionID, Login: sshSessionsLogin}
}

func sshSessionHeaderFields() []string {
	return []string{"OCCURRED_AT", "PHASE", "SESSION_ID", "LOGIN", "CLIENT_IP", "TARGET", "AUTH_METHOD", "CLOSE_REASON"}
}

// sshSessionRowFields renders rec's human-readable columns, in the same
// order sshSessionHeaderFields names them. Fields that are legitimately
// absent (e.g. CloseReason on an "open" record) print as "-" rather than
// an empty cell, so a reader can tell "absent" from "misaligned".
func sshSessionRowFields(rec sshsession.Record) []string {
	return []string{
		rec.OccurredAt.Format(time.RFC3339),
		string(rec.Phase),
		rec.SessionID,
		rec.Login,
		rec.ClientIP,
		dashIfEmpty(rec.Target),
		dashIfEmpty(string(rec.AuthMethod)),
		dashIfEmpty(string(rec.CloseReason)),
	}
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// encodeSSHSessionRecordsJSON writes one compact JSON object per record —
// the sink's own JSONL shape — so --json output is a direct passthrough a
// script can `jq` line by line, not a differently-shaped envelope.
func encodeSSHSessionRecordsJSON(w io.Writer, records []sshsession.Record) error {
	enc := json.NewEncoder(w)
	for _, rec := range records {
		if err := enc.Encode(rec); err != nil {
			return fmt.Errorf("encode record: %w", err)
		}
	}
	return nil
}

// reverseSSHSessionRecords reverses records in place — ReadRecordsFile
// returns oldest-first (file order); `list`'s acceptance criterion wants
// newest-first.
func reverseSSHSessionRecords(records []sshsession.Record) {
	for i, j := 0, len(records)-1; i < j; i, j = i+1, j-1 {
		records[i], records[j] = records[j], records[i]
	}
}

func runSentinelSSHSessionsList(cmd *cobra.Command, _ []string) error {
	records, err := sshsession.ReadRecordsFile(sshSessionsFile, sshSessionsFilter())
	if err != nil {
		return fmt.Errorf("read %s: %w", sshSessionsFile, err)
	}
	reverseSSHSessionRecords(records)

	out := cmd.OutOrStdout()
	if sshSessionsJSON {
		return encodeSSHSessionRecordsJSON(out, records)
	}

	if len(records) == 0 {
		fmt.Fprintln(out, "No SSH session records found.")
		return nil
	}

	w := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, strings.Join(sshSessionHeaderFields(), "\t"))
	for _, rec := range records {
		fmt.Fprintln(w, strings.Join(sshSessionRowFields(rec), "\t"))
	}
	return w.Flush()
}

func runSentinelSSHSessionsFollow(cmd *cobra.Command, _ []string) error {
	ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	out := cmd.OutOrStdout()
	if !sshSessionsJSON {
		fmt.Fprintln(out, strings.Join(sshSessionHeaderFields(), "\t"))
	}

	recs := make(chan sshsession.Record, 16)
	errc := make(chan error, 1)
	go func() { errc <- sshsession.Follow(ctx, sshSessionsFile, sshSessionsFilter(), recs) }()

	emit := func(rec sshsession.Record) error {
		if sshSessionsJSON {
			return encodeSSHSessionRecordsJSON(out, []sshsession.Record{rec})
		}
		_, err := fmt.Fprintln(out, strings.Join(sshSessionRowFields(rec), "\t"))
		return err
	}

	var followErr error
loop:
	for {
		select {
		case rec := <-recs:
			if err := emit(rec); err != nil {
				return err
			}
		case err := <-errc:
			followErr = err
			break loop
		}
	}

	// Follow may have queued a record (out has spare buffer) in the same
	// instant it observed ctx cancellation — drain it rather than dropping
	// a session record on shutdown.
	for {
		select {
		case rec := <-recs:
			if err := emit(rec); err != nil {
				return err
			}
		default:
			if followErr != nil && !errors.Is(followErr, context.Canceled) {
				return followErr
			}
			return nil
		}
	}
}
