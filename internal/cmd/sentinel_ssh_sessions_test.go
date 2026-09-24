//go:build !windows && !containarium_client

package cmd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/sentinel/sshsession"
	"github.com/spf13/cobra"
)

// writeSessionJSONL is the test-local twin of the sshsession package's own
// writeJSONL helper — kept here rather than exported across packages since
// it's a one-line convenience, not shared behavior.
func writeSessionJSONL(t *testing.T, path string, recs ...sshsession.Record) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatalf("open %q: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	for _, rec := range recs {
		line, err := json.Marshal(rec)
		if err != nil {
			t.Fatalf("marshal record: %v", err)
		}
		if _, err := f.Write(append(line, '\n')); err != nil {
			t.Fatalf("write record: %v", err)
		}
	}
}

func newSSHSessionsTestCmd(ctx context.Context, out *bytes.Buffer) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetContext(ctx)
	return cmd
}

// TestRunSentinelSSHSessionsList covers containarium#2004's `list` scope
// item: read the JSONL sink, print newest-first, filterable by
// session_id/login, with a --json passthrough. All fixture addresses are
// RFC 5737 test-net (never real), per this repo's CLAUDE.md.
func TestRunSentinelSSHSessionsList(t *testing.T) {
	open1 := sshsession.Record{
		SessionID: "sess-1", Phase: sshsession.SessionPhaseOpen,
		OccurredAt: time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC),
		ClientIP:   "203.0.113.10", Login: "alice", Target: "192.0.2.5:20022",
		AuthMethod: sshsession.AuthMethodPublicKey,
	}
	open2 := sshsession.Record{
		SessionID: "sess-2", Phase: sshsession.SessionPhaseOpen,
		OccurredAt: time.Date(2026, 1, 1, 10, 5, 0, 0, time.UTC),
		ClientIP:   "198.51.100.20", Login: "bob", Target: "192.0.2.6:20022",
		AuthMethod: sshsession.AuthMethodCertificate,
	}
	close1 := sshsession.Record{
		SessionID: "sess-1", Phase: sshsession.SessionPhaseClose,
		OccurredAt: time.Date(2026, 1, 1, 10, 10, 0, 0, time.UTC),
		ClientIP:   "203.0.113.10", Login: "alice", Target: "192.0.2.5:20022",
		CloseReason: sshsession.CloseReasonNormal,
	}

	tests := []struct {
		name       string
		sessionID  string
		login      string
		jsonOut    bool
		wantOrder  []string // session_id/phase, in printed order
		wantEmpty  bool
		wantErrSub string
	}{
		{
			name:      "no filter, newest first",
			wantOrder: []string{"sess-1/close", "sess-2/open", "sess-1/open"},
		},
		{
			name:      "filter by session_id",
			sessionID: "sess-1",
			wantOrder: []string{"sess-1/close", "sess-1/open"},
		},
		{
			name:      "filter by login",
			login:     "bob",
			wantOrder: []string{"sess-2/open"},
		},
		{
			name:      "filter matching nothing",
			sessionID: "does-not-exist",
			wantEmpty: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "ssh-sessions.jsonl")
			writeSessionJSONL(t, path, open1, open2, close1)

			t.Cleanup(resetSSHSessionsFlags)
			resetSSHSessionsFlags()
			sshSessionsFile = path
			sshSessionsSessionID = tt.sessionID
			sshSessionsLogin = tt.login
			sshSessionsJSON = tt.jsonOut

			var out bytes.Buffer
			cmd := newSSHSessionsTestCmd(context.Background(), &out)

			if err := runSentinelSSHSessionsList(cmd, nil); err != nil {
				t.Fatalf("runSentinelSSHSessionsList: %v", err)
			}

			if tt.wantEmpty {
				if !strings.Contains(out.String(), "No SSH session records found") {
					t.Fatalf("got %q, want the empty-result message", out.String())
				}
				return
			}

			gotOrder := extractSessionPhaseOrder(t, out.String())
			if len(gotOrder) != len(tt.wantOrder) {
				t.Fatalf("got order %v, want %v\nraw output:\n%s", gotOrder, tt.wantOrder, out.String())
			}
			for i := range gotOrder {
				if gotOrder[i] != tt.wantOrder[i] {
					t.Errorf("record %d = %q, want %q", i, gotOrder[i], tt.wantOrder[i])
				}
			}
		})
	}
}

// extractSessionPhaseOrder pulls "session_id/phase" out of either table or
// JSONL output, so the same test body can drive both without knowing which
// format it's reading in the JSON sub-cases.
func extractSessionPhaseOrder(t *testing.T, output string) []string {
	t.Helper()
	lines := strings.Split(strings.TrimRight(output, "\n"), "\n")
	var keys []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "OCCURRED_AT") {
			continue
		}
		if strings.HasPrefix(line, "{") {
			var rec sshsession.Record
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				t.Fatalf("line not valid JSON: %q: %v", line, err)
			}
			keys = append(keys, rec.SessionID+"/"+string(rec.Phase))
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			t.Fatalf("unexpected table line shape: %q", line)
		}
		keys = append(keys, fields[2]+"/"+fields[1])
	}
	return keys
}

func TestRunSentinelSSHSessionsList_JSONOutputRoundTrips(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ssh-sessions.jsonl")
	rec := sshsession.Record{
		SessionID: "sess-json", Phase: sshsession.SessionPhaseOpen,
		OccurredAt: time.Date(2026, 2, 2, 0, 0, 0, 0, time.UTC),
		ClientIP:   "203.0.113.50", Login: "carol", Target: "192.0.2.9:20022",
		AuthMethod: sshsession.AuthMethodCertificate,
	}
	writeSessionJSONL(t, path, rec)

	t.Cleanup(resetSSHSessionsFlags)
	resetSSHSessionsFlags()
	sshSessionsFile = path
	sshSessionsJSON = true

	var out bytes.Buffer
	cmd := newSSHSessionsTestCmd(context.Background(), &out)
	if err := runSentinelSSHSessionsList(cmd, nil); err != nil {
		t.Fatalf("runSentinelSSHSessionsList: %v", err)
	}

	var got sshsession.Record
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &got); err != nil {
		t.Fatalf("output is not a single JSON record: %v\noutput: %s", err, out.String())
	}
	if got.SessionID != rec.SessionID || got.Login != rec.Login {
		t.Errorf("got %+v, want session_id/login matching %+v", got, rec)
	}
}

func TestRunSentinelSSHSessionsList_MissingSinkIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "does-not-exist.jsonl")

	t.Cleanup(resetSSHSessionsFlags)
	resetSSHSessionsFlags()
	sshSessionsFile = path

	var out bytes.Buffer
	cmd := newSSHSessionsTestCmd(context.Background(), &out)
	if err := runSentinelSSHSessionsList(cmd, nil); err != nil {
		t.Fatalf("runSentinelSSHSessionsList: %v", err)
	}
	if !strings.Contains(out.String(), "No SSH session records found") {
		t.Fatalf("got %q, want the empty-result message for a not-yet-created sink", out.String())
	}
}

// TestRunSentinelSSHSessionsFollow_PicksUpAppendedRecord covers
// containarium#2004's `follow` scope item, at the CLI wiring level (the
// underlying tail semantics are covered exhaustively in
// internal/sentinel/sshsession/reader_test.go). Synchronization is a real
// io.Pipe: reading from it blocks until runSentinelSSHSessionsFollow
// actually writes the row, so the assertion never races the goroutine —
// the only sleep here is a generous, non-assertive setup window before the
// append (documented below), matching the pattern already established in
// reader_test.go.
func TestRunSentinelSSHSessionsFollow_PicksUpAppendedRecord(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ssh-sessions.jsonl")
	// Create the sink up front (empty) so Follow's "already exists" open
	// path is used — deterministic and immediate, unlike the
	// wait-for-creation path.
	writeSessionJSONL(t, path)

	origInterval := sshsession.FollowPollInterval
	sshsession.FollowPollInterval = 5 * time.Millisecond
	t.Cleanup(func() { sshsession.FollowPollInterval = origInterval })

	t.Cleanup(resetSSHSessionsFlags)
	resetSSHSessionsFlags()
	sshSessionsFile = path

	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pr.Close(); _ = pw.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cmd := newSSHSessionsTestCmd(ctx, nil)
	cmd.SetOut(pw)

	done := make(chan error, 1)
	go func() { done <- runSentinelSSHSessionsFollow(cmd, nil) }()

	reader := bufio.NewReader(pr)
	header, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read header: %v", err)
	}
	if !strings.HasPrefix(header, "OCCURRED_AT") {
		t.Fatalf("got header %q, want it to start with OCCURRED_AT", header)
	}

	// The header write happens on the main goroutine BEFORE the Follow
	// goroutine is even started, so reading it back proves nothing about
	// whether Follow has opened the sink yet — that open (and the
	// os.Stat that captures the pre-append offset) races the append
	// below. Same bounded, non-assertive setup window used in
	// reader_test.go's own Follow tests: it only affects when the
	// append happens, not the pass/fail assertion, which is the blocking
	// pipe read further down.
	time.Sleep(20 * time.Millisecond)

	writeSessionJSONL(t, path, sshsession.Record{
		SessionID: "sess-follow", Phase: sshsession.SessionPhaseOpen,
		OccurredAt: time.Date(2026, 3, 3, 0, 0, 0, 0, time.UTC),
		ClientIP:   "192.0.2.77", Login: "dave", Target: "198.51.100.9:20022",
	})

	row, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read row: %v", err)
	}
	fields := strings.Fields(row)
	if len(fields) < 4 || fields[1] != "open" || fields[2] != "sess-follow" || fields[3] != "dave" {
		t.Fatalf("got row %q, want phase=open session_id=sess-follow login=dave", row)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runSentinelSSHSessionsFollow returned an error after cancellation: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runSentinelSSHSessionsFollow did not exit after context cancellation")
	}
}
