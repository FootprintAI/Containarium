package sshsession

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeJSONL writes one JSON-encoded record per line to path, creating it
// if needed. Test helper only.
func writeJSONL(t *testing.T, path string, recs ...Record) {
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

func TestReadRecords_FiltersAndParsesInFileOrder(t *testing.T) {
	rec1 := Record{
		SessionID: "sess-1", Phase: SessionPhaseOpen,
		OccurredAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		ClientIP:   "203.0.113.10", Login: "alice",
	}
	rec2 := Record{
		SessionID: "sess-2", Phase: SessionPhaseOpen,
		OccurredAt: time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC),
		ClientIP:   "198.51.100.20", Login: "bob",
	}
	rec3 := Record{
		SessionID: "sess-1", Phase: SessionPhaseClose,
		OccurredAt: time.Date(2026, 1, 1, 0, 2, 0, 0, time.UTC),
		ClientIP:   "203.0.113.10", Login: "alice",
		CloseReason: CloseReasonNormal,
	}

	tests := []struct {
		name   string
		filter Filter
		want   []string // expected SessionID+Phase pairs, in order
	}{
		{
			name:   "no filter returns everything in file order",
			filter: Filter{},
			want:   []string{"sess-1/open", "sess-2/open", "sess-1/close"},
		},
		{
			name:   "filter by session_id",
			filter: Filter{SessionID: "sess-1"},
			want:   []string{"sess-1/open", "sess-1/close"},
		},
		{
			name:   "filter by login",
			filter: Filter{Login: "bob"},
			want:   []string{"sess-2/open"},
		},
		{
			name:   "filter by both session_id and login, no match",
			filter: Filter{SessionID: "sess-1", Login: "bob"},
			want:   nil,
		},
		{
			name:   "filter matching nothing",
			filter: Filter{SessionID: "does-not-exist"},
			want:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			for _, rec := range []Record{rec1, rec2, rec3} {
				line, err := json.Marshal(rec)
				if err != nil {
					t.Fatalf("marshal: %v", err)
				}
				buf.Write(line)
				buf.WriteByte('\n')
			}

			got, err := ReadRecords(&buf, tt.filter)
			if err != nil {
				t.Fatalf("ReadRecords: %v", err)
			}

			gotKeys := make([]string, len(got))
			for i, r := range got {
				gotKeys[i] = r.SessionID + "/" + string(r.Phase)
			}
			if len(gotKeys) != len(tt.want) {
				t.Fatalf("got %v, want %v", gotKeys, tt.want)
			}
			for i := range gotKeys {
				if gotKeys[i] != tt.want[i] {
					t.Errorf("record %d = %q, want %q", i, gotKeys[i], tt.want[i])
				}
			}
		})
	}
}

func TestReadRecords_SkipsBlankLines(t *testing.T) {
	buf := bytes.NewBufferString("\n\n")
	line, _ := json.Marshal(Record{SessionID: "sess-1", Phase: SessionPhaseOpen})
	buf.Write(line)
	buf.WriteString("\n\n")

	got, err := ReadRecords(buf, Filter{})
	if err != nil {
		t.Fatalf("ReadRecords: %v", err)
	}
	if len(got) != 1 || got[0].SessionID != "sess-1" {
		t.Fatalf("got %+v, want one record for sess-1", got)
	}
}

func TestReadRecords_InvalidJSONLineIsAnError(t *testing.T) {
	buf := bytes.NewBufferString("not-json\n")
	if _, err := ReadRecords(buf, Filter{}); err == nil {
		t.Fatal("expected an error for a malformed line, got nil")
	}
}

func TestReadRecordsFile_MissingFileReturnsEmptyNotError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "does-not-exist.jsonl")

	got, err := ReadRecordsFile(path, Filter{})
	if err != nil {
		t.Fatalf("ReadRecordsFile: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d records, want 0", len(got))
	}
}

func TestReadRecordsFile_ReadsWhatWasWritten(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ssh-sessions.jsonl")

	writeJSONL(t, path,
		Record{SessionID: "sess-1", Phase: SessionPhaseOpen, Login: "alice", ClientIP: "203.0.113.10"},
		Record{SessionID: "sess-1", Phase: SessionPhaseClose, Login: "alice", ClientIP: "203.0.113.10"},
	)

	got, err := ReadRecordsFile(path, Filter{})
	if err != nil {
		t.Fatalf("ReadRecordsFile: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d records, want 2", len(got))
	}
}

// TestFollow_PicksUpRecordAppendedAfterStart is the "tail -f" acceptance
// criterion: Follow must observe a record written to the sink AFTER
// following has already begun. Synchronization is entirely through the
// buffered channel Follow sends on — no sleep-then-assert timing
// dependency. FollowPollInterval is dialed down so the test doesn't wait
// through the production polling cadence, but the assertion itself blocks
// on the channel (bounded by a generous safety-net timeout), not on any
// fixed sleep.
func TestFollow_PicksUpRecordAppendedAfterStart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ssh-sessions.jsonl")

	// The file exists with one record before Follow starts; Follow must
	// NOT replay it (that's ReadRecordsFile's job), only report what's
	// appended from here on.
	writeJSONL(t, path, Record{SessionID: "pre-existing", Phase: SessionPhaseOpen})

	origInterval := FollowPollInterval
	FollowPollInterval = 5 * time.Millisecond
	defer func() { FollowPollInterval = origInterval }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := make(chan Record, 8)
	errc := make(chan error, 1)
	go func() { errc <- Follow(ctx, path, Filter{}, out) }()

	// Give Follow a moment to open the file and seek to its current end
	// before we append — otherwise there is no ordering guarantee the
	// open-at-end race requires. This is bounded and only affects when
	// the append happens, not whether the test's assertion succeeds; the
	// actual pass/fail synchronization is the channel receive below.
	time.Sleep(20 * time.Millisecond)

	writeJSONL(t, path, Record{
		SessionID: "sess-new", Phase: SessionPhaseOpen,
		Login: "carol", ClientIP: "192.0.2.44",
	})

	select {
	case rec := <-out:
		if rec.SessionID != "sess-new" {
			t.Fatalf("got session_id %q, want sess-new", rec.SessionID)
		}
		if rec.Login != "carol" {
			t.Fatalf("got login %q, want carol", rec.Login)
		}
	case err := <-errc:
		t.Fatalf("Follow exited early: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Follow to deliver the appended record")
	}

	cancel()
	select {
	case <-errc:
	case <-time.After(5 * time.Second):
		t.Fatal("Follow did not exit after context cancellation")
	}
}

// TestFollow_FiltersByLogin confirms Follow applies the same Filter
// semantics as ReadRecords, not just "everything new".
func TestFollow_FiltersByLogin(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ssh-sessions.jsonl")
	writeJSONL(t, path) // create the (empty) file up front

	origInterval := FollowPollInterval
	FollowPollInterval = 5 * time.Millisecond
	defer func() { FollowPollInterval = origInterval }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := make(chan Record, 8)
	errc := make(chan error, 1)
	go func() { errc <- Follow(ctx, path, Filter{Login: "carol"}, out) }()

	time.Sleep(20 * time.Millisecond)

	writeJSONL(t, path,
		Record{SessionID: "sess-a", Phase: SessionPhaseOpen, Login: "alice", ClientIP: "203.0.113.11"},
		Record{SessionID: "sess-b", Phase: SessionPhaseOpen, Login: "carol", ClientIP: "192.0.2.45"},
	)

	select {
	case rec := <-out:
		if rec.Login != "carol" || rec.SessionID != "sess-b" {
			t.Fatalf("got %+v, want only carol's sess-b record", rec)
		}
	case err := <-errc:
		t.Fatalf("Follow exited early: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the filtered record")
	}

	// Nothing else should arrive — alice's record must have been dropped
	// by the filter, not merely delayed.
	select {
	case rec := <-out:
		t.Fatalf("unexpected extra record delivered: %+v", rec)
	case <-time.After(50 * time.Millisecond):
	}

	cancel()
	// Wait for Follow to actually observe cancellation and return before
	// this test's deferred FollowPollInterval restore runs — otherwise
	// that write can race Follow's own read of the same package var if
	// the goroutine is still between poll ticks (caught by -race).
	select {
	case <-errc:
	case <-time.After(5 * time.Second):
		t.Fatal("Follow did not exit after context cancellation")
	}
}

// TestFollow_WaitsForFileToBeCreated matches `tail -f`'s own behavior on a
// not-yet-existing path: Follow must not error out, it must pick the
// record up once the file (and the plugin process that owns it) appears.
func TestFollow_WaitsForFileToBeCreated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "not-created-yet.jsonl")

	origInterval := FollowPollInterval
	FollowPollInterval = 5 * time.Millisecond
	defer func() { FollowPollInterval = origInterval }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := make(chan Record, 8)
	errc := make(chan error, 1)
	go func() { errc <- Follow(ctx, path, Filter{}, out) }()

	time.Sleep(20 * time.Millisecond)
	writeJSONL(t, path, Record{SessionID: "sess-late", Phase: SessionPhaseOpen})

	select {
	case rec := <-out:
		if rec.SessionID != "sess-late" {
			t.Fatalf("got %q, want sess-late", rec.SessionID)
		}
	case err := <-errc:
		t.Fatalf("Follow exited early: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Follow to notice the newly created file")
	}

	cancel()
	// Wait for Follow to actually observe cancellation and return before
	// this test's deferred FollowPollInterval restore runs — otherwise
	// that write can race Follow's own read of the same package var if
	// the goroutine is still between poll ticks (caught by -race).
	select {
	case <-errc:
	case <-time.After(5 * time.Second):
		t.Fatal("Follow did not exit after context cancellation")
	}
}
