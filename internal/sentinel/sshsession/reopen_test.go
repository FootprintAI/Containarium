//go:build !windows

package sshsession

import (
	"bytes"
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// #2415 — logrotate (create mode) renames the sink; the plugin must follow
// the PATH again on SIGHUP, or it keeps appending to the rotated file.

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestJSONLRecorder_ReopenFollowsThePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssh-sessions.jsonl")
	rec, err := NewJSONLFileRecorder(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rec.Close() }()

	at := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	if err := rec.Record(Record{SessionID: "before", Phase: SessionPhaseOpen, OccurredAt: at}); err != nil {
		t.Fatal(err)
	}

	// logrotate: rename, then (create mode) a fresh empty file at the path.
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := rec.Reopen(); err != nil {
		t.Fatalf("Reopen: %v", err)
	}
	if err := rec.Record(Record{SessionID: "after", Phase: SessionPhaseOpen, OccurredAt: at}); err != nil {
		t.Fatal(err)
	}

	if old := readFile(t, path+".1"); !strings.Contains(old, `"before"`) || strings.Contains(old, `"after"`) {
		t.Fatalf("rotated file must hold only pre-rotation records, got %q", old)
	}
	if cur := readFile(t, path); !strings.Contains(cur, `"after"`) || strings.Contains(cur, `"before"`) {
		t.Fatalf("new file must hold only post-rotation records, got %q", cur)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("reopened sink mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestJSONLRecorder_ReopenWithoutFileIsNoOp(t *testing.T) {
	var buf bytes.Buffer
	rec := NewJSONLRecorder(&buf)
	if err := rec.Reopen(); err != nil {
		t.Fatalf("a writer-backed recorder has nothing to reopen: %v", err)
	}
	if err := rec.Record(Record{SessionID: "x", Phase: SessionPhaseOpen}); err != nil || buf.Len() == 0 {
		t.Fatalf("recorder must keep writing after a no-op Reopen: %v", err)
	}
}

// A failed reopen must leave the old handle in place: losing records is
// worse than writing them to the rotated file.
func TestJSONLRecorder_FailedReopenKeepsWriting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "ssh-sessions.jsonl")
	rec, err := NewJSONLFileRecorder(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rec.Close() }()
	// Make the path unopenable: replace its directory with a plain file.
	if err := os.Rename(filepath.Join(dir, "sub"), filepath.Join(dir, "sub.moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rec.Reopen(); err == nil {
		t.Fatal("reopen into an unopenable path must error")
	}
	if err := rec.Record(Record{SessionID: "still-written", Phase: SessionPhaseOpen}); err != nil {
		t.Fatalf("recorder must keep its old handle after a failed reopen: %v", err)
	}
	if got := readFile(t, filepath.Join(dir, "sub.moved", "ssh-sessions.jsonl")); !strings.Contains(got, "still-written") {
		t.Fatalf("record lost: %q", got)
	}
}

func TestJSONLRecorder_ReopenConcurrentWithRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.jsonl")
	rec, err := NewJSONLFileRecorder(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rec.Close() }()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = rec.Record(Record{SessionID: "c", Phase: SessionPhaseOpen})
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 20; j++ {
			_ = rec.Reopen()
		}
	}()
	wg.Wait()
	if n := strings.Count(readFile(t, path), "\n"); n != 200 {
		t.Fatalf("lines = %d, want 200 (no record lost or torn across reopens)", n)
	}
}

type fakeReopener struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (f *fakeReopener) Reopen() error { f.mu.Lock(); defer f.mu.Unlock(); f.calls++; return f.err }
func (f *fakeReopener) n() int        { f.mu.Lock(); defer f.mu.Unlock(); return f.calls }

func TestReopenOn_ReopensPerSignalUntilCancelled(t *testing.T) {
	r := &fakeReopener{}
	sigs := make(chan os.Signal, 2)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var logs []string
	go func() {
		ReopenOn(ctx, sigs, r, func(f string, a ...any) { logs = append(logs, f) })
		close(done)
	}()

	sigs <- syscall.SIGHUP
	sigs <- syscall.SIGHUP
	deadline := time.After(2 * time.Second)
	for r.n() < 2 {
		select {
		case <-deadline:
			t.Fatalf("calls = %d, want 2", r.n())
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ReopenOn must return when ctx is cancelled")
	}
}

func TestReopenOn_ErrorIsLoggedNotFatal(t *testing.T) {
	r := &fakeReopener{err: os.ErrPermission}
	sigs := make(chan os.Signal, 1)
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	var logs []string
	done := make(chan struct{})
	go func() {
		ReopenOn(ctx, sigs, r, func(f string, a ...any) { mu.Lock(); logs = append(logs, f); mu.Unlock() })
		close(done)
	}()
	sigs <- syscall.SIGHUP
	for i := 0; i < 200 && r.n() == 0; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	mu.Lock()
	defer mu.Unlock()
	if len(logs) == 0 {
		t.Fatal("a failed reopen must be logged")
	}
}

// The real signal path, end to end in-process: SIGHUP -> ReopenOn -> the
// recorder follows the path. This is what logrotate's postrotate triggers.
func TestReopenOn_RealSIGHUPMovesTheSink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.jsonl")
	rec, err := NewJSONLFileRecorder(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rec.Close() }()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGHUP)
	defer signal.Stop(sigs)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ReopenOn(ctx, sigs, rec, func(string, ...any) {})

	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			break // the reopen recreated the sink at the path
		}
		if time.Now().After(deadline) {
			t.Fatal("SIGHUP did not make the recorder recreate the sink at its path")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := rec.Record(Record{SessionID: "post-hup", Phase: SessionPhaseOpen}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(readFile(t, path), "post-hup") {
		t.Fatal("record after SIGHUP must land in the new file")
	}
}
