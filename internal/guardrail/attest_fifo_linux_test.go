//go:build linux

package guardrail

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// exchangeLoop atomically swaps a and b (renameat2 RENAME_EXCHANGE) until
// stop is closed — the same race Stage's FIFO test exercises.
func exchangeLoop(t *testing.T, a, b string, stop <-chan struct{}, wg *sync.WaitGroup) {
	t.Helper()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if err := unix.Renameat2(unix.AT_FDCWD, a, unix.AT_FDCWD, b, unix.RENAME_EXCHANGE); err != nil {
				t.Errorf("renameat2: %v", err)
				return
			}
		}
	}()
}

// TestSubjectDigest_RaceSwappingAFileForAFIFONeverHangs: a regular file
// swapped for a FIFO between the walk's type check and the open must not
// block SubjectDigest (#2480).
func TestSubjectDigest_RaceSwappingAFileForAFIFONeverHangs(t *testing.T) {
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "a.txt"), []byte("alpha\n"), 0o644))
	if err := unix.Mkfifo(filepath.Join(dir, "pipe"), 0o600); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	exchangeLoop(t, filepath.Join(dir, "a.txt"), filepath.Join(dir, "pipe"), stop, &wg)
	defer func() { close(stop); wg.Wait() }()

	var done atomic.Int64
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		for i := 0; i < 3000; i++ {
			if _, err := SubjectDigest(dir); err == nil {
				done.Add(1)
			} else {
				done.Add(1) // errors mid-swap are fine; hanging is not
			}
		}
	}()
	select {
	case <-finished:
	case <-time.After(20 * time.Second):
		for _, p := range []string{"a.txt", "pipe"} {
			if f, err := os.OpenFile(filepath.Join(dir, p), os.O_WRONLY|unix.O_NONBLOCK, 0); err == nil {
				_ = f.Close()
			}
		}
		t.Fatalf("SubjectDigest hung on a FIFO after %d iterations", done.Load())
	}
}

// TestSubjectDigest_UnchangedTreeStableAcrossFix: digests of a quiet tree
// stay byte-identical (acceptance #2480).
func TestSubjectDigest_UnchangedTreeStableAcrossFix(t *testing.T) {
	dir := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(dir, "sub"), 0o755))
	must(t, os.WriteFile(filepath.Join(dir, "b.txt"), []byte("bee"), 0o644))
	must(t, os.WriteFile(filepath.Join(dir, "sub", "a.txt"), []byte("ay"), 0o644))
	d1, err := SubjectDigest(dir)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := SubjectDigest(dir)
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 {
		t.Fatalf("digest not stable: %s vs %s", d1, d2)
	}
}
