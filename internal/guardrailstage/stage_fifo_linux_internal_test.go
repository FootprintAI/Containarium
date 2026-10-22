//go:build linux

package guardrailstage

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestSnapshot_FileSwappedForFIFOBeforeOpenDoesNotHang: at the instant
// before a file is opened it becomes a FIFO with no writer. The snapshot
// must finish (skipping it), not block.
func TestSnapshot_FileSwappedForFIFOBeforeOpenDoesNotHang(t *testing.T) {
	area, root := newArea(t)
	target := filepath.Join(root, "tenant", "ds", "mine.txt")
	withHook(t, func(point, name string) {
		if point != hookBeforeOpenFile || name != "mine.txt" {
			return
		}
		if err := os.Remove(target); err != nil {
			t.Error(err)
		}
		if err := syscall.Mkfifo(target, 0o600); err != nil {
			t.Error(err)
		}
	})
	type result struct {
		snap *Snapshot
		err  error
	}
	parent := t.TempDir()
	done := make(chan result, 1)
	go func() {
		s, err := area.Snapshot("tenant/ds", parent)
		done <- result{s, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("Snapshot: %v", r.err)
		}
		if _, err := os.Lstat(filepath.Join(r.snap.Dir, "mine.txt")); err == nil {
			t.Error("the FIFO was copied into the snapshot")
		}
	case <-time.After(10 * time.Second):
		if f, err := os.OpenFile(target, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close() // release the stuck reader
		}
		t.Fatal("Snapshot blocked opening a FIFO")
	}
}
