//go:build linux

package guardrailstage_test

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/footprintai/containarium/internal/guardrailstage"
)

// exchangeLoop atomically swaps a and b (renameat2 RENAME_EXCHANGE) until
// stop is closed. Every instant, one of the two names is the real entry and
// the other is the swapped-in one, which is the race an attacker with write
// access to their own staging directory can run.
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

// TestSnapshot_RaceSwappingTheRefForASymlinkNeverReadsAnotherTenant: while
// tenant/ds is swapped back and forth with a symlink to another tenant's
// directory INSIDE the root, no successful snapshot may ever hold the
// other tenant's data. (os.Root alone follows such a symlink; the
// package's no-symlink rule must hold under a race, not only statically.)
func TestSnapshot_RaceSwappingTheRefForASymlinkNeverReadsAnotherTenant(t *testing.T) {
	root := filepath.Join(t.TempDir(), "staging")
	write(t, filepath.Join(root, "tenant", "ds", "mine.txt"), "mine\n")
	write(t, filepath.Join(root, "other", "ds", "theirs.txt"), "another tenant's data\n")
	if err := os.Symlink(filepath.Join("..", "other", "ds"), filepath.Join(root, "tenant", "lnk")); err != nil {
		t.Fatal(err)
	}
	area, err := guardrailstage.New(root)
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	exchangeLoop(t, filepath.Join(root, "tenant", "ds"), filepath.Join(root, "tenant", "lnk"), stop, &wg)
	defer func() { close(stop); wg.Wait() }()

	parent := t.TempDir()
	var ok, leaked int
	for i := 0; i < 3000; i++ {
		snap, err := area.Snapshot("tenant/ds", parent)
		if err != nil {
			continue // refused mid-swap: correct
		}
		ok++
		if _, err := os.Lstat(filepath.Join(snap.Dir, "theirs.txt")); err == nil {
			leaked++
		}
		if err := snap.Remove(); err != nil {
			t.Fatal(err)
		}
	}
	if leaked > 0 {
		t.Fatalf("%d of %d successful snapshots read the other tenant's directory", leaked, ok)
	}
	t.Logf("%d successful snapshots, none crossed tenants", ok)
}

// TestSnapshot_RaceSwappingAFileForAFIFONeverHangs: a regular file swapped
// for a FIFO between the walk's type check and the open must not block the
// snapshot (a synchronous DeployRecipe would hang with it).
func TestSnapshot_RaceSwappingAFileForAFIFONeverHangs(t *testing.T) {
	root := filepath.Join(t.TempDir(), "staging")
	ds := filepath.Join(root, "tenant", "ds")
	write(t, filepath.Join(ds, "a.txt"), "alpha\n")
	if err := unix.Mkfifo(filepath.Join(ds, "pipe"), 0o600); err != nil {
		t.Fatal(err)
	}
	area, err := guardrailstage.New(root)
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	exchangeLoop(t, filepath.Join(ds, "a.txt"), filepath.Join(ds, "pipe"), stop, &wg)
	defer func() { close(stop); wg.Wait() }()

	parent := t.TempDir()
	var done atomic.Int64
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		for i := 0; i < 3000; i++ {
			if snap, err := area.Snapshot("tenant/ds", parent); err == nil {
				_ = snap.Remove()
			}
			done.Add(1)
		}
	}()
	select {
	case <-finished:
	case <-time.After(20 * time.Second):
		// Unblock a reader stuck on the FIFO so the test binary can exit.
		for _, p := range []string{"a.txt", "pipe"} {
			if f, err := os.OpenFile(filepath.Join(ds, p), os.O_WRONLY|unix.O_NONBLOCK, 0); err == nil {
				_ = f.Close()
			}
		}
		t.Fatalf("Snapshot hung on a FIFO after %d iterations", done.Load())
	}
}
