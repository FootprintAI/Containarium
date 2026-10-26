package backup

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"
)

// gateBox is a BoxOps whose export blocks until released, so a test can hold
// one backup in flight while it starts another. It is safe for concurrent
// use.
type gateBox struct {
	archive []byte
	usage   int64
	usages  map[string]int64 // per-box override of usage

	entered chan string   // receives the box name when an export starts
	release chan struct{} // closed to let every export proceed

	mu       sync.Mutex
	exported []string
}

func newGateBox(archive []byte, usage int64) *gateBox {
	return &gateBox{archive: archive, usage: usage, entered: make(chan string, 16), release: make(chan struct{})}
}

func (g *gateBox) ExportInstance(name string) (io.ReadCloser, error) {
	g.mu.Lock()
	g.exported = append(g.exported, name)
	g.mu.Unlock()
	g.entered <- name
	<-g.release
	return io.NopCloser(bytes.NewReader(g.archive)), nil
}

func (g *gateBox) BoxDiskUsage(name string) (int64, error) {
	if u, ok := g.usages[name]; ok {
		return u, nil
	}
	return g.usage, nil
}

func (g *gateBox) exports() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.exported...)
}

// recv waits for a result, failing instead of hanging when a backup that
// should have been refused is stuck in the gated export.
func recv(t *testing.T, out <-chan createResult) createResult {
	t.Helper()
	select {
	case r := <-out:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("no result in 5s: a backup that should have been refused is running")
		return createResult{}
	}
}

// enter waits for a backup to reach its export, failing instead of hanging
// when one that should have been admitted was refused.
func enter(t *testing.T, gb *gateBox) {
	t.Helper()
	select {
	case <-gb.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("no backup reached its export in 5s")
	}
}

type createResult struct {
	box string
	err error
}

// startCreate runs a CreateBox for user/box in a goroutine.
func startCreate(m *Manager, recipient, user, box string, out chan<- createResult) {
	go func() {
		o := boxOpts(recipient)
		o.Username, o.ContainerName = user, box
		_, err := m.CreateBox(o)
		out <- createResult{box: box, err: err}
	}()
}

// #3116: two creates for the same box, on a filesystem with room for one
// copy. The second must be refused as in progress, not pass the same
// free-space check as the first. Exactly one succeeds.
func TestCreateBox_SameBoxConcurrentSecondIsRefused(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	const usage = 100 << 20
	gb := newGateBox(buildArchive(t, incusLikeEntries()), usage)
	// Room for exactly one backup: each check, taken alone, passes.
	m := newBoxManager(t, gb, withFreeSpace(func(string) (diskSpace, error) {
		return diskSpace{Free: usage + 1<<20, Device: 1}, nil
	}))
	out := make(chan createResult, 2)

	startCreate(m, id.Recipient().String(), "alice", "alice-container", out)
	enter(t, gb) // the first is past its pre-flight, inside the export

	startCreate(m, id.Recipient().String(), "alice", "alice-container", out)
	second := recv(t, out)
	if !errors.Is(second.err, ErrBoxBackupInProgress) {
		t.Fatalf("second concurrent backup of the same box: err = %v, want ErrBoxBackupInProgress", second.err)
	}
	close(gb.release)
	first := recv(t, out)
	if first.err != nil {
		t.Fatalf("first backup: %v", first.err)
	}
	if got := gb.exports(); len(got) != 1 {
		t.Errorf("exports = %v, want exactly one", got)
	}

	// The claim is released: the box can be backed up again. A later clock
	// gives the second backup a new id, so it reaches the claim instead of
	// stopping at the "backup already exists" check.
	m.clock = func() time.Time { return fixedClock().Add(time.Hour) }
	startCreate(m, id.Recipient().String(), "alice", "alice-container", out)
	if again := recv(t, out); again.err != nil {
		t.Errorf("a third backup after the first finished: %v", again.err)
	}
}

// A failed backup releases its claim too.
func TestCreateBox_FailedBackupReleasesClaim(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	box := newFakeBox(nil)
	box.exportErr = errors.New("export refused")
	m := newBoxManager(t, box)
	for i := 0; i < 2; i++ {
		_, err := m.CreateBox(boxOpts(id.Recipient().String()))
		if err == nil || errors.Is(err, ErrBoxBackupInProgress) {
			t.Fatalf("attempt %d: err = %v, want the export error", i, err)
		}
	}
}

// Different boxes run concurrently when the filesystem has room for both.
func TestCreateBox_DifferentBoxesRunConcurrently(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	const usage = 100 << 20
	gb := newGateBox(buildArchive(t, incusLikeEntries()), usage)
	m := newBoxManager(t, gb, withFreeSpace(func(string) (diskSpace, error) {
		return diskSpace{Free: 4 * usage, Device: 1}, nil
	}))
	out := make(chan createResult, 2)
	startCreate(m, id.Recipient().String(), "alice", "alice-container", out)
	startCreate(m, id.Recipient().String(), "bob", "bob-container", out)
	// Both reach the export while neither has finished.
	enter(t, gb)
	enter(t, gb)
	close(gb.release)
	for i := 0; i < 2; i++ {
		if r := recv(t, out); r.err != nil {
			t.Errorf("backup of %s: %v", r.box, r.err)
		}
	}
}

// The cross-box case: two different boxes share a backup directory with room
// for one. The first reserves its space, so the second is refused for space
// rather than both passing the same statfs reading.
func TestCreateBox_DifferentBoxesShareReservedSpace(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	const usage = 100 << 20
	gb := newGateBox(buildArchive(t, incusLikeEntries()), usage)
	m := newBoxManager(t, gb, withFreeSpace(func(string) (diskSpace, error) {
		return diskSpace{Free: usage + 1<<20, Device: 1}, nil
	}))
	out := make(chan createResult, 2)
	startCreate(m, id.Recipient().String(), "alice", "alice-container", out)
	enter(t, gb)
	startCreate(m, id.Recipient().String(), "bob", "bob-container", out)
	second := recv(t, out)
	if !errors.Is(second.err, ErrInsufficientSpace) {
		t.Fatalf("second box: err = %v, want ErrInsufficientSpace", second.err)
	}
	close(gb.release)
	if first := recv(t, out); first.err != nil {
		t.Fatalf("first box: %v", first.err)
	}
	// With the first finished, its reservation is gone.
	gb2 := newGateBox(buildArchive(t, incusLikeEntries()), usage)
	close(gb2.release)
	m.box = gb2
	o := boxOpts(id.Recipient().String())
	o.Username, o.ContainerName = "bob", "bob-container"
	if _, err := m.CreateBox(o); err != nil {
		t.Errorf("after the first finished: %v", err)
	}
}

// The reservation of a running backup shrinks as the backup writes: statfs
// already excludes the bytes it has written, so counting its full estimate
// again would refuse a backup that fits. Free space here drops as the first
// backup "writes".
func TestCreateBox_ReservationCreditsBytesAlreadyWritten(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	const usage = 100 << 20
	for _, tc := range []struct {
		name      string
		startFree uint64
		wantErr   bool
	}{
		// 205 free, 10 written: 195 free; A still holds 90, B needs 100.
		// Counting A's full 100 would refuse (200 > 195).
		{"fits once written bytes are credited", 205 << 20, false},
		// 185 free, 10 written: 175 free; 90 + 100 > 175.
		{"does not fit even with the credit", 185 << 20, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gb := newGateBox(buildArchive(t, incusLikeEntries()), usage)
			var free atomic.Uint64
			free.Store(tc.startFree)
			m := newBoxManager(t, gb, withFreeSpace(func(string) (diskSpace, error) {
				return diskSpace{Free: free.Load(), Device: 1}, nil
			}))
			out := make(chan createResult, 2)
			startCreate(m, id.Recipient().String(), "alice", "alice-container", out)
			enter(t, gb)
			free.Add(^uint64(10<<20 - 1)) // the first backup writes 10 MiB
			startCreate(m, id.Recipient().String(), "bob", "bob-container", out)
			if tc.wantErr {
				if r := recv(t, out); !errors.Is(r.err, ErrInsufficientSpace) {
					t.Fatalf("second box: err = %v, want ErrInsufficientSpace", r.err)
				}
				close(gb.release)
				if r := recv(t, out); r.err != nil {
					t.Fatalf("first box: %v", r.err)
				}
				return
			}
			enter(t, gb) // admitted: it reached its export
			close(gb.release)
			for i := 0; i < 2; i++ {
				if r := recv(t, out); r.err != nil {
					t.Errorf("backup of %s: %v", r.box, r.err)
				}
			}
		})
	}
}

// Reservations on different filesystems are independent: the first box holds
// 100 MiB on each device, and a 40 MiB box fits beside it on both even
// though 140 + 100 would not fit if the devices were pooled.
func TestCreateBox_ReservationsPerDeviceAreIndependent(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	gb := newGateBox(buildArchive(t, incusLikeEntries()), 100<<20)
	gb.usages = map[string]int64{"bob-container": 40 << 20}
	incusDir := t.TempDir()
	var m *Manager
	m = newBoxManager(t, gb, WithBoxStagingDirs(incusDir), withFreeSpace(func(p string) (diskSpace, error) {
		if p == m.dir {
			return diskSpace{Free: 150 << 20, Device: 1}, nil
		}
		return diskSpace{Free: 150 << 20, Device: 2}, nil
	}))
	out := make(chan createResult, 2)
	startCreate(m, id.Recipient().String(), "alice", "alice-container", out)
	enter(t, gb)
	startCreate(m, id.Recipient().String(), "bob", "bob-container", out)
	enter(t, gb)
	close(gb.release)
	for i := 0; i < 2; i++ {
		if r := recv(t, out); r.err != nil {
			t.Errorf("backup of %s: %v", r.box, r.err)
		}
	}
}

// The release func is idempotent, and a late second call from a finished
// backup must not drop a later backup's claim on the same box.
func TestCreateBox_ReleaseIsOnceAndTokenScoped(t *testing.T) {
	gb := newGateBox(nil, 1<<20)
	m := newBoxManager(t, gb)
	rel1, err := m.boxPreflight("alice-container")
	if err != nil {
		t.Fatal(err)
	}
	rel1()
	rel2, err := m.boxPreflight("alice-container")
	if err != nil {
		t.Fatalf("claim after release: %v", err)
	}
	rel1() // late double call from the first backup
	if _, err := m.boxPreflight("alice-container"); !errors.Is(err, ErrBoxBackupInProgress) {
		t.Fatalf("after a late release by the first backup the second's claim is gone: err = %v", err)
	}
	rel2()
	rel2()
	rel3, err := m.boxPreflight("alice-container")
	if err != nil {
		t.Fatalf("claim after the second release: %v", err)
	}
	rel3()
}
