package backup

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"strings"
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

// #3116 safety: free space that drops because ANOTHER process writes must
// never reduce what a running backup holds. A reserves 100 of 200 free and
// has written nothing; an unrelated process then writes 100 (free = 100).
// B (needs 100) must be refused: admitting it would commit 200 on 100 free.
func TestCreateBox_ForeignWritesAreNotCreditedToARunningBackup(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	const usage = 100 << 20
	gb := newGateBox(buildArchive(t, incusLikeEntries()), usage)
	var free atomic.Uint64
	free.Store(200 << 20)
	m := newBoxManager(t, gb, withFreeSpace(func(string) (diskSpace, error) {
		return diskSpace{Free: free.Load(), Device: 1}, nil
	}))
	out := make(chan createResult, 2)
	startCreate(m, id.Recipient().String(), "alice", "alice-container", out)
	enter(t, gb)
	free.Store(100 << 20) // a foreign writer takes 100 MiB
	startCreate(m, id.Recipient().String(), "bob", "bob-container", out)
	if r := recv(t, out); !errors.Is(r.err, ErrInsufficientSpace) {
		t.Fatalf("second box: err = %v, want ErrInsufficientSpace", r.err)
	}
	close(gb.release)
	if r := recv(t, out); r.err != nil {
		t.Fatalf("first box: %v", r.err)
	}
}

// The safety invariant, over many random interleavings run through the real
// pre-flight: right after each admission, free space covers the unwritten
// remainder of every backup in flight. Backups write (free drops by what
// they write, up to their estimate), foreign processes write, backups end.
func TestBoxPreflight_NeverOverAdmits(t *testing.T) {
	for seed := uint64(1); seed <= 500; seed++ {
		rng := mrand.New(mrand.NewPCG(seed, seed*7919))
		free := (100 + rng.Uint64N(400)) << 20
		type run struct {
			release       func()
			need, written uint64
		}
		runs := map[string]*run{}
		usages := map[string]int64{}
		need := map[string]uint64{}
		names := []string{"b0", "b1", "b2", "b3"}
		for _, n := range names {
			mib := 20 + rng.Uint64N(150)
			need[n] = mib << 20
			usages[n] = int64(need[n]) // #nosec G115 -- at most 170 MiB
		}
		gb := newGateBox(nil, 0)
		gb.usages = usages
		m := newBoxManager(t, gb, withFreeSpace(func(string) (diskSpace, error) {
			return diskSpace{Free: free, Device: 1}, nil
		}))
		for step := 0; step < 60; step++ {
			switch rng.IntN(4) {
			case 0: // try to start a backup
				n := names[rng.IntN(len(names))]
				rel, err := m.boxPreflight(n)
				if err != nil {
					continue
				}
				runs[n] = &run{release: rel, need: need[n]}
				var remaining uint64
				for _, r := range runs {
					remaining += r.need - r.written
				}
				if free < remaining {
					t.Fatalf("seed %d step %d: admitted %s with %d free but %d still to be written", seed, step, n, free, remaining)
				}
			case 1: // an in-flight backup writes
				for _, r := range runs {
					w := min(rng.Uint64N(40)<<20, r.need-r.written, free)
					r.written += w
					free -= w
					break
				}
			case 2: // a foreign process writes
				free -= min(rng.Uint64N(60)<<20, free)
			case 3: // a backup ends; its written bytes stay on disk
				for n, r := range runs {
					r.release()
					delete(runs, n)
					break
				}
			}
		}
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

// A repeated or late release from a finished backup must not drop a later
// backup's claim on the same box.
func TestCreateBox_ReleaseIsClaimScoped(t *testing.T) {
	gb := newGateBox(nil, 1<<20)
	m := newBoxManager(t, gb)
	rel1, err := m.boxPreflight("alice-container")
	if err != nil {
		t.Fatal(err)
	}
	stale := m.boxClaims.inFlight["alice-container"]
	rel1()
	rel1() // a repeated call
	rel2, err := m.boxPreflight("alice-container")
	if err != nil {
		t.Fatalf("claim after release: %v", err)
	}
	rel1()                   // a late call by the first backup
	m.releaseBoxClaim(stale) // and the helper itself, with the stale claim
	if _, err := m.boxPreflight("alice-container"); !errors.Is(err, ErrBoxBackupInProgress) {
		t.Fatalf("a stale release dropped the second backup's claim: err = %v", err)
	}
	rel2()
	rel3, err := m.boxPreflight("alice-container")
	if err != nil {
		t.Fatalf("claim after the second release: %v", err)
	}
	rel3()
}

// #3126 with #3116: whole-box backups of different boxes run concurrently,
// and every one sweeps stale spill files before it starts. The sweep of the
// second must never delete the spill file of the first, even when that file
// looks old (mtime past the stale age), because the first is still running.
// Only the in-flight registration can save it here.
func TestCreateBox_ConcurrentBackupSweepSparesInFlightSpill(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	const usage = 100 << 20
	gb := newGateBox(buildArchive(t, incusLikeEntries()), usage)
	m := newBoxManager(t, gb, withFreeSpace(func(string) (diskSpace, error) {
		return diskSpace{Free: 4 * usage, Device: 1}, nil
	}))
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	out := make(chan createResult, 2)
	startCreate(m, id.Recipient().String(), "alice", "alice-container", out)
	enter(t, gb) // the first backup is in flight

	// The first backup's spill: open (registered) but with an old mtime.
	inFlight := &boxSpill{dir: m.dir}
	if err := inFlight.add("a", &tar.Header{Name: "a", Size: 1}, strings.NewReader("x")); err != nil {
		t.Fatal(err)
	}
	defer inFlight.close()
	touchOld(t, inFlight.f.Name(), 72*time.Hour)
	// A genuine leftover beside it, which the sweep must still remove.
	dead := filepath.Join(m.dir, ".box-spill-dead.tmp")
	writeFile(t, dead, "leftover")
	touchOld(t, dead, 72*time.Hour)

	startCreate(m, id.Recipient().String(), "bob", "bob-container", out)
	enter(t, gb) // the second passed its sweep and pre-flight

	if _, err := os.Stat(inFlight.f.Name()); err != nil {
		t.Errorf("a concurrent backup's sweep removed an in-flight spill: %v", err)
	}
	if _, err := os.Lstat(dead); !os.IsNotExist(err) {
		t.Errorf("the dead spill survived the second backup's sweep: %v", err)
	}
	close(gb.release)
	for i := 0; i < 2; i++ {
		if r := recv(t, out); r.err != nil {
			t.Errorf("backup of %s: %v", r.box, r.err)
		}
	}
}
