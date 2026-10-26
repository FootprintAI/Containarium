package backup

import (
	"bytes"
	"errors"
	"io"
	"sync"
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

func (g *gateBox) BoxDiskUsage(string) (int64, error) { return g.usage, nil }

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
	<-gb.entered // the first is past its pre-flight, inside the export

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

	// The claim is released: the box can be backed up again.
	startCreate(m, id.Recipient().String(), "alice", "alice-container", out)
	// Same fixed clock, so the id repeats: that refusal is the id check,
	// not the in-flight one.
	if again := recv(t, out); errors.Is(again.err, ErrBoxBackupInProgress) {
		t.Errorf("the in-flight claim was not released: %v", again.err)
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
	<-gb.entered
	<-gb.entered
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
	<-gb.entered
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
