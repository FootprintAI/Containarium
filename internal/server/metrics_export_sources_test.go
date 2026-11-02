package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/metrics/cloudexport"
	"github.com/footprintai/containarium/pkg/core/backup"
)

// writeSidecarForTest fabricates a backup index entry directly on disk,
// bypassing Manager.Create (which needs a working ContainerOps fake this
// test has no reason to build) — backup.Record is exported with the
// exact JSON shape Manager.List reads back, so this is just as real a
// fixture as one Create would have produced.
func writeSidecarForTest(t *testing.T, dir, id, username string, createdAt time.Time) {
	t.Helper()
	rec := backup.Record{ID: id, Username: username, Database: "app", CreatedAt: createdAt}
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, id+".meta.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// OSS #2294: serverPlatformSources.BackupHealth is the production seam
// between the daemon's backup core and the metrics-export collector.
// Nil-safe when no backup Manager is wired, same posture as
// APIStats/ProvisionStats/Peers above it; delegates correctly when one
// is.
func TestServerPlatformSources_BackupHealth_NilManagerIsSafe(t *testing.T) {
	var s serverPlatformSources // zero value: backupMgr is nil
	got := s.BackupHealth()
	if got != nil {
		t.Errorf("got %+v, want nil with no backup Manager wired", got)
	}
}

func TestServerPlatformSources_BackupHealth_DelegatesToManager(t *testing.T) {
	dir := t.TempDir()
	mgr := backup.NewManager(nil, nil, dir)

	alice := time.Date(2026, 10, 5, 2, 0, 0, 0, time.UTC)
	bob := time.Date(2026, 10, 4, 2, 0, 0, 0, time.UTC)
	writeSidecarForTest(t, dir, "alice-app-20261005T020000Z", "alice", alice)
	writeSidecarForTest(t, dir, "bob-app-20261004T020000Z", "bob", bob)

	s := serverPlatformSources{backupMgr: mgr}
	got := s.BackupHealth()

	byUser := map[string]cloudexport.BackupHealthState{}
	for _, st := range got {
		byUser[st.Username] = st
	}
	if len(byUser) != 2 {
		t.Fatalf("got %d tenants, want 2: %+v", len(byUser), got)
	}
	if !byUser["alice"].LastSuccessAt.Equal(alice) {
		t.Errorf("alice.LastSuccessAt = %v, want %v", byUser["alice"].LastSuccessAt, alice)
	}
	if !byUser["bob"].LastSuccessAt.Equal(bob) {
		t.Errorf("bob.LastSuccessAt = %v, want %v", byUser["bob"].LastSuccessAt, bob)
	}
}

// A backup directory that does not exist yet (e.g. this daemon host has
// never run a backup) must degrade to an empty snapshot, same as
// backup.Manager.List itself does — not an error that skips the whole
// export tick over something this unremarkable.
func TestServerPlatformSources_BackupHealth_MissingDirIsEmptyNotError(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "never-created")
	mgr := backup.NewManager(nil, nil, dir)
	s := serverPlatformSources{backupMgr: mgr}
	got := s.BackupHealth()
	if len(got) != 0 {
		t.Errorf("got %+v, want empty", got)
	}
}

// #2305: a persistent read failure must be visible. The age series goes
// empty on failure (same as "no backups"), so the failure counter is the
// only distinguishing signal: it advances once per failed tick and does not
// move while reads succeed.
func TestServerPlatformSources_BackupHealth_ReadFailureIsCounted(t *testing.T) {
	good := t.TempDir()
	writeSidecarForTest(t, good, "alice-app-20261005T020000Z", "alice", time.Date(2026, 10, 5, 2, 0, 0, 0, time.UTC))

	// A backup "directory" whose parent is a regular file cannot be read
	// (ENOTDIR), unlike a merely-missing one, which List treats as empty.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(blocker, "backups")

	counter := new(atomic.Int64)
	healthy := serverPlatformSources{backupMgr: backup.NewManager(nil, nil, good), backupReadFailures: counter}
	broken := serverPlatformSources{backupMgr: backup.NewManager(nil, nil, bad), backupReadFailures: counter}

	if got := healthy.BackupHealth(); len(got) != 1 {
		t.Fatalf("healthy read = %+v, want 1 tenant", got)
	}
	if n := healthy.BackupHealthReadFailures(); n != 0 {
		t.Fatalf("failures after a healthy read = %d, want 0", n)
	}
	for i := 1; i <= 3; i++ {
		if got := broken.BackupHealth(); len(got) != 0 {
			t.Fatalf("broken read returned %+v, want empty", got)
		}
		if n := broken.BackupHealthReadFailures(); n != int64(i) {
			t.Fatalf("failures after %d broken reads = %d, want %d", i, n, i)
		}
	}
	if got := healthy.BackupHealth(); len(got) != 1 {
		t.Fatalf("recovered read = %+v, want 1 tenant", got)
	}
	if n := healthy.BackupHealthReadFailures(); n != 3 {
		t.Errorf("cumulative failures after recovery = %d, want 3 (a counter never decreases)", n)
	}
}

func TestServerPlatformSources_BackupHealthReadFailures_NilCounterIsSafe(t *testing.T) {
	var s serverPlatformSources
	if n := s.BackupHealthReadFailures(); n != 0 {
		t.Errorf("zero-value adapter reports %d failures, want 0", n)
	}
}

// OSS #3234: a tenant whose container is gone (moved to another host or
// deleted) must stop exporting a growing-age ghost series, while a tenant
// whose container exists keeps its age even when its backups are stale
// (the #2294 case) — and none of this may touch the stored files or the
// read-failure counter.
func liveSet(names ...string) func() (map[string]struct{}, error) {
	return func() (map[string]struct{}, error) {
		m := make(map[string]struct{}, len(names))
		for _, n := range names {
			m[n] = struct{}{}
		}
		return m, nil
	}
}

func TestServerPlatformSources_BackupHealth_SkipsTenantsWithoutContainer(t *testing.T) {
	dir := t.TempDir()
	mgr := backup.NewManager(nil, nil, dir)
	stale := time.Date(2026, 9, 1, 2, 0, 0, 0, time.UTC)
	writeSidecarForTest(t, dir, "alice-app-20260901T020000Z", "alice", stale) // live, long stale
	writeSidecarForTest(t, dir, "bob-app-20260901T020000Z", "bob", stale)     // removed

	counter := new(atomic.Int64)
	s := serverPlatformSources{backupMgr: mgr, backupReadFailures: counter, liveContainers: liveSet("alice-container")}

	got := s.BackupHealth()
	if len(got) != 1 || got[0].Username != "alice" || !got[0].LastSuccessAt.Equal(stale) {
		t.Fatalf("got %+v, want only alice (live and stale) with her real timestamp", got)
	}
	if n := s.BackupHealthReadFailures(); n != 0 {
		t.Errorf("health_read_failures = %d, want 0 (skipping a ghost is not a read failure)", n)
	}
	if _, err := os.Stat(filepath.Join(dir, "bob-app-20260901T020000Z.meta.json")); err != nil {
		t.Errorf("stored index entry for removed tenant was touched: %v", err)
	}
}

func TestServerPlatformSources_BackupHealth_RemovedTenantDropsOnNextTick(t *testing.T) {
	dir := t.TempDir()
	mgr := backup.NewManager(nil, nil, dir)
	at := time.Date(2026, 10, 5, 2, 0, 0, 0, time.UTC)
	writeSidecarForTest(t, dir, "alice-app-20261005T020000Z", "alice", at)
	writeSidecarForTest(t, dir, "bob-app-20261005T020000Z", "bob", at)

	live := map[string]struct{}{"alice-container": {}, "bob-container": {}}
	s := serverPlatformSources{backupMgr: mgr, liveContainers: func() (map[string]struct{}, error) { return live, nil }}
	if got := s.BackupHealth(); len(got) != 2 {
		t.Fatalf("before removal got %d series, want 2", len(got))
	}
	delete(live, "bob-container")
	got := s.BackupHealth()
	if len(got) != 1 || got[0].Username != "alice" {
		t.Fatalf("after removal got %+v, want only alice", got)
	}
}

// If the live-container list cannot be read the adapter must not guess:
// dropping series on a transient Incus error would hide a real stale
// backup, the exact failure #2294 exists to surface.
func TestServerPlatformSources_BackupHealth_ContainerListErrorKeepsAll(t *testing.T) {
	dir := t.TempDir()
	mgr := backup.NewManager(nil, nil, dir)
	at := time.Date(2026, 10, 5, 2, 0, 0, 0, time.UTC)
	writeSidecarForTest(t, dir, "alice-app-20261005T020000Z", "alice", at)
	counter := new(atomic.Int64)
	s := serverPlatformSources{backupMgr: mgr, backupReadFailures: counter,
		liveContainers: func() (map[string]struct{}, error) { return nil, os.ErrDeadlineExceeded }}
	if got := s.BackupHealth(); len(got) != 1 {
		t.Fatalf("got %+v, want alice kept when liveness is unknown", got)
	}
	if n := s.BackupHealthReadFailures(); n != 0 {
		t.Errorf("health_read_failures = %d, want 0: only index read failures count", n)
	}
}
