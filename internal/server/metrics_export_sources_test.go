package server

import (
	"encoding/json"
	"os"
	"path/filepath"
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
