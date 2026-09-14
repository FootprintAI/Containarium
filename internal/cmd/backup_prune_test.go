package cmd

import (
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func resetBackupPruneFlags(t *testing.T) {
	t.Helper()
	backupPruneDatabase, backupPruneKeep = "", 0
	t.Cleanup(func() { backupPruneDatabase, backupPruneKeep = "", 0 })
}

func TestBackupPrune_FlagsReachRequest(t *testing.T) {
	f := withRecordingBackupClient(t)
	resetBackupPruneFlags(t)
	backupPruneDatabase = "app"
	backupPruneKeep = 7

	if err := runBackupPrune(backupPruneCmd, []string{"alice"}); err != nil {
		t.Fatalf("runBackupPrune: %v", err)
	}
	if f.gotPrune == nil {
		t.Fatal("PruneBackups was not called")
	}
	if f.gotPrune.Username != "alice" || f.gotPrune.Database != "app" || f.gotPrune.Keep != 7 {
		t.Errorf("request = %+v, want username=alice database=app keep=7", f.gotPrune)
	}
}

func TestBackupPrune_EmptyDatabaseMeansEveryDatabase(t *testing.T) {
	f := withRecordingBackupClient(t)
	resetBackupPruneFlags(t)
	backupPruneKeep = 3

	if err := runBackupPrune(backupPruneCmd, []string{"alice"}); err != nil {
		t.Fatalf("runBackupPrune: %v", err)
	}
	if f.gotPrune.Database != "" {
		t.Errorf("Database = %q, want empty (every database) when --database is omitted", f.gotPrune.Database)
	}
}

// The CLI must refuse keep < 1 itself, before dialing the daemon — the
// same guard the server enforces (#1839), but failing fast locally means
// a typo'd `--keep 0` doesn't even attempt a network call.
func TestBackupPrune_RejectsKeepLessThanOneWithoutCallingTheAPI(t *testing.T) {
	f := withRecordingBackupClient(t)
	resetBackupPruneFlags(t)

	for _, keep := range []int32{0, -1} {
		backupPruneKeep = keep
		err := runBackupPrune(backupPruneCmd, []string{"alice"})
		if err == nil {
			t.Errorf("keep=%d should be rejected", keep)
		}
		if f.gotPrune != nil {
			t.Errorf("keep=%d must not reach the API, but PruneBackups was called with %+v", keep, f.gotPrune)
		}
	}
}

func TestBackupPrune_ReportsDeletedAndFailedIDs(t *testing.T) {
	f := withRecordingBackupClient(t)
	resetBackupPruneFlags(t)
	backupPruneKeep = 1
	f.pruneResp = &pb.PruneBackupsResponse{
		Message:    "pruned 1 backup(s), 1 failed",
		DeletedIds: []string{"alice-app-20260601T000000Z"},
		Failures:   []string{"alice-app-20260602T000000Z: transient object-store error"},
	}

	if err := runBackupPrune(backupPruneCmd, []string{"alice"}); err != nil {
		t.Fatalf("runBackupPrune: %v", err)
	}
	// No further assertions on stdout formatting here — this locks down
	// that a response carrying failures doesn't itself become a CLI
	// error (a partial prune succeeded and should exit 0, same as
	// CreateBackupResponse.failures never fails backup create).
}
