package cmd

import (
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

type snapshotCLIClient struct{ recordingBackupAPI }

func (c *snapshotCLIClient) GetBackup(id string) (*pb.BackupRecord, error) {
	return &pb.BackupRecord{Id: id, Destination: pb.BackupDestination_BACKUP_DESTINATION_SNAPSHOT}, nil
}

func TestSnapshotCLI(t *testing.T) {
	f := withRecordingBackupClient(t)
	resetBackupCreateFlags(t)
	backupCreateBox = true
	backupCreateDest = "snapshot"
	if err := runBackupCreate(backupCreateCmd, []string{"example"}); err != nil {
		t.Fatal(err)
	}
	if f.gotCreate == nil || f.gotCreate.Connection != nil || f.gotCreate.Scope != pb.BackupScope_BACKUP_SCOPE_BOX || f.gotCreate.Destination != pb.BackupDestination_BACKUP_DESTINATION_SNAPSHOT {
		t.Fatalf("request %+v", f.gotCreate)
	}
	for _, set := range []func(){func() { backupCreateBox = false }, func() { backupCreateKeyMode = "managed" }, func() { backupCreateAgeRecipient = "age1..." }} {
		f.gotCreate = nil
		resetBackupCreateFlags(t)
		backupCreateBox = true
		backupCreateDest = "snapshot"
		set()
		if err := runBackupCreate(backupCreateCmd, []string{"example"}); err == nil {
			t.Fatal("expected usage error")
		}
		if f.gotCreate != nil {
			t.Fatal("invalid request sent")
		}
	}
}

func TestSnapshotCLIRestoreOmitsDatabaseConnection(t *testing.T) {
	resetBackupRestoreFlags(t)
	c := &snapshotCLIClient{}
	old := newBackupClientFn
	newBackupClientFn = func() (backupAPI, error) { return c, nil }
	t.Cleanup(func() { newBackupClientFn = old })
	if err := runBackupRestore(backupRestoreCmd, []string{"snapshot-example"}); err != nil {
		t.Fatal(err)
	}
	if c.gotRestore == nil || c.gotRestore.Connection != nil {
		t.Fatalf("request %+v", c.gotRestore)
	}
}
