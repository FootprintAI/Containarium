package cmd

import (
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// `backup create <username> --box` is the CLI face of #2801: a BOX-scope
// request with no database connection, and an explicit key mode because a
// whole-box backup is never plaintext.
func TestBackupCreate_BoxFlagBuildsBoxRequest(t *testing.T) {
	f := withRecordingBackupClient(t)
	resetBackupCreateFlags(t)
	backupCreateBox = true
	backupCreateKeyMode = "age-recipient"
	backupCreateAgeRecipient = "age1examplerecipient"
	backupCreateDest, backupCreateBucket = "gcs", "gs://example-bucket/boxes"

	if err := runBackupCreate(backupCreateCmd, []string{"alice"}); err != nil {
		t.Fatalf("runBackupCreate: %v", err)
	}
	r := f.gotCreate
	if r == nil {
		t.Fatal("CreateBackup was not called")
	}
	if r.Scope != pb.BackupScope_BACKUP_SCOPE_BOX {
		t.Errorf("scope = %v, want BOX", r.Scope)
	}
	if r.Connection != nil {
		t.Errorf("a BOX request carries a connection: %+v (the daemon refuses even an empty one)", r.Connection)
	}
	if r.Username != "alice" || r.KeyMode != pb.BackupKeyMode_BACKUP_KEY_MODE_AGE_RECIPIENT ||
		r.AgeRecipient != "age1examplerecipient" || r.Destination != pb.BackupDestination_BACKUP_DESTINATION_GCS ||
		r.GcsBucket != "gs://example-bucket/boxes" {
		t.Errorf("request = %+v", r)
	}
}

// Without --box nothing changes: the database request still carries its
// connection and no scope.
func TestBackupCreate_WithoutBoxIsADatabaseRequest(t *testing.T) {
	f := withRecordingBackupClient(t)
	resetBackupCreateFlags(t)
	if err := runBackupCreate(backupCreateCmd, []string{"alice"}); err != nil {
		t.Fatalf("runBackupCreate: %v", err)
	}
	if f.gotCreate.Scope != pb.BackupScope_BACKUP_SCOPE_UNSPECIFIED || f.gotCreate.Connection == nil {
		t.Errorf("database request changed: scope %v connection %v", f.gotCreate.Scope, f.gotCreate.Connection)
	}
}

// Flags that only mean something for a database backup, and a missing key
// mode, are usage errors before anything reaches the daemon.
func TestBackupCreate_BoxFlagRefusals(t *testing.T) {
	for _, tc := range []struct {
		name    string
		set     func()
		wantErr string
	}{
		{"no key mode", func() { backupCreateKeyMode = "" }, "--key-mode"},
		{"--database", func() { backupCreateDatabase = "app" }, "--database"},
		{"--hook", func() { backupCreateHook = "/opt/dump.sh" }, "--hook"},
		{"--hook-format", func() { backupCreateHookFormat = "pg_custom" }, "--hook-format"},
		{"--label", func() { backupCreateLabel = "nightly" }, "--label"},
		{"--db-user", func() { backupCreateDBUser = "app" }, "--db-user"},
		{"--db-password", func() { backupCreateDBPass = "pw" }, "--db-password"},
		{"--db-host", func() { backupCreateDBHost = "db" }, "--db-host"},
		{"--db-port", func() { backupCreateDBPort = 5433 }, "--db-port"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := withRecordingBackupClient(t)
			resetBackupCreateFlags(t)
			backupCreateBox = true
			backupCreateKeyMode = "managed"
			tc.set()
			err := runBackupCreate(backupCreateCmd, []string{"alice"})
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want a usage error naming %s", err, tc.wantErr)
			}
			if f.gotCreate != nil {
				t.Error("the refused request reached the daemon")
			}
		})
	}
}

func TestEngineLabel_Box(t *testing.T) {
	if got := engineLabel(pb.BackupEngine_BACKUP_ENGINE_BOX); got != "box" {
		t.Errorf("engineLabel(BOX) = %q, want box", got)
	}
}
