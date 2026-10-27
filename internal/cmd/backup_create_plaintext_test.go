package cmd

import (
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3169: a stored-unencrypted dump must be unmistakable in the CLI output.
func TestPrintCreatedBackups_PlaintextIsLoud(t *testing.T) {
	out := captureStdout(t, func() {
		printCreatedBackups(&pb.CreateBackupResponse{
			Message: "backed up 1 database(s)",
			Records: []*pb.BackupRecord{{Id: "b1", Database: "app", Scope: pb.BackupScope_BACKUP_SCOPE_DATABASE}},
		})
	})
	for _, want := range []string{"Encrypted: no", "WARNING", "stored UNENCRYPTED"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestPrintCreatedBackups_EncryptedUnchanged(t *testing.T) {
	out := captureStdout(t, func() {
		printCreatedBackups(&pb.CreateBackupResponse{
			Message: "ok",
			Records: []*pb.BackupRecord{{
				Id: "b1", Database: "app", Encrypted: true, AgeRecipient: "age1abc",
				KeyMode: pb.BackupKeyMode_BACKUP_KEY_MODE_AGE_RECIPIENT,
			}},
		})
	})
	if !strings.Contains(out, "Encrypted: yes (to age1abc)") {
		t.Errorf("missing yes line:\n%s", out)
	}
	if strings.Contains(out, "Encrypted: no") || strings.Contains(out, "WARNING") {
		t.Errorf("encrypted record must not warn:\n%s", out)
	}
}

func TestPrintCreatedBackups_ManagedKeyIsNotPlaintext(t *testing.T) {
	out := captureStdout(t, func() {
		printCreatedBackups(&pb.CreateBackupResponse{
			Records: []*pb.BackupRecord{{Id: "b1", Database: "app", KeyMode: pb.BackupKeyMode_BACKUP_KEY_MODE_MANAGED}},
		})
	})
	if strings.Contains(out, "Encrypted: no") || strings.Contains(out, "WARNING") {
		t.Errorf("managed-key record must not warn:\n%s", out)
	}
}
