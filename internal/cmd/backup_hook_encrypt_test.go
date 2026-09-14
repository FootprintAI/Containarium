package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// recordingBackupAPI captures the create/restore requests the CLI builds so
// a test can assert the #1831 flags reach the wire request.
type recordingBackupAPI struct {
	fakeBackupAPI
	gotCreate  *pb.CreateBackupRequest
	gotRestore *pb.RestoreBackupRequest
	gotPrune   *pb.PruneBackupsRequest
	pruneResp  *pb.PruneBackupsResponse
}

func (f *recordingBackupAPI) CreateBackup(req *pb.CreateBackupRequest) (*pb.CreateBackupResponse, error) {
	f.gotCreate = req
	return &pb.CreateBackupResponse{Message: "ok", Records: []*pb.BackupRecord{{Id: "alice-db-dump-x", Database: "db-dump"}}}, nil
}

func (f *recordingBackupAPI) RestoreBackup(req *pb.RestoreBackupRequest) (*pb.RestoreBackupResponse, error) {
	f.gotRestore = req
	return &pb.RestoreBackupResponse{Message: "ok"}, nil
}

func (f *recordingBackupAPI) PruneBackups(req *pb.PruneBackupsRequest) (*pb.PruneBackupsResponse, error) {
	f.gotPrune = req
	if f.pruneResp != nil {
		return f.pruneResp, nil
	}
	return &pb.PruneBackupsResponse{Message: "ok"}, nil
}

func withRecordingBackupClient(t *testing.T) *recordingBackupAPI {
	t.Helper()
	f := &recordingBackupAPI{}
	orig := newBackupClientFn
	newBackupClientFn = func() (backupAPI, error) { return f, nil }
	t.Cleanup(func() { newBackupClientFn = orig })
	return f
}

func resetBackupCreateFlags(t *testing.T) {
	t.Helper()
	backupCreateDatabase, backupCreateDest, backupCreateBucket = "", "local", ""
	backupCreateHook, backupCreateLabel, backupCreateAgeRecipient = "", "", ""
	t.Cleanup(func() {
		backupCreateDatabase, backupCreateDest, backupCreateBucket = "", "local", ""
		backupCreateHook, backupCreateLabel, backupCreateAgeRecipient = "", "", ""
	})
}

// --hook / --label / --age-recipient are the CLI face of #1831 and must
// land verbatim on the request; the daemon does the validation.
func TestBackupCreate_HookAndRecipientFlagsReachRequest(t *testing.T) {
	f := withRecordingBackupClient(t)
	resetBackupCreateFlags(t)
	backupCreateHook = "/opt/backup/db-dump.sh"
	backupCreateLabel = "app"
	backupCreateAgeRecipient = "age1examplerecipient"

	if err := runBackupCreate(backupCreateCmd, []string{"alice"}); err != nil {
		t.Fatalf("runBackupCreate: %v", err)
	}
	if f.gotCreate == nil {
		t.Fatal("CreateBackup was not called")
	}
	if f.gotCreate.Hook != "/opt/backup/db-dump.sh" || f.gotCreate.Label != "app" || f.gotCreate.AgeRecipient != "age1examplerecipient" {
		t.Errorf("request = %+v, want hook/label/recipient set", f.gotCreate)
	}
}

// The age identity is a private key: it is read from a file the operator
// names, never taken on argv, and handed to the daemon for that one call.
func TestBackupRestore_AgeIdentityReadFromFile(t *testing.T) {
	f := withRecordingBackupClient(t)
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "backup.key")
	const secret = "AGE-SECRET-KEY-1EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE"
	if err := os.WriteFile(keyFile, []byte("# created: 2026-09-13\n# public key: age1example\n"+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	backupRestoreAgeIdentityFile = keyFile
	t.Cleanup(func() { backupRestoreAgeIdentityFile = "" })

	if err := runBackupRestore(backupRestoreCmd, []string{"alice-app-x"}); err != nil {
		t.Fatalf("runBackupRestore: %v", err)
	}
	if f.gotRestore == nil {
		t.Fatal("RestoreBackup was not called")
	}
	if f.gotRestore.AgeIdentity != secret {
		t.Errorf("AgeIdentity = %q, want the AGE-SECRET-KEY line from the file (comments stripped)", f.gotRestore.AgeIdentity)
	}
}

func TestBackupRestore_MissingIdentityFileIsAnErrorBeforeAnyCall(t *testing.T) {
	f := withRecordingBackupClient(t)
	backupRestoreAgeIdentityFile = filepath.Join(t.TempDir(), "nope.key")
	t.Cleanup(func() { backupRestoreAgeIdentityFile = "" })

	err := runBackupRestore(backupRestoreCmd, []string{"alice-app-x"})
	if err == nil || !errors.Is(err, os.ErrNotExist) && !strings.Contains(err.Error(), "identity") {
		t.Fatalf("expected a read error naming the identity file, got %v", err)
	}
	if f.gotRestore != nil {
		t.Error("restore must not be attempted when the identity file cannot be read")
	}
}

func TestParseAgeIdentityFile(t *testing.T) {
	for _, tc := range []struct {
		name, content, want string
		wantErr             bool
	}{
		{"bare key", "AGE-SECRET-KEY-1ABC\n", "AGE-SECRET-KEY-1ABC", false},
		{"age-keygen output with comments", "# created: x\n# public key: age1y\nAGE-SECRET-KEY-1ABC\n", "AGE-SECRET-KEY-1ABC", false},
		{"empty", "\n# only comments\n", "", true},
		{"two keys is ambiguous", "AGE-SECRET-KEY-1A\nAGE-SECRET-KEY-1B\n", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseAgeIdentity([]byte(tc.content))
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestEngineLabel_Hook(t *testing.T) {
	if got := engineLabel(pb.BackupEngine_BACKUP_ENGINE_HOOK); got != "hook" {
		t.Errorf("engineLabel(HOOK) = %q, want %q", got, "hook")
	}
}
