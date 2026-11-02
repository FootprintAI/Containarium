package cmd

import (
	"reflect"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// --- #3358: `containarium backup restore --box` ---

// boxRestoreBackupAPI serves one BOX record and records the restore request.
type boxRestoreBackupAPI struct {
	recordingBackupAPI
	rec *pb.BackupRecord
	got *pb.RestoreBoxBackupRequest
}

func (f *boxRestoreBackupAPI) GetBackup(string) (*pb.BackupRecord, error) { return f.rec, nil }

func (f *boxRestoreBackupAPI) RestoreBoxBackup(req *pb.RestoreBoxBackupRequest) (*pb.RestoreBoxBackupResponse, error) {
	f.got = req
	box := req.TargetBox
	if box == "" {
		box = f.rec.Username + "-restored"
	}
	return &pb.RestoreBoxBackupResponse{Message: "restore complete: " + req.Id, Box: box}, nil
}

func withBoxRestoreClient(t *testing.T) *boxRestoreBackupAPI {
	t.Helper()
	f := &boxRestoreBackupAPI{rec: &pb.BackupRecord{Id: "alice-box-20261101T000000Z", Username: "alice", Scope: pb.BackupScope_BACKUP_SCOPE_BOX, Encrypted: true}}
	orig := newBackupClientFn
	newBackupClientFn = func() (backupAPI, error) { return f, nil }
	t.Cleanup(func() { newBackupClientFn = orig })
	setTransportGlobals(t, "localhost:8080", false, true)
	return f
}

// resetBackupRestoreBoxFlags puts every restore flag, the box ones
// included, back to its default before and after the test.
func resetBackupRestoreBoxFlags(t *testing.T) {
	t.Helper()
	resetBackupRestoreFlags(t)
	reset := func() {
		backupRestoreDBUser, backupRestoreDBPass, backupRestoreDBHost, backupRestoreDBPort = "", "", "", 0
		backupRestoreBox, backupRestoreBackup, backupRestoreAs, backupRestoreForce = "", "", "", false
	}
	reset()
	t.Cleanup(reset)
}

// Flags parsed from argv reach the request: --as and --force, the backup
// id, and the identity read from the file.
func TestBackupRestoreBox_FlagsReachTheRequest(t *testing.T) {
	for _, tc := range []struct {
		name    string
		extra   []string
		wantAs  string
		force   bool
		wantBox string
	}{
		{"--as and --force", []string{"--as", "alice-copy", "--force"}, "alice-copy", true, "alice-copy"},
		{"defaults", nil, "", false, "alice-restored"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := withBoxRestoreClient(t)
			resetBackupRestoreBoxFlags(t)
			key := writeIdentityFile(t)
			argv := append([]string{"--box", "alice", "--backup", "alice-box-20261101T000000Z", "--age-identity-file", key}, tc.extra...)
			if err := backupRestoreCmd.ParseFlags(argv); err != nil {
				t.Fatalf("ParseFlags: %v", err)
			}
			if err := runBackupRestore(backupRestoreCmd, backupRestoreCmd.Flags().Args()); err != nil {
				t.Fatalf("runBackupRestore: %v", err)
			}
			if f.got == nil {
				t.Fatal("RestoreBoxBackup was not called")
			}
			if f.got.Id != "alice-box-20261101T000000Z" || f.got.TargetBox != tc.wantAs || f.got.Force != tc.force ||
				!strings.HasPrefix(f.got.AgeIdentity, "AGE-SECRET-KEY-1") {
				t.Errorf("request = id %q target %q force %t identity-set %t", f.got.Id, f.got.TargetBox, f.got.Force, f.got.AgeIdentity != "")
			}
			if f.gotRestore != nil {
				t.Error("the database restore was called too")
			}
		})
	}
}

// The help text names the box flags and says the identity comes from a
// file.
func TestBackupRestoreBox_HelpText(t *testing.T) {
	for _, name := range []string{"box", "backup", "as", "force"} {
		fl := backupRestoreCmd.Flags().Lookup(name)
		if fl == nil || fl.Usage == "" {
			t.Errorf("flag --%s missing or undocumented", name)
		}
	}
	if fl := backupRestoreCmd.Flags().Lookup("force"); fl != nil && fl.Value.Type() != "bool" {
		t.Errorf("--force is a %s, want a bool", fl.Value.Type())
	}
	long := backupRestoreCmd.Long
	for _, want := range []string{"--box", "--backup", "--as", "--force", "-restored", "--age-identity-file"} {
		if !strings.Contains(long, want) {
			t.Errorf("restore help does not mention %s", want)
		}
	}
}

// Database-restore flags, a positional id, a missing identity file and box
// flags without --box are usage errors before anything is sent.
func TestBackupRestoreBox_Refusals(t *testing.T) {
	for _, tc := range []struct {
		name    string
		set     func()
		args    []string
		wantErr string
	}{
		{"positional id", nil, []string{"alice-box-20261101T000000Z"}, "--backup"},
		{"no --backup", func() { backupRestoreBackup = "" }, nil, "--backup"},
		{"no identity file", func() { backupRestoreAgeIdentityFile = "" }, nil, "--age-identity-file"},
		{"--clean", func() { backupRestoreClean = true }, nil, "--clean"},
		{"--database", func() { backupRestoreDatabase = "app" }, nil, "--database"},
		{"--db-user", func() { backupRestoreDBUser = "u" }, nil, "--db-user"},
		{"--db-password", func() { backupRestoreDBPass = "p" }, nil, "--db-password"},
		{"--db-host", func() { backupRestoreDBHost = "h" }, nil, "--db-host"},
		{"--db-port", func() { backupRestoreDBPort = 5433 }, nil, "--db-port"},
		{"--target", func() { backupRestoreTarget = "bob-container" }, nil, "--target"},
		{"--latest", func() { backupRestoreLatest = true }, nil, "--latest"},
		{"--user", func() { backupRestoreUser = "alice" }, nil, "--user"},
		{"--managed", func() { backupRestoreManaged = true }, nil, "--managed"},
		{"--as without --box", func() { backupRestoreBox = "" }, nil, "--box"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := withBoxRestoreClient(t)
			resetBackupRestoreBoxFlags(t)
			backupRestoreBox, backupRestoreBackup, backupRestoreAs = "alice", "alice-box-20261101T000000Z", "alice-copy"
			backupRestoreAgeIdentityFile = writeIdentityFile(t)
			if tc.set != nil {
				tc.set()
			}
			err := runBackupRestore(backupRestoreCmd, tc.args)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want a usage error naming %s", err, tc.wantErr)
			}
			if strings.Contains(err.Error(), "AGE-SECRET-KEY") {
				t.Errorf("error carries key material: %v", err)
			}
			if f.got != nil || f.gotRestore != nil {
				t.Error("a refused restore reached the daemon")
			}
		})
	}
}

// The identity is a private key: it is not sent over cleartext to a remote
// host, as for the database restore.
func TestBackupRestoreBox_RefusesIdentityOverCleartext(t *testing.T) {
	f := withBoxRestoreClient(t)
	resetBackupRestoreBoxFlags(t)
	setTransportGlobals(t, "host.example.com:8080", true, false)
	backupRestoreBox, backupRestoreBackup = "alice", "alice-box-20261101T000000Z"
	backupRestoreAgeIdentityFile = writeIdentityFile(t)
	err := runBackupRestore(backupRestoreCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "age identity") {
		t.Fatalf("err = %v, want a refusal naming the age identity", err)
	}
	if f.got != nil {
		t.Error("the key was sent over cleartext")
	}
}

// The CLI calls the function the MCP tool calls (CLI-first, CLAUDE.md).
func TestBackupRestoreBox_UsesTheSharedClientFunction(t *testing.T) {
	if reflect.ValueOf(restoreBoxFn).Pointer() != reflect.ValueOf(client.RestoreBoxBackupFromFile).Pointer() {
		t.Fatal("backup restore --box does not call client.RestoreBoxBackupFromFile")
	}
}
