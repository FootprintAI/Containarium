package client

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// --- #3358: the box restore call the CLI and the MCP tool share ---

const testBoxIdentity = "AGE-SECRET-KEY-1EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE"

type fakeBoxRestoreAPI struct {
	rec     *pb.BackupRecord
	getErr  error
	restErr error
	got     *pb.RestoreBoxBackupRequest
	closed  bool
}

func (f *fakeBoxRestoreAPI) GetBackup(id string) (*pb.BackupRecord, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.rec, nil
}

func (f *fakeBoxRestoreAPI) RestoreBoxBackup(req *pb.RestoreBoxBackupRequest) (*pb.RestoreBoxBackupResponse, error) {
	f.got = req
	if f.restErr != nil {
		return nil, f.restErr
	}
	box := req.TargetBox
	if box == "" {
		box = f.rec.Username + "-restored"
	}
	return &pb.RestoreBoxBackupResponse{Message: "restore complete: " + req.Id, Box: box}, nil
}

func (f *fakeBoxRestoreAPI) Close() error { f.closed = true; return nil }

func boxRecord() *pb.BackupRecord {
	return &pb.BackupRecord{Id: "alice-box-20261101T000000Z", Username: "alice", Scope: pb.BackupScope_BACKUP_SCOPE_BOX, Encrypted: true}
}

func writeBoxIdentity(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "box.key")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRestoreBoxBackupFromFile_BuildsTheRequest(t *testing.T) {
	for _, tc := range []struct {
		name  string
		as    string
		force bool
		want  string
	}{
		{"named target with force", "alice-copy", true, "alice-copy"},
		{"default target", "", false, "alice-restored"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeBoxRestoreAPI{rec: boxRecord()}
			resp, err := RestoreBoxBackupFromFile(func() (BoxRestoreAPI, error) { return f, nil }, BoxRestoreParams{
				Box: "alice", BackupID: "alice-box-20261101T000000Z", As: tc.as, Force: tc.force,
				AgeIdentityFile: writeBoxIdentity(t, "# created: today\n# public key: age1example\n"+testBoxIdentity+"\n"),
			})
			if err != nil {
				t.Fatalf("RestoreBoxBackupFromFile: %v", err)
			}
			want := &pb.RestoreBoxBackupRequest{Id: "alice-box-20261101T000000Z", TargetBox: tc.as, Force: tc.force, AgeIdentity: testBoxIdentity}
			if f.got == nil || f.got.Id != want.Id || f.got.TargetBox != want.TargetBox || f.got.Force != want.Force || f.got.AgeIdentity != want.AgeIdentity {
				t.Errorf("request = %+v, want %+v", f.got, want)
			}
			if resp.Box != tc.want || !f.closed {
				t.Errorf("box = %q (closed %t), want %q and the client closed", resp.Box, f.closed, tc.want)
			}
		})
	}
}

// Every refusal comes before the restore RPC, and none carries key
// material: a missing or bad identity file is caught before the client is
// even built.
func TestRestoreBoxBackupFromFile_Refusals(t *testing.T) {
	good := func(t *testing.T) string { return writeBoxIdentity(t, testBoxIdentity+"\n") }
	for _, tc := range []struct {
		name      string
		params    func(t *testing.T) BoxRestoreParams
		rec       *pb.BackupRecord
		wantErr   string
		noFactory bool
	}{
		{name: "no box", params: func(t *testing.T) BoxRestoreParams {
			return BoxRestoreParams{BackupID: "x", AgeIdentityFile: good(t)}
		}, wantErr: "box", noFactory: true},
		{name: "no backup id", params: func(t *testing.T) BoxRestoreParams {
			return BoxRestoreParams{Box: "alice", AgeIdentityFile: good(t)}
		}, wantErr: "backup", noFactory: true},
		{name: "no identity file", params: func(*testing.T) BoxRestoreParams {
			return BoxRestoreParams{Box: "alice", BackupID: "x"}
		}, wantErr: "identity file", noFactory: true},
		{name: "unreadable identity file", params: func(t *testing.T) BoxRestoreParams {
			return BoxRestoreParams{Box: "alice", BackupID: "x", AgeIdentityFile: filepath.Join(t.TempDir(), "missing.key")}
		}, wantErr: "identity file", noFactory: true},
		{name: "two identities in the file", params: func(t *testing.T) BoxRestoreParams {
			return BoxRestoreParams{Box: "alice", BackupID: "x", AgeIdentityFile: writeBoxIdentity(t, testBoxIdentity+"\n"+testBoxIdentity+"X\n")}
		}, wantErr: "exactly one", noFactory: true},
		{name: "a database backup", rec: &pb.BackupRecord{Id: "x", Username: "alice", Scope: pb.BackupScope_BACKUP_SCOPE_DATABASE},
			params: func(t *testing.T) BoxRestoreParams {
				return BoxRestoreParams{Box: "alice", BackupID: "x", AgeIdentityFile: good(t)}
			}, wantErr: "not a whole-box backup"},
		{name: "a backup of another box", rec: boxRecord(),
			params: func(t *testing.T) BoxRestoreParams {
				return BoxRestoreParams{Box: "bob", BackupID: "alice-box-20261101T000000Z", AgeIdentityFile: good(t)}
			}, wantErr: "box alice, not bob"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeBoxRestoreAPI{rec: tc.rec}
			built := false
			_, err := RestoreBoxBackupFromFile(func() (BoxRestoreAPI, error) { built = true; return f, nil }, tc.params(t))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want one naming %q", err, tc.wantErr)
			}
			if strings.Contains(err.Error(), "AGE-SECRET-KEY") {
				t.Errorf("error carries key material: %v", err)
			}
			if f.got != nil {
				t.Error("a refused restore reached the daemon")
			}
			if tc.noFactory && built {
				t.Error("the client was built before a local refusal")
			}
		})
	}
}

// A daemon error is returned as is; the identity is not added to it.
func TestRestoreBoxBackupFromFile_DaemonErrorCarriesNoIdentity(t *testing.T) {
	boom := errors.New("rpc error: code = AlreadyExists desc = box restore failed")
	f := &fakeBoxRestoreAPI{rec: boxRecord(), restErr: boom}
	_, err := RestoreBoxBackupFromFile(func() (BoxRestoreAPI, error) { return f, nil }, BoxRestoreParams{
		Box: "alice", BackupID: "alice-box-20261101T000000Z", AgeIdentityFile: writeBoxIdentity(t, testBoxIdentity),
	})
	if !errors.Is(err, boom) || strings.Contains(err.Error(), "AGE-SECRET-KEY") {
		t.Fatalf("err = %v, want the daemon's error without key material", err)
	}
}
