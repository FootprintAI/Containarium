package client

import (
	"errors"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// --- #3504: the whole-box backup call the CLI and the MCP tool share ---

type fakeBoxBackupAPI struct {
	err    error
	got    *pb.CreateBackupRequest
	closed bool
}

func (f *fakeBoxBackupAPI) CreateBackup(req *pb.CreateBackupRequest) (*pb.CreateBackupResponse, error) {
	f.got = req
	if f.err != nil {
		return nil, f.err
	}
	return &pb.CreateBackupResponse{Message: "box backup created: alice-box-1"}, nil
}

func (f *fakeBoxBackupAPI) Close() error { f.closed = true; return nil }

func TestCreateBoxBackup_BuildsABoxRequest(t *testing.T) {
	f := &fakeBoxBackupAPI{}
	resp, err := CreateBoxBackup(func() (BoxBackupAPI, error) { return f, nil }, BoxBackupParams{
		Box:          "alice",
		Destination:  pb.BackupDestination_BACKUP_DESTINATION_GCS,
		GCSBucket:    "gs://example-bucket/boxes",
		AgeRecipient: "age1examplerecipient",
		KeyMode:      pb.BackupKeyMode_BACKUP_KEY_MODE_BOTH,
	})
	if err != nil {
		t.Fatalf("CreateBoxBackup: %v", err)
	}
	if resp.GetMessage() != "box backup created: alice-box-1" {
		t.Errorf("response = %+v", resp)
	}
	r := f.got
	if r == nil {
		t.Fatal("CreateBackup was not called")
	}
	if r.Scope != pb.BackupScope_BACKUP_SCOPE_BOX {
		t.Errorf("scope = %v, want BOX", r.Scope)
	}
	// The daemon refuses a BOX request with any connection (even an empty
	// one), a hook or a hook format.
	if r.Connection != nil || r.Hook != "" || r.HookFormat != pb.HookFormat_HOOK_FORMAT_UNSPECIFIED || r.Label != "" {
		t.Errorf("a BOX request carries database fields: %+v", r)
	}
	if r.Username != "alice" || r.Destination != pb.BackupDestination_BACKUP_DESTINATION_GCS ||
		r.GcsBucket != "gs://example-bucket/boxes" || r.AgeRecipient != "age1examplerecipient" ||
		r.KeyMode != pb.BackupKeyMode_BACKUP_KEY_MODE_BOTH {
		t.Errorf("request = %+v", r)
	}
	if !f.closed {
		t.Error("the client was not closed")
	}
}

func TestCreateBoxBackup_RefusalsSendNothing(t *testing.T) {
	valid := BoxBackupParams{Box: "alice", Destination: pb.BackupDestination_BACKUP_DESTINATION_LOCAL, KeyMode: pb.BackupKeyMode_BACKUP_KEY_MODE_MANAGED}
	for _, tc := range []struct {
		name    string
		edit    func(*BoxBackupParams)
		wantErr string
	}{
		{"no box", func(p *BoxBackupParams) { p.Box = "" }, "box"},
		{"blank box", func(p *BoxBackupParams) { p.Box = "  " }, "box"},
		{"no key mode", func(p *BoxBackupParams) { p.KeyMode = pb.BackupKeyMode_BACKUP_KEY_MODE_UNSPECIFIED }, "key mode"},
		{"gcs without a bucket", func(p *BoxBackupParams) { p.Destination = pb.BackupDestination_BACKUP_DESTINATION_GCS }, "bucket"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := valid
			tc.edit(&p)
			called := false
			_, err := CreateBoxBackup(func() (BoxBackupAPI, error) { called = true; return &fakeBoxBackupAPI{}, nil }, p)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want one naming %q", err, tc.wantErr)
			}
			if called {
				t.Error("a client was built for a refused call")
			}
		})
	}
}

func TestCreateBoxBackup_PassesErrorsThrough(t *testing.T) {
	dial := errors.New("dial failed")
	_, err := CreateBoxBackup(func() (BoxBackupAPI, error) { return nil, dial }, BoxBackupParams{
		Box: "alice", KeyMode: pb.BackupKeyMode_BACKUP_KEY_MODE_MANAGED,
	})
	if !errors.Is(err, dial) {
		t.Errorf("client error = %v, want %v", err, dial)
	}

	refused := errors.New("box backup failed: not enough space")
	f := &fakeBoxBackupAPI{err: refused}
	_, err = CreateBoxBackup(func() (BoxBackupAPI, error) { return f, nil }, BoxBackupParams{
		Box: "alice", KeyMode: pb.BackupKeyMode_BACKUP_KEY_MODE_MANAGED,
	})
	if !errors.Is(err, refused) || !f.closed {
		t.Errorf("create error = %v (closed %t), want %v and the client closed", err, f.closed, refused)
	}
}
