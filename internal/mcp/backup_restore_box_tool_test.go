package mcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// --- #3358: restore_box_backup, a thin wrapper over the CLI's function ---

const mcpBoxIdentity = "AGE-SECRET-KEY-1EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE"

func mcpBoxIdentityFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "box.key")
	if err := os.WriteFile(p, []byte(mcpBoxIdentity+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

type fakeMCPBoxRestoreAPI struct {
	got    *pb.RestoreBoxBackupRequest
	closed bool
}

func (f *fakeMCPBoxRestoreAPI) GetBackup(id string) (*pb.BackupRecord, error) {
	return &pb.BackupRecord{Id: id, Username: "alice", Scope: pb.BackupScope_BACKUP_SCOPE_BOX, Encrypted: true}, nil
}

func (f *fakeMCPBoxRestoreAPI) RestoreBoxBackup(req *pb.RestoreBoxBackupRequest) (*pb.RestoreBoxBackupResponse, error) {
	f.got = req
	return &pb.RestoreBoxBackupResponse{Message: "restore complete: " + req.Id, Box: req.TargetBox}, nil
}

func (f *fakeMCPBoxRestoreAPI) Close() error { f.closed = true; return nil }

// The tool and `containarium backup restore --box` call the same function.
func TestRestoreBoxBackupTool_UsesTheSharedClientFunction(t *testing.T) {
	if reflect.ValueOf(restoreBoxFn).Pointer() != reflect.ValueOf(client.RestoreBoxBackupFromFile).Pointer() {
		t.Fatal("restore_box_backup does not call client.RestoreBoxBackupFromFile")
	}
}

// With the shared client faked, the tool's arguments reach the request as
// the CLI's flags do, and the MCP transport sends nothing of its own.
func TestRestoreBoxBackupTool_CallsSharedClient(t *testing.T) {
	var ownRequests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ownRequests.Add(1)
		w.WriteHeader(http.StatusTeapot)
	}))
	defer srv.Close()
	fake := &fakeMCPBoxRestoreAPI{}
	var built *Client
	prev := newBoxRestoreAPI
	newBoxRestoreAPI = func(c *Client) (client.BoxRestoreAPI, error) { built = c; return fake, nil }
	t.Cleanup(func() { newBoxRestoreAPI = prev })

	c := NewClient(srv.URL, "tok")
	out, err := handleRestoreBoxBackup(c, map[string]interface{}{
		"box": "alice", "backup": "alice-box-20261101T000000Z", "as": "alice-copy", "force": true,
		"age_identity_file": mcpBoxIdentityFile(t),
	})
	if err != nil {
		t.Fatalf("handleRestoreBoxBackup: %v", err)
	}
	if fake.got == nil || fake.got.Id != "alice-box-20261101T000000Z" || fake.got.TargetBox != "alice-copy" || !fake.got.Force || fake.got.AgeIdentity != mcpBoxIdentity {
		t.Errorf("request = %+v", fake.got)
	}
	if built != c || !fake.closed || ownRequests.Load() != 0 {
		t.Errorf("built from tool client %t, closed %t, own requests %d", built == c, fake.closed, ownRequests.Load())
	}
	if !strings.Contains(out, "alice-copy") || strings.Contains(out, "AGE-SECRET-KEY") {
		t.Errorf("output = %q", out)
	}
}

// With the real factory the request is the typed client's: the record is
// read, then the restore-box REST path is posted with the MCP bearer.
func TestRestoreBoxBackupTool_RealClientPath(t *testing.T) {
	var paths []string
	var body map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"record":{"id":"alice-box-1","username":"alice","scope":"BACKUP_SCOPE_BOX","encrypted":true}}`))
			return
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		_, _ = w.Write([]byte(`{"message":"restore complete: alice-box-1","box":"alice-restored"}`))
	}))
	defer srv.Close()

	out, err := handleRestoreBoxBackup(NewClient(srv.URL, "tok"), map[string]interface{}{
		"box": "alice", "backup": "alice-box-1", "age_identity_file": mcpBoxIdentityFile(t),
	})
	if err != nil {
		t.Fatalf("handleRestoreBoxBackup: %v", err)
	}
	if strings.Join(paths, ",") != "GET /v1/backups/alice-box-1,POST /v1/backups/alice-box-1/restore-box" {
		t.Errorf("requests = %v", paths)
	}
	if body["ageIdentity"] != mcpBoxIdentity && body["age_identity"] != mcpBoxIdentity {
		t.Errorf("restore body did not carry the identity from the file")
	}
	if !strings.Contains(out, "alice-restored") {
		t.Errorf("output = %q", out)
	}
}

// The schema names the arguments, the identity only as a file path, and
// the tool is gated by backups:write like restore_backup.
func TestRestoreBoxBackupTool_SchemaAndScope(t *testing.T) {
	var tool *Tool
	for _, tl := range backupTools() {
		if tl.Name == "restore_box_backup" {
			tl := tl
			tool = &tl
		}
	}
	if tool == nil {
		t.Fatal("restore_box_backup is not registered")
	}
	props := tool.InputSchema["properties"].(map[string]interface{})
	for _, k := range []string{"box", "backup", "as", "force", "age_identity_file"} {
		if _, ok := props[k]; !ok {
			t.Errorf("schema has no %s", k)
		}
	}
	if _, ok := props["age_identity"]; ok {
		t.Error("the schema accepts the identity itself as an argument")
	}
	if got := toolScopeAssignments()["restore_box_backup"]; got != auth.ScopeBackupsWrite {
		t.Errorf("scope = %q, want %q", got, auth.ScopeBackupsWrite)
	}
}
