package mcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// --- #3504: create_backup's box scope, a thin wrapper over the CLI's function ---

type fakeMCPBoxBackupAPI struct {
	got    *pb.CreateBackupRequest
	closed bool
}

func (f *fakeMCPBoxBackupAPI) CreateBackup(req *pb.CreateBackupRequest) (*pb.CreateBackupResponse, error) {
	f.got = req
	rec := &pb.BackupRecord{
		Id: "alice-box-20261101T000000Z", Username: req.Username, Database: req.Username,
		Scope: pb.BackupScope_BACKUP_SCOPE_BOX, SizeBytes: 4096, Sha256: "abc123",
		Location:  "/var/lib/containarium/backups/alice-box-20261101T000000Z.tar.zst.age",
		Encrypted: true, AgeRecipient: "age1ephemeral",
		KeyMode: req.KeyMode, KekId: "kms-key-version-1",
	}
	return &pb.CreateBackupResponse{Message: "box backup created: " + rec.Id, Record: rec, Records: []*pb.BackupRecord{rec}}, nil
}

func (f *fakeMCPBoxBackupAPI) Close() error { f.closed = true; return nil }

// The tool and `containarium backup create --box` call the same function.
func TestCreateBackupBoxScope_UsesTheSharedClientFunction(t *testing.T) {
	if reflect.ValueOf(createBoxBackupFn).Pointer() != reflect.ValueOf(client.CreateBoxBackup).Pointer() {
		t.Fatal("create_backup scope 'box' does not call client.CreateBoxBackup")
	}
}

// With the shared client faked, the tool's arguments reach the request as
// the CLI's flags do, and the MCP transport sends nothing of its own.
func TestCreateBackupBoxScope_CallsSharedClient(t *testing.T) {
	var ownRequests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ownRequests.Add(1)
		w.WriteHeader(http.StatusTeapot)
	}))
	defer srv.Close()
	fake := &fakeMCPBoxBackupAPI{}
	var built *Client
	prev := newBoxBackupAPI
	newBoxBackupAPI = func(c *Client) (client.BoxBackupAPI, error) { built = c; return fake, nil }
	t.Cleanup(func() { newBoxBackupAPI = prev })

	c := NewClient(srv.URL, "tok")
	out, err := handleCreateBackup(c, map[string]interface{}{
		"username": "alice", "scope": "box", "dest": "gcs", "gcs_bucket": "gs://example-bucket/boxes",
		"key_mode": "both", "age_recipient": "age1examplerecipient", "require_encryption": true,
	})
	if err != nil {
		t.Fatalf("handleCreateBackup: %v", err)
	}
	r := fake.got
	if r == nil {
		t.Fatal("CreateBackup was not called")
	}
	if r.Scope != pb.BackupScope_BACKUP_SCOPE_BOX || r.Connection != nil || r.Username != "alice" ||
		r.Destination != pb.BackupDestination_BACKUP_DESTINATION_GCS || r.GcsBucket != "gs://example-bucket/boxes" ||
		r.KeyMode != pb.BackupKeyMode_BACKUP_KEY_MODE_BOTH || r.AgeRecipient != "age1examplerecipient" {
		t.Errorf("request = %+v", r)
	}
	if built != c || !fake.closed || ownRequests.Load() != 0 {
		t.Errorf("built from tool client %t, closed %t, own requests %d", built == c, fake.closed, ownRequests.Load())
	}
	for _, want := range []string{
		"box backup created: alice-box-20261101T000000Z",
		"Box:      alice",
		"Size:     4096 bytes",
		"SHA-256:  abc123",
		"Encrypted: yes, to age1ephemeral",
		"Key mode: both (key version kms-key-version-1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

// With the real factory the request is the typed client's: one POST to
// /v1/backups with the MCP bearer, scope BOX and no database connection,
// and its transport waits as long as the CLI does, not the 120s default.
func TestCreateBackupBoxScope_RealClientPath(t *testing.T) {
	var paths []string
	var body map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"box backup created: alice-box-1","record":{"id":"alice-box-1","username":"alice","database":"alice","scope":"BACKUP_SCOPE_BOX","sizeBytes":"10","encrypted":true,"ageRecipient":"age1ephemeral","keyMode":"BACKUP_KEY_MODE_MANAGED","kekId":"v1"}}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "tok")
	if hc := c.boxBackupHTTPClient(); hc.Timeout != boxBackupTimeout || hc.Transport != c.httpClient.Transport {
		t.Errorf("box backup transport: timeout %v (want %v), shares the tool transport %t", hc.Timeout, boxBackupTimeout, hc.Transport == c.httpClient.Transport)
	}
	if c.httpClient.Timeout == boxBackupTimeout {
		t.Error("the longer timeout leaked into the tool client's own transport")
	}

	out, err := handleCreateBackup(c, map[string]interface{}{"username": "alice", "scope": "box", "key_mode": "managed"})
	if err != nil {
		t.Fatalf("handleCreateBackup: %v", err)
	}
	if strings.Join(paths, ",") != "POST /v1/backups" {
		t.Errorf("requests = %v", paths)
	}
	if body["scope"] != "BACKUP_SCOPE_BOX" || body["keyMode"] != "BACKUP_KEY_MODE_MANAGED" ||
		body["destination"] != "BACKUP_DESTINATION_LOCAL" || body["username"] != "alice" {
		t.Errorf("request body = %v", body)
	}
	if _, ok := body["connection"]; ok {
		t.Errorf("a BOX request carries a connection: %v", body)
	}
	if !strings.Contains(out, "alice-box-1") || !strings.Contains(out, "Key mode: managed (key version v1") {
		t.Errorf("output = %q", out)
	}
}

// Invalid scope combinations are refused before any request is made.
func TestCreateBackupBoxScope_InvalidArgumentsSendNoRequest(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusTeapot)
	}))
	defer srv.Close()

	box := func(extra map[string]interface{}) map[string]interface{} {
		args := map[string]interface{}{"username": "alice", "scope": "box", "key_mode": "managed"}
		for k, v := range extra {
			args[k] = v
		}
		return args
	}
	for _, tc := range []struct {
		name    string
		args    map[string]interface{}
		wantErr string
	}{
		{"database", box(map[string]interface{}{"database": "app"}), "database"},
		{"hook", box(map[string]interface{}{"hook": "/opt/dump.sh"}), "hook"},
		{"hook_format", box(map[string]interface{}{"hook_format": "pg_custom"}), "hook_format"},
		{"label", box(map[string]interface{}{"label": "nightly"}), "label"},
		{"db_user", box(map[string]interface{}{"db_user": "app"}), "db_user"},
		{"db_password", box(map[string]interface{}{"db_password": "pw"}), "db_password"},
		{"no key_mode", map[string]interface{}{"username": "alice", "scope": "box"}, "key_mode"},
		{"unknown key_mode", box(map[string]interface{}{"key_mode": "plaintext"}), "key_mode"},
		{"no username", map[string]interface{}{"scope": "box", "key_mode": "managed"}, "box"},
		{"gcs without a bucket", box(map[string]interface{}{"dest": "gcs"}), "bucket"},
		{"unknown dest", box(map[string]interface{}{"dest": "s3"}), "dest"},
		{"unknown scope", map[string]interface{}{"username": "alice", "scope": "volume", "key_mode": "managed"}, "scope"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := handleCreateBackup(NewClient(srv.URL, "tok"), tc.args)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want one naming %q", err, tc.wantErr)
			}
		})
	}
	if n := requests.Load(); n != 0 {
		t.Errorf("%d request(s) reached the daemon for refused arguments", n)
	}
}

// Without a scope, or with scope 'database', the request is the database
// request it always was: no scope on the wire.
func TestCreateBackup_DatabaseScopeUnchanged(t *testing.T) {
	for _, scope := range []interface{}{nil, "database"} {
		api := &createBackupOnlyAPI{}
		args := map[string]interface{}{"username": "alice", "database": "app", "dest": "gcs", "gcs_bucket": "gs://b"}
		if scope != nil {
			args["scope"] = scope
		}
		if _, err := handleCreateBackup(api, args); err != nil {
			t.Fatalf("scope %v: %v", scope, err)
		}
		if api.got == nil || api.got.Destination != "BACKUP_DESTINATION_GCS" || api.got.Connection == nil || api.got.Connection.Database != "app" {
			t.Errorf("scope %v: request = %+v", scope, api.got)
		}
	}
}

func TestCreateBackupSchema_DeclaresScope(t *testing.T) {
	for _, tool := range backupTools() {
		if tool.Name != "create_backup" {
			continue
		}
		props, _ := tool.InputSchema["properties"].(map[string]interface{})
		p, ok := props["scope"].(map[string]interface{})
		if !ok || p["type"] != "string" || !reflect.DeepEqual(p["enum"], []string{"database", "box"}) {
			t.Fatalf("create_backup schema scope = %v, want a string enum of database and box", props["scope"])
		}
		if !strings.Contains(tool.Description, "scope 'box'") {
			t.Errorf("create_backup description does not document scope 'box'")
		}
		return
	}
	t.Fatal("create_backup tool not found")
}
