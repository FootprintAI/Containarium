package mcp

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/internal/coderun"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// #3548: put_file is a thin wrapper over client.PutBoxFile, the function
// `containarium code put-file` calls, over the same REST path.

// sha256("hello")
const putFileHelloSHA = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

func putFileServer(t *testing.T, status int, reply string, got *pb.WriteBoxFileRequest, path, method *string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if path != nil {
			*path, *method = r.URL.Path, r.Method
		}
		b, _ := io.ReadAll(r.Body)
		if got != nil {
			if err := protojson.Unmarshal(b, got); err != nil {
				t.Errorf("request body %q: %v", b, err)
			}
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(reply))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestPutFileTool_WritesInlineContent(t *testing.T) {
	cases := map[string]map[string]interface{}{
		"text":   {"box": "alice", "path": "in/a.txt", "content": "hello"},
		"base64": {"box": "alice", "path": "in/a.txt", "content_base64": base64.StdEncoding.EncodeToString([]byte("hello"))},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			var got pb.WriteBoxFileRequest
			var path, method string
			srv := putFileServer(t, http.StatusOK, `{"path":"/home/alice/in/a.txt","size":"5","sha256":"`+putFileHelloSHA+`"}`, &got, &path, &method)
			out, err := handlePutFile(NewClient(srv.URL, "tok"), args)
			if err != nil {
				t.Fatalf("handlePutFile: %v", err)
			}
			if method != http.MethodPut || path != "/v1/containers/alice/files" {
				t.Errorf("request = %s %s", method, path)
			}
			if got.GetPath() != "in/a.txt" || string(got.GetContent()) != "hello" || got.GetSha256() != putFileHelloSHA {
				t.Errorf("sent = %v", &got)
			}
			if want := client.RenderBoxFileWrite("alice", &pb.WriteBoxFileResponse{Path: "/home/alice/in/a.txt", Size: 5, Sha256: putFileHelloSHA}); out != want {
				t.Errorf("output = %q, want the CLI's %q", out, want)
			}
		})
	}
}

func TestPutFileTool_ModeAndChecksumArePassedThrough(t *testing.T) {
	var got pb.WriteBoxFileRequest
	srv := putFileServer(t, http.StatusOK, `{}`, &got, nil, nil)
	if _, err := handlePutFile(NewClient(srv.URL, "tok"), map[string]interface{}{
		"box": "alice", "path": "a", "content": "hello", "mode": "0400", "sha256": putFileHelloSHA,
	}); err != nil {
		t.Fatal(err)
	}
	if got.GetMode() != "0400" || got.GetSha256() != putFileHelloSHA {
		t.Errorf("sent = %v", &got)
	}
}

func TestPutFileTool_EmptyTextIsAnEmptyFile(t *testing.T) {
	var got pb.WriteBoxFileRequest
	srv := putFileServer(t, http.StatusOK, `{}`, &got, nil, nil)
	if _, err := handlePutFile(NewClient(srv.URL, "tok"), map[string]interface{}{"box": "alice", "path": "a", "content": ""}); err != nil {
		t.Fatal(err)
	}
	if len(got.GetContent()) != 0 || got.GetPath() != "a" {
		t.Errorf("sent = %v", &got)
	}
}

// The daemon owns the path rules and the checksum check: its refusal comes
// back typed, with the reason. The replies are in the daemon's error-body shape
// (internal/gateway ErrorHandler: HTTP status in "code", gRPC status in "error").
func TestPutFileTool_TypedRefusalCarriesReason(t *testing.T) {
	daemonErr := func(grpcCode string, httpStatus int, msg string) string {
		return fmt.Sprintf(`{"error":"rpc error: code = %s desc = %s","code":%d,"message":"%s"}`, grpcCode, msg, httpStatus, msg)
	}
	cases := []struct {
		name, path, reply, reason string
		status                    int
	}{
		{"escape path", "../x", daemonErr("InvalidArgument", 400, "path must stay inside the home directory"), "INVALID_ARGUMENT", http.StatusBadRequest},
		{"platform dir", ".ssh/authorized_keys", daemonErr("InvalidArgument", 400, "path must not be under .ssh"), "INVALID_ARGUMENT", http.StatusBadRequest},
		{"checksum mismatch", "a", daemonErr("DataLoss", 500, "the bytes on the box do not match sha256; no file was written"), "DATA_LOSS", http.StatusInternalServerError},
		{"directory at the path", "a", daemonErr("FailedPrecondition", 400, "a is a directory"), "FAILED_PRECONDITION", http.StatusBadRequest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := putFileServer(t, c.status, c.reply, nil, nil, nil)
			_, err := handlePutFile(NewClient(srv.URL, "tok"), map[string]interface{}{"box": "alice", "path": c.path, "content": "x"})
			if err == nil || !strings.Contains(err.Error(), "refused ("+c.reason+")") {
				t.Fatalf("err = %v, want refused (%s)", err, c.reason)
			}
		})
	}
}

func TestPutFileTool_OldDaemonSaysSo(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	_, err := handlePutFile(NewClient(srv.URL, "tok"), map[string]interface{}{"box": "alice", "path": "a", "content": "x"})
	if err == nil || !strings.Contains(err.Error(), "WriteBoxFile") || !strings.Contains(err.Error(), "upgrade") {
		t.Fatalf("err = %v", err)
	}
}

// Invalid input is rejected before any request is made.
func TestPutFileTool_InvalidInputSendsNoRequest(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusTeapot)
	}))
	t.Cleanup(srv.Close)
	c := NewClient(srv.URL, "tok")
	over := strings.Repeat("a", coderun.MaxBoxFileBytes+1)
	cases := map[string]map[string]interface{}{
		"missing box":          {"path": "a", "content": "x"},
		"bad box":              {"box": "../etc", "path": "a", "content": "x"},
		"missing path":         {"box": "alice", "content": "x"},
		"no content":           {"box": "alice", "path": "a"},
		"both contents":        {"box": "alice", "path": "a", "content": "x", "content_base64": "eA=="},
		"content not a string": {"box": "alice", "path": "a", "content": float64(3)},
		"bad base64":           {"box": "alice", "path": "a", "content_base64": "not base64!"},
		"text over the cap":    {"box": "alice", "path": "a", "content": over},
		"base64 over the cap":  {"box": "alice", "path": "a", "content_base64": base64.StdEncoding.EncodeToString([]byte(over))},
		"bad mode":             {"box": "alice", "path": "a", "content": "x", "mode": "0644"},
		"bad sha256":           {"box": "alice", "path": "a", "content": "x", "sha256": "abc"},
		"local path argument":  {"box": "alice", "path": "a", "local_path": "/etc/passwd"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := handlePutFile(c, args); err == nil {
				t.Fatal("invalid input accepted")
			}
		})
	}
	if requests.Load() != 0 {
		t.Errorf("%d requests were sent", requests.Load())
	}
}

func TestPutFileTool_SchemaScopeAndRegistration(t *testing.T) {
	tool := putFileTool()
	props := tool.InputSchema["properties"].(map[string]interface{})
	for _, k := range []string{"box", "path", "content", "content_base64", "mode", "sha256"} {
		if _, ok := props[k]; !ok {
			t.Errorf("schema has no %s", k)
		}
	}
	for _, k := range []string{"local_path", "file"} {
		if _, ok := props[k]; ok {
			t.Errorf("schema has %s: the tool must not read files on the MCP host", k)
		}
	}
	if got := toolScopeAssignments()["put_file"]; got != auth.ScopeSSHWrite {
		t.Errorf("scope = %q, want %q (the daemon's own gate)", got, auth.ScopeSSHWrite)
	}
	srv := &Server{}
	srv.registerTools()
	registered := false
	for _, tl := range srv.tools {
		if tl.Name == "put_file" {
			registered = true
		}
	}
	if !registered {
		t.Error("put_file is not registered")
	}
}

// The tool goes through the CLI's own function, not a copy of it.
func TestPutFileTool_UsesTheCLIFunction(t *testing.T) {
	if reflect.ValueOf(putBoxFileFn).Pointer() != reflect.ValueOf(client.PutBoxFile).Pointer() {
		t.Error("putBoxFileFn is not client.PutBoxFile")
	}
}
