package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestHTTPGetToolAccessLevel(t *testing.T) {
	rec, c := newBodyRecorder(t, `{"level":"TOOL_ACCESS_LEVEL_BUILD_TOOLS"}`)
	resp, err := c.GetToolAccessLevel("alice")
	if err != nil {
		t.Fatalf("GetToolAccessLevel: %v", err)
	}
	if rec.method != http.MethodGet || rec.path != "/v1/containers/alice/tool-access" {
		t.Errorf("request = %s %s; want GET /v1/containers/alice/tool-access", rec.method, rec.path)
	}
	if resp.GetLevel() != pb.ToolAccessLevel_TOOL_ACCESS_LEVEL_BUILD_TOOLS {
		t.Errorf("level = %v; want BUILD_TOOLS", resp.GetLevel())
	}
}

// The gateway omits zero-valued enums; a response without "level" must still
// decode, and the CLI treats the missing value as NONE.
func TestHTTPGetToolAccessLevel_EmptyBodyDecodes(t *testing.T) {
	_, c := newBodyRecorder(t, `{}`)
	if _, err := c.GetToolAccessLevel("alice"); err != nil {
		t.Fatalf("GetToolAccessLevel: %v", err)
	}
}

func TestHTTPSetToolAccessLevel_WireFormat(t *testing.T) {
	rec, c := newBodyRecorder(t, `{"message":"ok","level":"TOOL_ACCESS_LEVEL_FULL_SUDO"}`)
	resp, err := c.SetToolAccessLevel("alice", pb.ToolAccessLevel_TOOL_ACCESS_LEVEL_FULL_SUDO)
	if err != nil {
		t.Fatalf("SetToolAccessLevel: %v", err)
	}
	if rec.method != http.MethodPut || rec.path != "/v1/containers/alice/tool-access" {
		t.Errorf("request = %s %s; want PUT /v1/containers/alice/tool-access", rec.method, rec.path)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.raw, &body); err != nil {
		t.Fatalf("body not JSON: %v (%s)", err, rec.raw)
	}
	if len(body) != 1 || body["level"] != "TOOL_ACCESS_LEVEL_FULL_SUDO" {
		t.Errorf("body = %v; want only level=TOOL_ACCESS_LEVEL_FULL_SUDO (enum sent by name)", body)
	}
	if resp.GetLevel() != pb.ToolAccessLevel_TOOL_ACCESS_LEVEL_FULL_SUDO {
		t.Errorf("response level = %v", resp.GetLevel())
	}
}

func TestHTTPToolAccessLevel_ServerErrorIsSurfaced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"not authorized for this tenant"}`))
	}))
	defer srv.Close()
	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	if _, err := c.GetToolAccessLevel("alice"); err == nil || !strings.Contains(err.Error(), "not authorized") {
		t.Errorf("Get error = %v; want the server's message", err)
	}
	if _, err := c.SetToolAccessLevel("alice", pb.ToolAccessLevel_TOOL_ACCESS_LEVEL_NONE); err == nil || !strings.Contains(err.Error(), "not authorized") {
		t.Errorf("Set error = %v; want the server's message", err)
	}
}
