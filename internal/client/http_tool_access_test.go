package client

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The tool-access level is sent as the enum's proto JSON name (the gateway
// decodes it into BoxToolAccess), to the documented route, and the response
// decodes back into the enum.
func TestHTTPSetContainerToolAccess_WireFormat(t *testing.T) {
	rec, c := newBodyRecorder(t, `{"toolAccess":"BOX_TOOL_ACCESS_FULL_SUDO"}`)
	resp, err := c.SetContainerToolAccess("alice", pb.BoxToolAccess_BOX_TOOL_ACCESS_FULL_SUDO)
	if err != nil {
		t.Fatalf("SetContainerToolAccess: %v", err)
	}
	if rec.method != http.MethodPost || rec.path != "/v1/containers/alice/tool-access" {
		t.Errorf("request = %s %s; want POST /v1/containers/alice/tool-access", rec.method, rec.path)
	}
	body := rec.object(t)
	if len(body) != 1 || body["tool_access"] != "BOX_TOOL_ACCESS_FULL_SUDO" {
		t.Errorf("body = %v; want only tool_access=BOX_TOOL_ACCESS_FULL_SUDO (enum sent by name)", body)
	}
	if resp.GetToolAccess() != pb.BoxToolAccess_BOX_TOOL_ACCESS_FULL_SUDO {
		t.Errorf("response level = %v", resp.GetToolAccess())
	}
}

// Clearing sends the UNSPECIFIED name, and the gateway omits a zero-valued enum
// from the response, so an empty object must still decode.
func TestHTTPSetContainerToolAccess_ClearAndEmptyResponse(t *testing.T) {
	rec, c := newBodyRecorder(t, `{}`)
	resp, err := c.SetContainerToolAccess("alice", pb.BoxToolAccess_BOX_TOOL_ACCESS_UNSPECIFIED)
	if err != nil {
		t.Fatalf("SetContainerToolAccess: %v", err)
	}
	if got := rec.object(t)["tool_access"]; got != "BOX_TOOL_ACCESS_UNSPECIFIED" {
		t.Errorf("tool_access = %v; want BOX_TOOL_ACCESS_UNSPECIFIED", got)
	}
	if resp.GetToolAccess() != pb.BoxToolAccess_BOX_TOOL_ACCESS_UNSPECIFIED {
		t.Errorf("response level = %v; want UNSPECIFIED", resp.GetToolAccess())
	}
}

// A daemon too old to expose the route (HTTP 404) surfaces as gRPC Unimplemented,
// which `containarium tool-access` turns into a warning rather than a failure.
func TestHTTPSetContainerToolAccess_404IsUnimplemented(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()
	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	_, err = c.SetContainerToolAccess("alice", pb.BoxToolAccess_BOX_TOOL_ACCESS_NONE)
	if status.Code(err) != codes.Unimplemented {
		t.Errorf("error = %v; want codes.Unimplemented", err)
	}
}

func TestHTTPSetContainerToolAccess_ServerErrorIsSurfaced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"not authorized for this tenant"}`))
	}))
	defer srv.Close()
	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	if _, err := c.SetContainerToolAccess("alice", pb.BoxToolAccess_BOX_TOOL_ACCESS_NONE); err == nil || !strings.Contains(err.Error(), "not authorized") {
		t.Errorf("error = %v; want the server's message", err)
	}
}

// GetContainer decodes the container view's toolAccess into the stored string,
// and an absent or unrecognised value never turns into a level (it must not
// widen what a box is recorded as having).
func TestHTTPGetContainer_ToolAccessDecode(t *testing.T) {
	for _, tc := range []struct{ name, field, want string }{
		{"none", `,"toolAccess":"BOX_TOOL_ACCESS_NONE"`, "none"},
		{"build tools", `,"toolAccess":"BOX_TOOL_ACCESS_BUILD_TOOLS"`, "build_tools"},
		{"full sudo", `,"toolAccess":"BOX_TOOL_ACCESS_FULL_SUDO"`, "full_sudo"},
		{"absent (none recorded)", ``, ""},
		{"unspecified", `,"toolAccess":"BOX_TOOL_ACCESS_UNSPECIFIED"`, ""},
		{"unknown name", `,"toolAccess":"BOX_TOOL_ACCESS_ROOT"`, ""},
		{"wrong case", `,"toolAccess":"box_tool_access_full_sudo"`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, c := newBodyRecorder(t, `{"container":{"name":"alice-container","username":"alice","state":"CONTAINER_STATE_RUNNING"`+tc.field+`}}`)
			info, err := c.GetContainer("alice")
			if err != nil {
				t.Fatalf("GetContainer: %v", err)
			}
			if info.ToolAccess != tc.want {
				t.Errorf("ToolAccess = %q; want %q", info.ToolAccess, tc.want)
			}
		})
	}
}
