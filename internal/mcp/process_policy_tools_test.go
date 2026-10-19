package mcp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// policyServer records the one request it receives and answers with resp.
func policyServer(t *testing.T, resp []byte) (srv *httptest.Server, got *recordedReq) {
	t.Helper()
	got = &recordedReq{}
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		*got = recordedReq{method: r.Method, path: r.URL.Path, query: r.URL.RawQuery, auth: r.Header.Get("Authorization"), body: string(b)}
		_, _ = w.Write(resp)
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

type recordedReq struct{ method, path, query, auth, body string }

func TestProcessPolicyGetTool(t *testing.T) {
	resp, _ := protojson.Marshal(&pb.GetProcessPolicyResponse{
		Policy:     &pb.ProcessPolicy{Action: pb.ProcessAction_PROCESS_ACTION_THROTTLE},
		IsOverride: true,
		Effective:  &pb.ProcessPolicy{Action: pb.ProcessAction_PROCESS_ACTION_THROTTLE, ThrottleAllowance: "10%"},
	})
	for _, tt := range []struct {
		name      string
		args      map[string]interface{}
		wantQuery string
	}{
		{"backend default", map[string]interface{}{}, ""},
		{"container override", map[string]interface{}{"container": "box-1"}, "container=box-1"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv, got := policyServer(t, resp)
			out, err := handleSecurityProcessPolicyGet(NewClient(srv.URL, "tok"), tt.args)
			if err != nil {
				t.Fatalf("handler: %v", err)
			}
			if got.method != http.MethodGet || got.path != "/v1/security/process-policy" || got.query != tt.wantQuery || got.auth != "Bearer tok" {
				t.Fatalf("request = %+v, want GET /v1/security/process-policy?%s with the bearer", got, tt.wantQuery)
			}
			if !strings.Contains(out, "PROCESS_ACTION_THROTTLE") || !strings.Contains(out, "10%") {
				t.Errorf("output lacks the effective policy: %s", out)
			}
		})
	}
}

func TestProcessPolicySetTool(t *testing.T) {
	resp, _ := protojson.Marshal(&pb.SetProcessPolicyResponse{Effective: &pb.ProcessPolicy{Action: pb.ProcessAction_PROCESS_ACTION_FREEZE}})
	srv, got := policyServer(t, resp)
	_, err := handleSecurityProcessPolicySet(NewClient(srv.URL, "tok"), map[string]interface{}{
		"action": "freeze", "ttl": "2h", "throttle_allowance": "10%", "container": "box-1",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if got.method != http.MethodPut || got.path != "/v1/security/process-policy" {
		t.Fatalf("request = %s %s, want PUT /v1/security/process-policy", got.method, got.path)
	}
	var req pb.SetProcessPolicyRequest
	if err := protojson.Unmarshal([]byte(got.body), &req); err != nil {
		t.Fatalf("body is not a SetProcessPolicyRequest: %v (%s)", err, got.body)
	}
	if req.GetContainer() != "box-1" || req.GetPolicy().GetAction() != pb.ProcessAction_PROCESS_ACTION_FREEZE ||
		req.GetPolicy().GetThrottleAllowance() != "10%" || req.GetPolicy().GetTtl().AsDuration() != 2*time.Hour {
		t.Errorf("request = %+v", &req)
	}
}

func TestProcessPolicySetTool_ClearOverride(t *testing.T) {
	srv, got := policyServer(t, []byte(`{}`))
	if _, err := handleSecurityProcessPolicySet(NewClient(srv.URL, "tok"), map[string]interface{}{"container": "box-1", "clear_override": true}); err != nil {
		t.Fatalf("handler: %v", err)
	}
	var req pb.SetProcessPolicyRequest
	if err := protojson.Unmarshal([]byte(got.body), &req); err != nil {
		t.Fatal(err)
	}
	if !req.GetClearOverride() || req.GetContainer() != "box-1" || req.GetPolicy() != nil {
		t.Errorf("request = %+v, want clear_override on box-1 with no policy", &req)
	}
}

// Invalid input is rejected before any request is made.
func TestProcessPolicySetTool_Validation(t *testing.T) {
	for _, tt := range []struct {
		name string
		args map[string]interface{}
		want string
	}{
		{"unknown action", map[string]interface{}{"action": "kill"}, "allowed values are ALERT, THROTTLE, FREEZE"},
		{"bad ttl", map[string]interface{}{"action": "alert", "ttl": "soon"}, "invalid ttl"},
		{"negative ttl", map[string]interface{}{"ttl": "-1h"}, "invalid ttl"},
		{"nothing to set", map[string]interface{}{}, "nothing to set"},
		{"clear without container", map[string]interface{}{"clear_override": true}, "requires container"},
		{"clear with policy", map[string]interface{}{"container": "b", "clear_override": true, "action": "alert"}, "cannot be combined"},
		{"wrong type", map[string]interface{}{"action": 3}, "invalid arguments"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
			defer srv.Close()
			_, err := handleSecurityProcessPolicySet(NewClient(srv.URL, "tok"), tt.args)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tt.want)
			}
			if called {
				t.Error("a request was sent for invalid input")
			}
		})
	}
}

func TestProcessPolicyReleaseTool(t *testing.T) {
	resp, _ := protojson.Marshal(&pb.ReleaseProcessActionResponse{})
	srv, got := policyServer(t, resp)
	if _, err := handleSecurityProcessPolicyRelease(NewClient(srv.URL, "tok"), map[string]interface{}{"container": "box-1"}); err != nil {
		t.Fatalf("handler: %v", err)
	}
	if got.method != http.MethodPost || got.path != "/v1/security/process-policy/release" || !strings.Contains(got.body, `"container":"box-1"`) {
		t.Fatalf("request = %+v, want POST .../release with container box-1", got)
	}
	if _, err := handleSecurityProcessPolicyRelease(NewClient(srv.URL, "tok"), map[string]interface{}{}); err == nil {
		t.Error("release without a container should fail")
	}
}

func TestProcessPolicyTools_RegisteredAndScoped(t *testing.T) {
	srv := &Server{}
	srv.registerTools()
	want := map[string]string{
		"security_process_policy_get":     auth.ScopeSecurityRead,
		"security_process_policy_set":     auth.ScopeSecurityWrite,
		"security_process_policy_release": auth.ScopeSecurityWrite,
	}
	for _, tool := range srv.tools {
		if s, ok := want[tool.Name]; ok {
			if tool.RequiredScope != s {
				t.Errorf("%s scope = %q, want %q", tool.Name, tool.RequiredScope, s)
			}
			delete(want, tool.Name)
		}
	}
	for name := range want {
		t.Errorf("%s is not registered", name)
	}
}
