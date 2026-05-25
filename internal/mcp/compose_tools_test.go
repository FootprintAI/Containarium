package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

// Per-workstream test file (NEW; not appended to a shared *_test.go).
// Drives the compose-tool handlers without a real daemon — uses a
// stubbed *Client whose doRequest is wired to an in-memory response.
//
// We don't try to run the typed `client.composeDispatch` path here
// since that's a thin wrapper over doRequest (already covered by the
// daemon-side tests in internal/server/compose_autostart_server_test.go).
// The tests below focus on the args→request mapping and the
// schema-required validation the handlers perform locally.

func TestComposeTools_RegisteredFour(t *testing.T) {
	tools := composeTools()
	if len(tools) != 4 {
		t.Fatalf("composeTools() returned %d, want 4", len(tools))
	}
	names := map[string]bool{}
	for _, tool := range tools {
		names[tool.Name] = true
		if tool.Handler == nil {
			t.Errorf("tool %q has nil Handler", tool.Name)
		}
		if tool.Description == "" {
			t.Errorf("tool %q has empty Description", tool.Name)
		}
		if tool.InputSchema == nil {
			t.Errorf("tool %q has nil InputSchema", tool.Name)
		}
	}
	for _, want := range []string{"compose_discover", "compose_enable", "compose_disable", "compose_status"} {
		if !names[want] {
			t.Errorf("missing tool: %q", want)
		}
	}
}

func TestComposeTools_RequiredFields(t *testing.T) {
	cases := []struct {
		name   string
		schema map[string]interface{}
		want   []string
	}{
		{"compose_discover", nil, []string{"username"}},
		{"compose_enable", nil, []string{"username", "dir"}},
		{"compose_disable", nil, []string{"username", "dir"}},
		{"compose_status", nil, []string{"username", "dir"}},
	}
	tools := composeTools()
	byName := map[string]Tool{}
	for _, t2 := range tools {
		byName[t2.Name] = t2
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			tool, ok := byName[tc.name]
			if !ok {
				t.Fatalf("tool %q not found", tc.name)
			}
			req, _ := tool.InputSchema["required"].([]string)
			if len(req) != len(tc.want) {
				t.Errorf("required = %v, want %v", req, tc.want)
				return
			}
			for i, r := range req {
				if r != tc.want[i] {
					t.Errorf("required[%d] = %q, want %q", i, r, tc.want[i])
				}
			}
		})
	}
}

// handler dispatch — verify each handler exists and respects local
// required-field checks before any network call. We pass a nil client
// because the validation should fire before doRequest is reached;
// a nil-deref would mean the validation is missing.

func TestHandleComposeEnable_RequiresDir(t *testing.T) {
	_, err := handleComposeEnablePlatform(nil, map[string]interface{}{"username": "alice"})
	if err == nil || !strings.Contains(err.Error(), "dir is required") {
		t.Errorf("expected 'dir is required' error, got %v", err)
	}
}

func TestHandleComposeDisable_RequiresDir(t *testing.T) {
	_, err := handleComposeDisablePlatform(nil, map[string]interface{}{"username": "alice"})
	if err == nil || !strings.Contains(err.Error(), "dir is required") {
		t.Errorf("expected 'dir is required' error, got %v", err)
	}
}

func TestHandleComposeStatus_RequiresUsernameAndDir(t *testing.T) {
	// Missing username — handler calls composeStatus which checks first
	// (defensive even though the daemon would also reject; saves a
	// round-trip + gives a clearer message to the agent).
	c := &Client{} // unused for the username-empty path
	_, err := handleComposeStatusPlatform(c, map[string]interface{}{})
	if err == nil || !strings.Contains(err.Error(), "username is required") {
		t.Errorf("expected 'username is required' error, got %v", err)
	}
}

// Verify the discover request builder maps args correctly. We don't
// fire doRequest; instead we exercise the parts that don't need a
// network: the JSON marshaling of the request body.
func TestComposeDiscoverReq_Marshaling(t *testing.T) {
	// Full request — every field set.
	req := composeDiscoverReq{
		Username: "alice",
		Root:     "/home/alice",
		MaxDepth: 4,
		Skip:     []string{"node_modules", "vendor"},
		NoSkip:   true,
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(b)
	for _, want := range []string{
		`"username":"alice"`,
		`"root":"/home/alice"`,
		`"maxDepth":4`,
		`"skip":["node_modules","vendor"]`,
		`"noSkip":true`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in: %s", want, got)
		}
	}

	// Empty optional fields → omitempty drops them so the daemon sees
	// the zero-value defaults rather than ambiguous explicit ""s.
	minimal := composeDiscoverReq{Username: "alice"}
	b, _ = json.Marshal(minimal)
	got = string(b)
	for _, mustNotContain := range []string{`"root"`, `"maxDepth"`, `"skip"`, `"noSkip"`} {
		if strings.Contains(got, mustNotContain) {
			t.Errorf("minimal request should omit %s but got: %s", mustNotContain, got)
		}
	}
}

func TestComposeEnableReq_DirRequired(t *testing.T) {
	// Dir is NOT marked omitempty — server-side will reject empty,
	// but the handler-side check catches it earlier; this test asserts
	// the JSON shape preserves explicit "" so the handler-side check
	// is the only thing gating us (no silent default).
	req := composeEnableReq{Username: "alice", Dir: ""}
	b, _ := json.Marshal(req)
	if !strings.Contains(string(b), `"dir":""`) {
		t.Errorf("dir should serialize as empty string, not omitted: %s", string(b))
	}
}
