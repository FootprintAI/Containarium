package agentbox

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// Per-workstream test file (NEW; not appended to a shared *_test.go)
// per the Phase-1 lesson. Focused on the dispatcher + envelope shape
// — the underlying compose ops (discoverStacks, systemctlUser, etc.)
// touch real systemd/podman and aren't worth mocking; the existing
// MCP-handler tests in compose_test.go cover the inner-logic edges.

func TestRunComposeCLI_NoArgs(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := RunComposeCLI(nil, &out, &errBuf)
	if code != 2 {
		t.Errorf("exit code = %d, want 2 (usage error)", code)
	}
	if !strings.Contains(errBuf.String(), "usage:") {
		t.Errorf("stderr missing usage line: %q", errBuf.String())
	}
	if out.Len() != 0 {
		t.Errorf("stdout should be empty on usage error, got: %q", out.String())
	}
}

func TestRunComposeCLI_UnknownVerb(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := RunComposeCLI([]string{"nonsense"}, &out, &errBuf)
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if !strings.Contains(errBuf.String(), "unknown compose verb") {
		t.Errorf("stderr missing 'unknown' diagnosis: %q", errBuf.String())
	}
}

func TestRunComposeCLI_EnableRequiresDir(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := RunComposeCLI([]string{"enable"}, &out, &errBuf)
	if code != 1 {
		t.Errorf("exit code = %d, want 1 (operation failure)", code)
	}
	// stdout must be valid JSON with ok:false; that's the daemon-parse
	// contract — even on failure, daemon expects JSON it can introspect.
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("stdout not valid JSON: %v\nbody: %q", err, out.String())
	}
	if got["ok"] != false {
		t.Errorf("ok field = %v, want false", got["ok"])
	}
	if msg, _ := got["error"].(string); !strings.Contains(msg, "--dir is required") {
		t.Errorf("error message missing 'dir' diagnosis: %q", msg)
	}
}

func TestRunComposeCLI_DisableRequiresDir(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := RunComposeCLI([]string{"disable"}, &out, &errBuf)
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("stdout not valid JSON: %v", err)
	}
	if got["ok"] != false {
		t.Errorf("ok = %v, want false", got["ok"])
	}
}

func TestRunComposeCLI_StatusRequiresDir(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := RunComposeCLI([]string{"status"}, &out, &errBuf)
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("stdout not valid JSON: %v", err)
	}
}

func TestRunComposeCLI_StatusMissingComposeFile(t *testing.T) {
	tmp := t.TempDir() // no compose file under here
	var out, errBuf bytes.Buffer
	code := RunComposeCLI([]string{"status", "--dir", tmp}, &out, &errBuf)
	if code != 1 {
		t.Errorf("exit code = %d, want 1 (no compose file)", code)
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("stdout not valid JSON: %v", err)
	}
	if got["ok"] != false {
		t.Errorf("ok = %v, want false", got["ok"])
	}
	if msg, _ := got["error"].(string); !strings.Contains(msg, "no compose file") {
		t.Errorf("error missing 'no compose file': %q", msg)
	}
}

func TestRunComposeCLI_DiscoverEmptyRoot(t *testing.T) {
	// Empty tmp dir → discover returns empty stack list, ok=true.
	tmp := t.TempDir()
	var out, errBuf bytes.Buffer
	code := RunComposeCLI([]string{"discover", "--root", tmp}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr: %q", code, errBuf.String())
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("stdout not valid JSON: %v", err)
	}
	if got["ok"] != true {
		t.Errorf("ok = %v, want true", got["ok"])
	}
	// result.stacks must be empty or absent
	result, _ := got["result"].(map[string]any)
	if result == nil {
		t.Fatal("result missing")
	}
	if stacks, ok := result["stacks"].([]any); ok && len(stacks) != 0 {
		t.Errorf("expected empty stacks, got %d", len(stacks))
	}
}
