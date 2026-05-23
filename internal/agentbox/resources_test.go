package agentbox

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

// callCIContextResource invokes the resource handler and returns the
// (single) text body it produced. Mirrors callTool in agentbox_test.go.
func callCIContextResource(t *testing.T) mcp.TextResourceContents {
	t.Helper()
	req := mcp.ReadResourceRequest{}
	req.Params.URI = ciContextResourceURI
	out, err := handleCIContextRead(context.Background(), req)
	if err != nil {
		t.Fatalf("handleCIContextRead: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 resource content, got %d", len(out))
	}
	trc, ok := out[0].(mcp.TextResourceContents)
	if !ok {
		t.Fatalf("expected TextResourceContents, got %T", out[0])
	}
	return trc
}

func TestCIContext_FilePresentReturnsExactBytes(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "ci-context.json")

	payload := `{"schema_version":"1.0","platform":"github","pr_number":1234,"failing_test":"TestExposePort_TLSHandshake"}`
	if err := os.WriteFile(p, []byte(payload), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(ciContextPathEnv, p)

	trc := callCIContextResource(t)
	if trc.URI != ciContextResourceURI {
		t.Errorf("URI = %q, want %q", trc.URI, ciContextResourceURI)
	}
	if trc.MIMEType != "application/json" {
		t.Errorf("MIMEType = %q, want application/json", trc.MIMEType)
	}
	if trc.Text != payload {
		t.Errorf("Text = %q, want %q (must be byte-for-byte passthrough)", trc.Text, payload)
	}
}

func TestCIContext_FileAbsentReturnsValidJSONStub(t *testing.T) {
	// Point at a path that explicitly doesn't exist; handler must not
	// error — "no CI context" is a normal state for any non-CI box.
	dir := t.TempDir()
	t.Setenv(ciContextPathEnv, filepath.Join(dir, "does-not-exist.json"))

	trc := callCIContextResource(t)
	if trc.MIMEType != "application/json" {
		t.Errorf("MIMEType = %q, want application/json", trc.MIMEType)
	}

	// The stub must be parseable JSON — agents that assume MIME-type
	// honesty will choke on a non-JSON body.
	var stub struct {
		SchemaVersion string `json:"schema_version"`
		Platform      any    `json:"platform"`
		Available     bool   `json:"available"`
	}
	if err := json.Unmarshal([]byte(trc.Text), &stub); err != nil {
		t.Fatalf("absent-file stub is not valid JSON: %v\nbody: %q", err, trc.Text)
	}
	if stub.Available {
		t.Errorf("absent stub should have available=false, got true")
	}
	if stub.Platform != nil {
		t.Errorf("absent stub should have platform=null, got %v", stub.Platform)
	}
	if stub.SchemaVersion == "" {
		t.Errorf("absent stub should have schema_version set, got empty")
	}
}

func TestCIContext_EnvVarOverrideTakesPrecedence(t *testing.T) {
	// Verify the env var actually steers reads — without this we could
	// accidentally hardcode the default in some refactor and the tests
	// above would still pass (they'd just be silently reading the real
	// /workspace path, if any).
	dir := t.TempDir()
	p := filepath.Join(dir, "custom-location.json")
	if err := os.WriteFile(p, []byte(`{"marker":"env-override-worked"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(ciContextPathEnv, p)

	if got := ciContextPath(); got != p {
		t.Errorf("ciContextPath() = %q, want %q (env override should win)", got, p)
	}

	trc := callCIContextResource(t)
	if trc.Text != `{"marker":"env-override-worked"}` {
		t.Errorf("Text = %q, want env-override payload", trc.Text)
	}
}

func TestCIContext_DefaultPathWhenEnvUnset(t *testing.T) {
	// When the env var is empty, fall back to the canonical /workspace
	// location — that's the contract the containarium-run Action relies
	// on for the resource to "just work" without configuration.
	t.Setenv(ciContextPathEnv, "")
	if got := ciContextPath(); got != defaultCIContextPath {
		t.Errorf("ciContextPath() with empty env = %q, want %q", got, defaultCIContextPath)
	}
}
