//go:build !windows

package agentbox

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
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

// callCIPromptResource is the ci-prompt counterpart to
// callCIContextResource — invokes the handler and returns the single
// text body it produced.
func callCIPromptResource(t *testing.T) mcp.TextResourceContents {
	t.Helper()
	req := mcp.ReadResourceRequest{}
	req.Params.URI = ciPromptResourceURI
	out, err := handleCIPromptRead(context.Background(), req)
	if err != nil {
		t.Fatalf("handleCIPromptRead: %v", err)
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

func TestCIPrompt_HandlerReturnsMarkdownPlaybook(t *testing.T) {
	trc := callCIPromptResource(t)

	if trc.URI != ciPromptResourceURI {
		t.Errorf("URI = %q, want %q", trc.URI, ciPromptResourceURI)
	}
	if trc.MIMEType != "text/markdown" {
		t.Errorf("MIMEType = %q, want text/markdown", trc.MIMEType)
	}
	if trc.Text == "" {
		t.Fatal("Text is empty; prompt body must be non-empty")
	}

	// Lock in the headings that agents will actually look for. If a
	// future edit drops these, the prompt has either been gutted or
	// renamed and the test wants to know.
	wantSubstrings := []string{
		"# Debugging a failing CI run in Containarium",
		"## What to read first",
		"## How to work",
		"## How to report",
		"## What NOT to do",
		"containarium://ci-context",
	}
	for _, want := range wantSubstrings {
		if !strings.Contains(trc.Text, want) {
			t.Errorf("prompt body missing expected substring %q", want)
		}
	}
}

func TestCIPrompt_RegisteredOnServer(t *testing.T) {
	// Smoke test: a freshly-created server with RegisterResources called
	// must end up advertising the ci-prompt URI. Catches the kind of
	// regression where someone adds the handler but forgets to wire it
	// into RegisterResources.
	s := server.NewMCPServer("test", "0.0.0",
		server.WithResourceCapabilities(false, false),
	)
	RegisterResources(s)

	req := mcp.ListResourcesRequest{}
	resp := s.HandleMessage(context.Background(), mustMarshalListResources(t, req))
	body := jsonString(t, resp)
	if !strings.Contains(body, ciPromptResourceURI) {
		t.Errorf("ListResources response missing %q\nbody: %s", ciPromptResourceURI, body)
	}
	if !strings.Contains(body, ciContextResourceURI) {
		t.Errorf("ListResources response missing %q (regression in ci-context registration?)\nbody: %s",
			ciContextResourceURI, body)
	}
}

// mustMarshalListResources builds a minimal JSON-RPC envelope for the
// resources/list method so we can drive the MCP server in-process.
func mustMarshalListResources(t *testing.T, _ mcp.ListResourcesRequest) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "resources/list",
		"params":  map[string]any{},
	})
	if err != nil {
		t.Fatalf("marshal list-resources envelope: %v", err)
	}
	return b
}

// jsonString renders any value as compact JSON for substring assertions
// on the ListResources response shape.
func jsonString(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	return string(b)
}
