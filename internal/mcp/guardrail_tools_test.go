package mcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/guardrailpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// guardrail_policy_get (#2368) is a thin wrapper: it reads the same REST
// endpoint the CLI's HTTP path reads and prints the same text the CLI prints.
func TestGuardrailPolicyGetTool(t *testing.T) {
	resp := &pb.GetGuardrailPolicyResponse{
		Configured: true,
		PolicyHash: "abc123",
		Policy: &pb.ServerGuardrailPolicy{
			Revision: 4,
			Policy: &pb.GuardrailPolicy{Rules: []*pb.GuardrailRule{
				{Kind: pb.GuardrailKind_GUARDRAIL_KIND_SECRET, Action: pb.GuardrailAction_GUARDRAIL_ACTION_BLOCK},
			}},
			TrustedSigners: []*pb.GuardrailTrustedSigner{{KeyId: "k1", PublicKey: []byte("0123456789abcdef0123456789abcdef"), Label: "release key"}},
		},
	}
	body, err := protojson.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	var sawMethod, sawPath, sawAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawMethod, sawPath, sawAuth = r.Method, r.URL.Path, r.Header.Get("Authorization")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	out, err := handleGuardrailPolicyGet(NewClient(srv.URL, "tok"), map[string]interface{}{})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if sawMethod != http.MethodGet || sawPath != "/v1/guardrail/policy" || sawAuth != "Bearer tok" {
		t.Fatalf("request = %s %s (auth %q), want GET /v1/guardrail/policy with the bearer", sawMethod, sawPath, sawAuth)
	}
	if want := guardrailpolicy.Describe(resp); out != want {
		t.Fatalf("tool output differs from the CLI's text:\n got %q\nwant %q", out, want)
	}
	if strings.Contains(out, "0123456789abcdef") {
		t.Fatalf("tool output prints key bytes: %s", out)
	}
}

// The tool is a read gated like other security reads, and there is
// deliberately no MCP write: replacing the policy stays CLI-only.
func TestGuardrailPolicyTools_ReadOnlyAndScoped(t *testing.T) {
	srv := &Server{}
	srv.registerTools()
	found := false
	for _, tool := range srv.tools {
		if strings.HasPrefix(tool.Name, "guardrail_policy_") && tool.Name != "guardrail_policy_get" {
			t.Errorf("unexpected guardrail policy tool %q: policy writes stay CLI-only", tool.Name)
		}
		if tool.Name == "guardrail_policy_get" {
			found = true
			if tool.RequiredScope != auth.ScopeSecurityRead {
				t.Errorf("guardrail_policy_get scope = %q, want %q", tool.RequiredScope, auth.ScopeSecurityRead)
			}
		}
	}
	if !found {
		t.Fatal("guardrail_policy_get is not registered")
	}
}
