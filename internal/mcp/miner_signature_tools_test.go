package mcp

import (
	"net/url"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestMinerSignatureTools_RegisteredAndScoped(t *testing.T) {
	srv := &Server{}
	srv.registerTools()
	want := map[string]string{
		"list_miner_signatures":  auth.ScopeSecurityRead,
		"add_miner_signature":    auth.ScopeSecurityWrite,
		"remove_miner_signature": auth.ScopeSecurityWrite,
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

func TestListMinerSignaturesTool(t *testing.T) {
	resp, _ := protojson.Marshal(&pb.ListMinerSignaturesResponse{
		BaselineVersion: "v9",
		Signatures:      []*pb.MinerSignature{{Kind: pb.MinerSignatureKind_MINER_SIGNATURE_KIND_NAME, Pattern: "xmrig", Builtin: true}},
	})
	srv, got := policyServer(t, resp)
	out, err := handleListMinerSignatures(NewClient(srv.URL, "tok"), map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	if got.method != "GET" || got.path != "/v1/security/miner-signatures" {
		t.Errorf("request = %s %s", got.method, got.path)
	}
	if !strings.Contains(out, "xmrig") || !strings.Contains(out, "v9") {
		t.Errorf("output lacks signatures: %s", out)
	}
}

func TestAddMinerSignatureTool(t *testing.T) {
	resp, _ := protojson.Marshal(&pb.AddMinerSignatureResponse{})
	srv, got := policyServer(t, resp)
	_, err := handleAddMinerSignature(NewClient(srv.URL, "tok"), map[string]interface{}{
		"kind": "ARGV", "pattern": "--coin ", "label": "pool flag",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.method != "POST" || got.path != "/v1/security/miner-signatures" {
		t.Errorf("request = %s %s", got.method, got.path)
	}
	var req pb.AddMinerSignatureRequest
	if err := protojson.Unmarshal([]byte(got.body), &req); err != nil {
		t.Fatalf("body: %v (%s)", err, got.body)
	}
	s := req.GetSignature()
	if s.GetKind() != pb.MinerSignatureKind_MINER_SIGNATURE_KIND_ARGV || s.GetPattern() != "--coin " || s.GetLabel() != "pool flag" {
		t.Errorf("signature = %v", s)
	}
}

func TestRemoveMinerSignatureTool(t *testing.T) {
	resp, _ := protojson.Marshal(&pb.RemoveMinerSignatureResponse{})
	srv, got := policyServer(t, resp)
	_, err := handleRemoveMinerSignature(NewClient(srv.URL, "tok"), map[string]interface{}{"kind": "argv", "pattern": "/tmp/x --coin"})
	if err != nil {
		t.Fatal(err)
	}
	if got.method != "DELETE" || got.path != "/v1/security/miner-signatures" || got.body != "" {
		t.Errorf("request = %s %s body=%q", got.method, got.path, got.body)
	}
	q, _ := url.ParseQuery(got.query)
	if q.Get("kind") != "MINER_SIGNATURE_KIND_ARGV" || q.Get("pattern") != "/tmp/x --coin" {
		t.Errorf("query = %q", got.query)
	}
}

func TestMinerSignatureTools_Validation(t *testing.T) {
	srv, got := policyServer(t, []byte(`{}`))
	c := NewClient(srv.URL, "tok")
	tests := []struct {
		name string
		fn   func(API, map[string]interface{}) (string, error)
		args map[string]interface{}
	}{
		{"add bad kind", handleAddMinerSignature, map[string]interface{}{"kind": "regex", "pattern": "x"}},
		{"add missing kind", handleAddMinerSignature, map[string]interface{}{"pattern": "x"}},
		{"add missing pattern", handleAddMinerSignature, map[string]interface{}{"kind": "name"}},
		{"remove bad kind", handleRemoveMinerSignature, map[string]interface{}{"kind": "x", "pattern": "x"}},
		{"remove missing pattern", handleRemoveMinerSignature, map[string]interface{}{"kind": "name"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.fn(c, tt.args); err == nil {
				t.Fatal("want error")
			}
			if got.method != "" {
				t.Errorf("request sent despite invalid args: %s", got.method)
			}
		})
	}
}

func TestProcessPolicySetTool_KillProcess(t *testing.T) {
	resp, _ := protojson.Marshal(&pb.SetProcessPolicyResponse{})
	for _, tt := range []struct {
		name     string
		args     map[string]interface{}
		wantKill *bool
	}{
		{"true", map[string]interface{}{"kill_process": true}, ptrBool(true)},
		{"false", map[string]interface{}{"kill_process": false}, ptrBool(false)},
		{"omitted inherits", map[string]interface{}{"action": "alert"}, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv, got := policyServer(t, resp)
			if _, err := handleSecurityProcessPolicySet(NewClient(srv.URL, "tok"), tt.args); err != nil {
				t.Fatal(err)
			}
			var req pb.SetProcessPolicyRequest
			if err := protojson.Unmarshal([]byte(got.body), &req); err != nil {
				t.Fatal(err)
			}
			pol := req.GetPolicy()
			if (tt.wantKill == nil) != (pol.KillProcess == nil) || (tt.wantKill != nil && *tt.wantKill != pol.GetKillProcess()) {
				t.Errorf("kill_process = %v, want %v", pol.KillProcess, tt.wantKill)
			}
		})
	}
	// clear_override cannot be combined with kill_process.
	srv, _ := policyServer(t, resp)
	if _, err := handleSecurityProcessPolicySet(NewClient(srv.URL, "tok"), map[string]interface{}{"container": "b", "clear_override": true, "kill_process": true}); err == nil {
		t.Error("clear_override + kill_process should be rejected")
	}
}

func ptrBool(b bool) *bool { return &b }
