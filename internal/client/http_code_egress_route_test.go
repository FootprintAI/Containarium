package client

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// CodingToolEgressPolicyService REST calls (#2378): method + path must match
// the google.api.http mapping in code_egress.proto:
//
//	PUT    /v1/code/egress-policy/{policy.tenant}   (and /v1/code/egress-policy)
//	GET    /v1/code/egress-policy/{tenant}          (and /v1/code/egress-policy)
//	DELETE /v1/code/egress-policy/{tenant}          (and /v1/code/egress-policy)
func TestCodeEgress_HTTPPathsAndDecoding(t *testing.T) {
	var gotMethod, gotPath, gotBody, respBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.EscapedPath()
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, respBody)
	}))
	defer srv.Close()
	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("Set tenant", func(t *testing.T) {
		respBody = `{"policy":{"tenant":"alice","mode":"NETWORK_POLICY_MODE_ENFORCE","egressCidrs":["192.0.2.0/24"],"revision":"5"}}`
		resp, err := c.SetCodingToolEgressPolicy(&pb.SetCodingToolEgressPolicyRequest{Policy: &pb.CodingToolEgressPolicy{
			Tenant: "alice", Mode: pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE, EgressCidrs: []string{"192.0.2.0/24"},
		}})
		if err != nil {
			t.Fatal(err)
		}
		if gotMethod != http.MethodPut || gotPath != "/v1/code/egress-policy/alice" {
			t.Errorf("%s %s", gotMethod, gotPath)
		}
		// body: "policy" — the body is the policy message itself, not a wrapper.
		if !strings.Contains(gotBody, `"egressCidrs":["192.0.2.0/24"]`) || strings.Contains(gotBody, `"policy"`) {
			t.Errorf("body = %s", gotBody)
		}
		if resp.GetPolicy().GetRevision() != 5 {
			t.Errorf("decoded %+v", resp.GetPolicy())
		}
	})
	t.Run("Set cluster default", func(t *testing.T) {
		respBody = `{"policy":{}}`
		if _, err := c.SetCodingToolEgressPolicy(&pb.SetCodingToolEgressPolicyRequest{Policy: &pb.CodingToolEgressPolicy{}}); err != nil {
			t.Fatal(err)
		}
		if gotMethod != http.MethodPut || gotPath != "/v1/code/egress-policy" {
			t.Errorf("%s %s", gotMethod, gotPath)
		}
	})
	t.Run("Get", func(t *testing.T) {
		respBody = `{"effective":{"tenant":"alice","source":"CODING_TOOL_EGRESS_POLICY_SOURCE_NONE"}}`
		resp, err := c.GetCodingToolEgressPolicy(&pb.GetCodingToolEgressPolicyRequest{Tenant: "alice"})
		if err != nil {
			t.Fatal(err)
		}
		if gotMethod != http.MethodGet || gotPath != "/v1/code/egress-policy/alice" {
			t.Errorf("%s %s", gotMethod, gotPath)
		}
		if resp.GetEffective().GetSource() != pb.CodingToolEgressPolicySource_CODING_TOOL_EGRESS_POLICY_SOURCE_NONE {
			t.Errorf("decoded %+v", resp)
		}
	})
	t.Run("Delete", func(t *testing.T) {
		respBody = `{}`
		if _, err := c.DeleteCodingToolEgressPolicy(&pb.DeleteCodingToolEgressPolicyRequest{Tenant: "alice"}); err != nil {
			t.Fatal(err)
		}
		if gotMethod != http.MethodDelete || gotPath != "/v1/code/egress-policy/alice" {
			t.Errorf("%s %s", gotMethod, gotPath)
		}
	})
}
