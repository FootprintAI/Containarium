package codeegress

import (
	"errors"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestPolicyPath(t *testing.T) {
	cases := map[string]string{
		"":          "/v1/code/egress-policy",
		"alice":     "/v1/code/egress-policy/alice",
		"a b/c":     "/v1/code/egress-policy/a%20b%2Fc",
		"  alice  ": "/v1/code/egress-policy/alice",
	}
	for tenant, want := range cases {
		if got := PolicyPath(tenant); got != want {
			t.Errorf("PolicyPath(%q) = %q, want %q", tenant, got, want)
		}
	}
}

func TestParseMode(t *testing.T) {
	cases := []struct {
		in      string
		want    pb.NetworkPolicyMode
		wantErr bool
	}{
		{"log_only", logOnly, false},
		{"LOG-ONLY", logOnly, false},
		{"enforce", enforce, false},
		{"NETWORK_POLICY_MODE_ENFORCE", enforce, false},
		{"", 0, true},
		{"drop", 0, true},
	}
	for _, tc := range cases {
		got, err := ParseMode(tc.in)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("ParseMode(%q) = %v, %v; want %v, err=%v", tc.in, got, err, tc.want, tc.wantErr)
		}
	}
}

type fakeAPI struct {
	gotGet *pb.GetCodingToolEgressPolicyRequest
	gotSet *pb.SetCodingToolEgressPolicyRequest
	resp   *pb.GetCodingToolEgressPolicyResponse
	err    error
}

func (f *fakeAPI) GetCodingToolEgressPolicy(r *pb.GetCodingToolEgressPolicyRequest) (*pb.GetCodingToolEgressPolicyResponse, error) {
	f.gotGet = r
	return f.resp, f.err
}

func (f *fakeAPI) SetCodingToolEgressPolicy(r *pb.SetCodingToolEgressPolicyRequest) (*pb.SetCodingToolEgressPolicyResponse, error) {
	f.gotSet = r
	return &pb.SetCodingToolEgressPolicyResponse{Policy: r.GetPolicy()}, f.err
}

func TestGetAndSet_ForwardTypedRequests(t *testing.T) {
	f := &fakeAPI{resp: &pb.GetCodingToolEgressPolicyResponse{}}
	if _, err := Get(f, " alice "); err != nil || f.gotGet.GetTenant() != "alice" {
		t.Fatalf("Get forwarded %+v, %v", f.gotGet, err)
	}
	if _, err := Set(f, "alice", enforce, []string{"192.0.2.0/24"}, []string{"api.example.com"}); err != nil {
		t.Fatal(err)
	}
	p := f.gotSet.GetPolicy()
	if p.GetTenant() != "alice" || p.GetMode() != enforce || p.GetEgressCidrs()[0] != "192.0.2.0/24" || p.GetEgressDomains()[0] != "api.example.com" {
		t.Errorf("Set forwarded %+v", p)
	}
	f.err = errors.New("boom")
	if _, err := Get(f, "alice"); err == nil || !strings.Contains(err.Error(), "alice") {
		t.Errorf("Get error should name the tenant, got %v", err)
	}
}

func TestWriteResponse(t *testing.T) {
	cases := []struct {
		name string
		resp *pb.GetCodingToolEgressPolicyResponse
		want []string
		not  []string
	}{
		{
			name: "unrestricted",
			resp: &pb.GetCodingToolEgressPolicyResponse{Effective: Effective("alice", nil, nil, Implicit{})},
			want: []string{"tenant:     alice", "unrestricted", "no policy"},
			not:  []string{"always allowed"},
		},
		{
			name: "deny-all from the cluster default, with implicit entries",
			resp: &pb.GetCodingToolEgressPolicyResponse{Effective: Effective("alice", nil,
				&pb.CodingToolEgressPolicy{Mode: enforce, Revision: 4}, Implicit{GatewayEndpoint: "gateway.example.internal:8080"})},
			want: []string{"cluster default", "revision 4", "enforce", "deny all", "always allowed", "dns resolver", "model gateway", "gateway.example.internal:8080"},
		},
		{
			name: "tenant policy lists",
			resp: &pb.GetCodingToolEgressPolicyResponse{
				Policy: &pb.CodingToolEgressPolicy{Tenant: "alice", Revision: 7, UpdatedBy: "root-admin"},
				Effective: Effective("alice", &pb.CodingToolEgressPolicy{Tenant: "alice", Mode: logOnly, Revision: 7,
					EgressCidrs: []string{"192.0.2.0/24"}, EgressDomains: []string{"api.example.com"}}, nil, Implicit{}),
			},
			want: []string{"tenant policy", "log_only", "192.0.2.0/24", "api.example.com", "stored:     revision 7 by root-admin"},
			not:  []string{"deny all"},
		},
		{
			name: "cluster default key",
			resp: &pb.GetCodingToolEgressPolicyResponse{Effective: Effective("", nil, nil, Implicit{})},
			want: []string{"tenant:     (cluster default)"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var b strings.Builder
			if err := WriteResponse(&b, tc.resp); err != nil {
				t.Fatal(err)
			}
			out := b.String()
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("output missing %q:\n%s", w, out)
				}
			}
			for _, n := range tc.not {
				if strings.Contains(out, n) {
					t.Errorf("output should not contain %q:\n%s", n, out)
				}
			}
		})
	}
}
