package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/codeegress"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

type recordingAudit struct{ entries []*audit.AuditEntry }

func (r *recordingAudit) Log(_ context.Context, e *audit.AuditEntry) error {
	r.entries = append(r.entries, e)
	return nil
}

func newTestCodeEgressServer() (*CodingToolEgressPolicyServer, *recordingAudit) {
	s := NewCodingToolEgressPolicyServer(NewMemCodingToolEgressPolicyStore())
	a := &recordingAudit{}
	s.SetAuditStore(a)
	s.SetImplicit(codeegress.Implicit{GatewayEndpoint: "gateway.example.internal:8080"})
	return s, a
}

func ceAdminCtx() context.Context {
	return auth.ContextWithTestSubject(context.Background(), "root-admin", auth.RoleAdmin)
}

func ceTenantCtx(user string, scopes ...string) context.Context {
	return auth.ContextWithTestSubjectScopes(context.Background(), user, []string{"user"}, scopes)
}

func codeOf(err error) codes.Code { return status.Code(err) }

func setReq(tenant string, mode pb.NetworkPolicyMode, cidrs, domains []string) *pb.SetCodingToolEgressPolicyRequest {
	return &pb.SetCodingToolEgressPolicyRequest{Policy: &pb.CodingToolEgressPolicy{
		Tenant: tenant, Mode: mode, EgressCidrs: cidrs, EgressDomains: domains,
	}}
}

func TestCodeEgressSetPolicy_AdminOnly(t *testing.T) {
	s, a := newTestCodeEgressServer()
	req := setReq("alice", pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE, []string{"192.0.2.0/24"}, nil)

	cases := []struct {
		name string
		ctx  context.Context
		want codes.Code
	}{
		{"no subject", context.Background(), codes.Unauthenticated},
		{"tenant itself", ceTenantCtx("alice"), codes.PermissionDenied},
		{"tenant with the read scope", ceTenantCtx("alice", auth.ScopeCodeEgressRead), codes.PermissionDenied},
		{"wildcard scope without the admin role", ceTenantCtx("alice", auth.ScopeWildcard), codes.PermissionDenied},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := s.SetCodingToolEgressPolicy(tc.ctx, req); codeOf(err) != tc.want {
				t.Errorf("Set = %v, want %v", err, tc.want)
			}
			if _, err := s.DeleteCodingToolEgressPolicy(tc.ctx, &pb.DeleteCodingToolEgressPolicyRequest{Tenant: "alice"}); codeOf(err) != tc.want {
				t.Errorf("Delete = %v, want %v", err, tc.want)
			}
		})
	}
	if _, err := s.store.Get(context.Background(), "alice"); err == nil {
		t.Fatal("a denied Set stored a policy")
	}
	if len(a.entries) != 0 {
		t.Fatalf("a denied change wrote audit entries: %+v", a.entries)
	}

	resp, err := s.SetCodingToolEgressPolicy(ceAdminCtx(), req)
	if err != nil {
		t.Fatalf("admin Set: %v", err)
	}
	if resp.GetPolicy().GetRevision() <= 0 || resp.GetPolicy().GetUpdatedBy() != "root-admin" {
		t.Errorf("admin Set echoed %+v", resp.GetPolicy())
	}
}

func TestCodeEgressSetPolicy_Validation(t *testing.T) {
	s, a := newTestCodeEgressServer()
	ok, err := s.SetCodingToolEgressPolicy(ceAdminCtx(), setReq("alice", pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE, []string{"192.0.2.0/24"}, []string{"api.example.com"}))
	if err != nil {
		t.Fatalf("valid Set: %v", err)
	}
	rev := ok.GetPolicy().GetRevision()
	auditsBefore := len(a.entries)

	bad := []struct {
		name string
		req  *pb.SetCodingToolEgressPolicyRequest
	}{
		{"invalid cidr", setReq("alice", pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE, []string{"not-a-cidr"}, nil)},
		{"invalid ipv6 cidr", setReq("alice", pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE, []string{"2001:db8::/129"}, nil)},
		{"invalid domain", setReq("alice", pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE, nil, []string{"https://api.example.com"})},
		{"unknown mode", setReq("alice", pb.NetworkPolicyMode(99), nil, nil)},
		// No default mode: a forgotten mode must not store a log-only policy.
		{"unspecified mode", setReq("alice", pb.NetworkPolicyMode_NETWORK_POLICY_MODE_UNSPECIFIED, []string{"192.0.2.0/24"}, nil)},
		{"unspecified mode, cluster default", setReq("", pb.NetworkPolicyMode_NETWORK_POLICY_MODE_UNSPECIFIED, nil, nil)},
		{"missing policy", &pb.SetCodingToolEgressPolicyRequest{}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := s.SetCodingToolEgressPolicy(ceAdminCtx(), tc.req); codeOf(err) != codes.InvalidArgument {
				t.Fatalf("Set = %v, want InvalidArgument", err)
			}
			got, err := s.store.Get(context.Background(), "alice")
			if err != nil || got.GetRevision() != rev || got.GetEgressCidrs()[0] != "192.0.2.0/24" {
				t.Fatalf("a rejected Set changed the stored policy: %+v, %v (want revision %d)", got, err, rev)
			}
		})
	}
	if len(a.entries) != auditsBefore {
		t.Errorf("a rejected Set wrote an audit entry")
	}
}

func TestSetGetPolicy_AdminRoundTrip(t *testing.T) {
	s, _ := newTestCodeEgressServer()
	set, err := s.SetCodingToolEgressPolicy(ceAdminCtx(), setReq("alice", pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE,
		[]string{"192.0.2.9/24", "2001:db8::/32"}, []string{"API.Example.com."}))
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got := set.GetPolicy().GetEgressCidrs(); len(got) != 2 || got[0] != "192.0.2.0/24" {
		t.Errorf("Set must echo the normalized form, got %v", got)
	}
	got, err := s.GetCodingToolEgressPolicy(ceAdminCtx(), &pb.GetCodingToolEgressPolicyRequest{Tenant: "alice"})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.GetPolicy().GetRevision() != set.GetPolicy().GetRevision() || got.GetPolicy().GetEgressDomains()[0] != "api.example.com" {
		t.Errorf("Get = %+v, want what Set stored %+v", got.GetPolicy(), set.GetPolicy())
	}
	eff := got.GetEffective()
	if !eff.GetRestricted() || eff.GetSource() != pb.CodingToolEgressPolicySource_CODING_TOOL_EGRESS_POLICY_SOURCE_TENANT ||
		eff.GetRevision() != set.GetPolicy().GetRevision() || len(eff.GetImplicit()) != 2 {
		t.Errorf("effective = %+v", eff)
	}
}

func TestGetPolicy_UnsetIsUnrestricted(t *testing.T) {
	s, _ := newTestCodeEgressServer()
	got, err := s.GetCodingToolEgressPolicy(ceAdminCtx(), &pb.GetCodingToolEgressPolicyRequest{Tenant: "alice"})
	if err != nil {
		t.Fatalf("Get with nothing set must not fail: %v", err)
	}
	if got.GetPolicy() != nil {
		t.Errorf("no stored policy expected, got %+v", got.GetPolicy())
	}
	if got.GetEffective().GetRestricted() || got.GetEffective().GetSource() != pb.CodingToolEgressPolicySource_CODING_TOOL_EGRESS_POLICY_SOURCE_NONE {
		t.Errorf("unset must be unrestricted, got %+v", got.GetEffective())
	}
}

func TestGetPolicy_ClusterDefaultApplies(t *testing.T) {
	s, _ := newTestCodeEgressServer()
	if _, err := s.SetCodingToolEgressPolicy(ceAdminCtx(), setReq("", pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE, nil, nil)); err != nil {
		t.Fatalf("Set default: %v", err)
	}
	got, err := s.GetCodingToolEgressPolicy(ceAdminCtx(), &pb.GetCodingToolEgressPolicyRequest{Tenant: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if got.GetPolicy() != nil {
		t.Errorf("alice has no policy of her own, got %+v", got.GetPolicy())
	}
	eff := got.GetEffective()
	if eff.GetSource() != pb.CodingToolEgressPolicySource_CODING_TOOL_EGRESS_POLICY_SOURCE_CLUSTER_DEFAULT || !eff.GetDenyAll() {
		t.Errorf("empty ENFORCE default must give deny-all from the cluster default, got %+v", eff)
	}
	def, err := s.GetCodingToolEgressPolicy(ceAdminCtx(), &pb.GetCodingToolEgressPolicyRequest{})
	if err != nil || def.GetPolicy() == nil || def.GetPolicy().GetTenant() != "" {
		t.Errorf("Get of the cluster default = %+v, %v", def, err)
	}
}

func TestGetPolicy_Authorization(t *testing.T) {
	s, _ := newTestCodeEgressServer()
	if _, err := s.SetCodingToolEgressPolicy(ceAdminCtx(), setReq("alice", pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE, nil, nil)); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		ctx    context.Context
		tenant string
		want   codes.Code
	}{
		{"admin, any tenant", ceAdminCtx(), "bob", codes.OK},
		{"admin, cluster default", ceAdminCtx(), "", codes.OK},
		{"tenant itself with the read scope", ceTenantCtx("alice", auth.ScopeCodeEgressRead), "alice", codes.OK},
		{"tenant itself without the scope", ceTenantCtx("alice"), "alice", codes.PermissionDenied},
		{"tenant itself with an unrelated scope", ceTenantCtx("alice", auth.ScopeNetworkPolicyRead), "alice", codes.PermissionDenied},
		{"read scope, another tenant", ceTenantCtx("alice", auth.ScopeCodeEgressRead), "bob", codes.PermissionDenied},
		{"read scope, cluster default", ceTenantCtx("alice", auth.ScopeCodeEgressRead), "", codes.PermissionDenied},
		{"no subject", context.Background(), "alice", codes.Unauthenticated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.GetCodingToolEgressPolicy(tc.ctx, &pb.GetCodingToolEgressPolicyRequest{Tenant: tc.tenant})
			if codeOf(err) != tc.want {
				t.Errorf("Get = %v, want %v", err, tc.want)
			}
		})
	}
}

// codeEgressAuditDetail mirrors what the server writes, so the test reads it
// as a typed value.
type codeEgressAuditDetailForTest struct {
	PreviousRevision int64  `json:"previous_revision"`
	Revision         int64  `json:"revision"`
	Mode             string `json:"mode"`
	CIDRCount        int    `json:"cidr_count"`
	DomainCount      int    `json:"domain_count"`
}

func TestCodeEgressPolicy_AuditEntryPerChange(t *testing.T) {
	s, a := newTestCodeEgressServer()
	first, err := s.SetCodingToolEgressPolicy(ceAdminCtx(), setReq("alice", pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE,
		[]string{"192.0.2.0/24", "198.51.100.0/24"}, []string{"api.example.com"}))
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.SetCodingToolEgressPolicy(ceAdminCtx(), setReq("alice", pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteCodingToolEgressPolicy(ceAdminCtx(), &pb.DeleteCodingToolEgressPolicyRequest{Tenant: "alice"}); err != nil {
		t.Fatal(err)
	}
	// A read is not a change.
	if _, err := s.GetCodingToolEgressPolicy(ceAdminCtx(), &pb.GetCodingToolEgressPolicyRequest{Tenant: "alice"}); err != nil {
		t.Fatal(err)
	}

	if len(a.entries) != 3 {
		t.Fatalf("want one audit entry per change (3), got %d: %+v", len(a.entries), a.entries)
	}
	want := []struct {
		action string
		detail codeEgressAuditDetailForTest
	}{
		{"code_egress_policy.set", codeEgressAuditDetailForTest{0, first.GetPolicy().GetRevision(), "NETWORK_POLICY_MODE_ENFORCE", 2, 1}},
		{"code_egress_policy.set", codeEgressAuditDetailForTest{first.GetPolicy().GetRevision(), second.GetPolicy().GetRevision(), "NETWORK_POLICY_MODE_LOG_ONLY", 0, 0}},
		{"code_egress_policy.delete", codeEgressAuditDetailForTest{PreviousRevision: second.GetPolicy().GetRevision()}},
	}
	for i, e := range a.entries {
		if e.Action != want[i].action || e.ResourceType != "coding_tool_egress_policy" || e.ResourceID != "alice" || e.Username != "root-admin" {
			t.Errorf("entry %d = %+v", i, e)
		}
		var got codeEgressAuditDetailForTest
		if err := json.Unmarshal([]byte(e.Detail), &got); err != nil {
			t.Fatalf("entry %d detail is not JSON: %q", i, e.Detail)
		}
		if got != want[i].detail {
			t.Errorf("entry %d detail = %+v, want %+v", i, got, want[i].detail)
		}
		// Revisions and counts only: never the destinations themselves.
		for _, leak := range []string{"192.0.2", "198.51.100", "example.com"} {
			if strings.Contains(e.Detail, leak) {
				t.Errorf("entry %d detail carries a destination (%q): %s", i, leak, e.Detail)
			}
		}
	}
}

func TestCodeEgressPolicy_ClusterDefaultAuditResourceID(t *testing.T) {
	s, a := newTestCodeEgressServer()
	if _, err := s.SetCodingToolEgressPolicy(ceAdminCtx(), setReq("", pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE, nil, nil)); err != nil {
		t.Fatal(err)
	}
	if len(a.entries) != 1 || a.entries[0].ResourceID != codeEgressClusterDefaultResourceID {
		t.Fatalf("cluster default audit entry = %+v", a.entries)
	}
}
