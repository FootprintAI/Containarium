package server

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// --- egress preset: storage and enforcer fold-in (#2440) ---

func TestEgressPreset_SurvivesSetGetAndTheStoreClone(t *testing.T) {
	s := newNPServer()
	ctx := npAdminCtx()
	if _, err := s.SetNetworkPolicy(ctx, &pb.SetNetworkPolicyRequest{Policy: &pb.NetworkPolicy{
		Tenant:       "acme",
		Mode:         pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE,
		EgressPreset: pb.EgressPreset_EGRESS_PRESET_ALLOW_LIST_ONLY,
	}}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetNetworkPolicy(ctx, &pb.GetNetworkPolicyRequest{Tenant: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if got.GetPolicy().GetEgressPreset() != pb.EgressPreset_EGRESS_PRESET_ALLOW_LIST_ONLY {
		t.Fatalf("preset lost across set/get: %v", got.GetPolicy().GetEgressPreset())
	}
	// A later set without the preset clears it, like every other field of the
	// allow-policy: set declares the whole allow-policy.
	if _, err := s.SetNetworkPolicy(ctx, &pb.SetNetworkPolicyRequest{Policy: &pb.NetworkPolicy{Tenant: "acme"}}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetNetworkPolicy(ctx, &pb.GetNetworkPolicyRequest{Tenant: "acme"})
	if got.GetPolicy().GetEgressPreset() != pb.EgressPreset_EGRESS_PRESET_UNSPECIFIED {
		t.Errorf("set without a preset must clear it, got %v", got.GetPolicy().GetEgressPreset())
	}
	// An unknown preset is refused at the API, not stored.
	_, err = s.SetNetworkPolicy(ctx, &pb.SetNetworkPolicyRequest{Policy: &pb.NetworkPolicy{Tenant: "acme", EgressPreset: pb.EgressPreset(42)}})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("unknown preset: code = %v, want InvalidArgument", status.Code(err))
	}
}

func TestCompiledPolicies_PresetAllowsTheResolverImplicitly(t *testing.T) {
	store := NewMemNetworkPolicyStore()
	ctx := context.Background()
	for _, p := range []*pb.NetworkPolicy{
		{Tenant: "locked", EgressCidrs: []string{"203.0.113.0/24"}, EgressPreset: pb.EgressPreset_EGRESS_PRESET_ALLOW_LIST_ONLY},
		{Tenant: "plain", EgressCidrs: []string{"203.0.113.0/24"}},
	} {
		if err := store.Set(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	e := NewNetworkPolicyEnforcer("", store, NewMemTenantRegistry(), nil, nil, nil, false)
	e.ctx = ctx
	e.SetImplicitGateway(netip.MustParseAddr("10.100.0.1"))

	got, err := e.compiledPolicies(ctx)
	if err != nil {
		t.Fatal(err)
	}
	has := func(tenant, cidr string) bool {
		for _, p := range got[tenant].EgressCIDRs {
			if p == netip.MustParsePrefix(cidr) {
				return true
			}
		}
		return false
	}
	if !has("locked", "10.100.0.1/32") || !has("locked", "203.0.113.0/24") {
		t.Errorf("preset tenant egress = %v, want the listed CIDR plus the resolver", got["locked"].EgressCIDRs)
	}
	if has("plain", "10.100.0.1/32") {
		t.Errorf("a tenant without the preset must not get the resolver implicitly: %v", got["plain"].EgressCIDRs)
	}
	// What the operator wrote is untouched in the store: `get` shows it as set.
	stored, _ := store.Get(ctx, "locked")
	if len(stored.GetEgressCidrs()) != 1 {
		t.Errorf("stored policy must not carry the implicit entry: %v", stored.GetEgressCidrs())
	}
}

func TestCompiledPolicies_PresetWithUnknownGatewayAddsNothing(t *testing.T) {
	store := NewMemNetworkPolicyStore()
	ctx := context.Background()
	_ = store.Set(ctx, &pb.NetworkPolicy{Tenant: "locked", EgressPreset: pb.EgressPreset_EGRESS_PRESET_ALLOW_LIST_ONLY})
	e := NewNetworkPolicyEnforcer("", store, NewMemTenantRegistry(), nil, nil, nil, false)
	e.ctx = ctx
	got, err := e.compiledPolicies(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(got["locked"].EgressCIDRs); n != 0 {
		t.Errorf("no gateway known, yet egress = %v", got["locked"].EgressCIDRs)
	}
}

// --- PlanNetworkPolicy ---

type fakeAuditQuery struct {
	rows  map[string][]audit.AuditEntry // by action
	total map[string]int32
	err   error
	calls []audit.QueryParams
}

func (f *fakeAuditQuery) Query(_ context.Context, p audit.QueryParams) ([]audit.AuditEntry, int32, error) {
	f.calls = append(f.calls, p)
	if f.err != nil {
		return nil, 0, f.err
	}
	rows := f.rows[p.Action]
	total := int32(len(rows))
	if t, ok := f.total[p.Action]; ok {
		total = t
	}
	return rows, total, nil
}

func denyEntry(ts time.Time, dst string, proto, dport int, dropped bool) audit.AuditEntry {
	d := `{"src":"10.0.0.5","dst":"` + dst + `","proto":` + itoa(proto) + `,"dport":` + itoa(dport) + `,"dropped":false,"virtual_patch":false}`
	if dropped {
		d = strings.Replace(d, `"dropped":false`, `"dropped":true`, 1)
	}
	return audit.AuditEntry{Timestamp: ts, Detail: d}
}

func TestPlanNetworkPolicy_AggregatesAndSubtractsWhatIsAllowed(t *testing.T) {
	s := newNPServer()
	ctx := npAdminCtx()
	now := time.Now()
	q := &fakeAuditQuery{rows: map[string][]audit.AuditEntry{
		"network_policy.deny_logged": {
			denyEntry(now, "140.82.112.3", 6, 443, false),
			denyEntry(now, "140.82.112.3", 6, 443, false),
			denyEntry(now, "203.0.113.9", 6, 443, false), // already in egress_cidrs
			denyEntry(now, "10.100.0.1", 17, 53, false),  // the preset's implicit resolver
		},
		"network_policy.deny_dropped": {
			denyEntry(now, "9.9.9.9", 6, 853, true),
		},
	}}
	s.SetPlanSources(q, netip.MustParseAddr("10.100.0.1"))
	if _, err := s.SetNetworkPolicy(ctx, &pb.SetNetworkPolicyRequest{Policy: &pb.NetworkPolicy{
		Tenant: "acme", EgressCidrs: []string{"203.0.113.0/24"},
		EgressPreset: pb.EgressPreset_EGRESS_PRESET_ALLOW_LIST_ONLY,
	}}); err != nil {
		t.Fatal(err)
	}

	resp, err := s.PlanNetworkPolicy(ctx, &pb.PlanNetworkPolicyRequest{Tenant: "acme", SinceMinutes: 30})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetSinceMinutes() != 30 || resp.GetRowsScanned() != 5 {
		t.Errorf("window/rows = %d/%d", resp.GetSinceMinutes(), resp.GetRowsScanned())
	}
	if len(resp.GetDestinations()) != 2 {
		t.Fatalf("destinations = %+v", resp.GetDestinations())
	}
	top := resp.GetDestinations()[0]
	if top.GetIp() != "140.82.112.3" || top.GetCount() != 2 || top.GetDropped() || top.GetProtocol() != "tcp" || top.GetPort() != 443 {
		t.Errorf("top = %+v", top)
	}
	if d := resp.GetDestinations()[1]; d.GetIp() != "9.9.9.9" || !d.GetDropped() {
		t.Errorf("second = %+v", d)
	}
	// Both actions queried, scoped to the tenant and the window.
	if len(q.calls) != 2 || q.calls[0].ResourceID != "acme" || q.calls[0].ResourceType != "network_policy" || q.calls[0].From.IsZero() {
		t.Errorf("query params = %+v", q.calls)
	}
}

func TestPlanNetworkPolicy_NoPolicyListsEverythingAndSaysSo(t *testing.T) {
	s := newNPServer()
	s.SetPlanSources(&fakeAuditQuery{rows: map[string][]audit.AuditEntry{
		"network_policy.deny_logged": {denyEntry(time.Now(), "1.1.1.1", 6, 443, false)},
	}}, netip.Addr{})
	resp, err := s.PlanNetworkPolicy(npAdminCtx(), &pb.PlanNetworkPolicyRequest{Tenant: "fresh"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetSinceMinutes() != 60 {
		t.Errorf("default window = %d, want 60", resp.GetSinceMinutes())
	}
	if len(resp.GetDestinations()) != 1 || len(resp.GetNotes()) == 0 || !strings.Contains(resp.GetNotes()[0], "no policy") {
		t.Errorf("resp = %+v", resp)
	}
}

func TestPlanNetworkPolicy_DomainsAreNotSubtractedAndNoted(t *testing.T) {
	s := newNPServer()
	s.SetPlanSources(&fakeAuditQuery{}, netip.Addr{})
	_, _ = s.SetNetworkPolicy(npAdminCtx(), &pb.SetNetworkPolicyRequest{Policy: &pb.NetworkPolicy{Tenant: "d", EgressDomains: []string{"api.example.com"}}})
	resp, err := s.PlanNetworkPolicy(npAdminCtx(), &pb.PlanNetworkPolicyRequest{Tenant: "d"})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.GetNotes()) != 1 || !strings.Contains(resp.GetNotes()[0], "egress_domains") {
		t.Errorf("notes = %v", resp.GetNotes())
	}
}

func TestPlanNetworkPolicy_CapsTheWindowAndFlagsTruncation(t *testing.T) {
	s := newNPServer()
	q := &fakeAuditQuery{
		rows:  map[string][]audit.AuditEntry{"network_policy.deny_logged": {denyEntry(time.Now(), "1.1.1.1", 6, 443, false)}},
		total: map[string]int32{"network_policy.deny_logged": 99999},
	}
	s.SetPlanSources(q, netip.Addr{})
	resp, err := s.PlanNetworkPolicy(npAdminCtx(), &pb.PlanNetworkPolicyRequest{Tenant: "t", SinceMinutes: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetSinceMinutes() != 7*24*60 {
		t.Errorf("window = %d, want the one-week cap", resp.GetSinceMinutes())
	}
	if !resp.GetTruncated() {
		t.Error("a total above the returned rows must set truncated")
	}
}

func TestPlanNetworkPolicy_Errors(t *testing.T) {
	ctx := npAdminCtx()
	if _, err := newNPServer().PlanNetworkPolicy(ctx, &pb.PlanNetworkPolicyRequest{Tenant: "x"}); status.Code(err) != codes.Unavailable {
		t.Errorf("no audit store: code = %v, want Unavailable", status.Code(err))
	}
	s := newNPServer()
	s.SetPlanSources(&fakeAuditQuery{}, netip.Addr{})
	if _, err := s.PlanNetworkPolicy(ctx, &pb.PlanNetworkPolicyRequest{Tenant: "  "}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("blank tenant: code = %v, want InvalidArgument", status.Code(err))
	}
	s.SetPlanSources(&fakeAuditQuery{err: errors.New("db down")}, netip.Addr{})
	if _, err := s.PlanNetworkPolicy(ctx, &pb.PlanNetworkPolicyRequest{Tenant: "x"}); status.Code(err) != codes.Internal {
		t.Errorf("query failure: code = %v, want Internal", status.Code(err))
	}
}

func TestPlanNetworkPolicy_RequiresAdminOrReadScope(t *testing.T) {
	s := newNPServer()
	s.SetPlanSources(&fakeAuditQuery{}, netip.Addr{})
	userCtx := auth.ContextWithTestSubject(context.Background(), "alice", "user")
	if _, err := s.PlanNetworkPolicy(userCtx, &pb.PlanNetworkPolicyRequest{Tenant: "x"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("non-admin: code = %v, want PermissionDenied", status.Code(err))
	}
}
