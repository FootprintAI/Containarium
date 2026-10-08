package server

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// listFailingStore is a policy store whose List is down (an outage).
type listFailingStore struct {
	NetworkPolicyStore
	fail bool
}

func (s *listFailingStore) List(ctx context.Context) ([]*pb.NetworkPolicy, error) {
	if s.fail {
		return nil, errors.New("store unavailable")
	}
	return s.NetworkPolicyStore.List(ctx)
}

// TestRefreshDomains_StoreOutageBacksOff locks down the #2389 review finding:
// when the policy store cannot be listed, Refresh never runs, so the cached
// names stay past due and NextRefreshDelay would floor at 1s — polling the
// failing store every second. An outage must back off to each name's interval.
func TestRefreshDomains_StoreOutageBacksOff(t *testing.T) {
	store := &listFailingStore{NetworkPolicyStore: NewMemNetworkPolicyStore()}
	if err := store.Set(context.Background(), &pb.NetworkPolicy{Tenant: "acme", EgressDomains: []string{"a.example"}}); err != nil {
		t.Fatalf("store.Set: %v", err)
	}
	e := NewNetworkPolicyEnforcer("", store, NewMemTenantRegistry(), nil, nil, nil, false)
	e.ctx = context.Background()
	clk := newResolverClock()
	f := &fakeTTLResolver{answers: map[string]dnsAnswer{"a.example": {Addrs: addrs("192.0.2.5"), TTL: 30 * time.Second}}}
	e.resolver = newDomainResolver(f, clk.now)
	e.refreshDomains()

	store.fail = true
	clk.advance(30 * time.Second) // a.example is now due
	e.refreshDomains()
	if got := e.resolver.NextRefreshDelay(); got != 30*time.Second {
		t.Fatalf("after a store outage NextRefreshDelay = %v, want the 30s interval (not the 1s floor)", got)
	}
	if got := addrStrings(e.resolver.Addrs("a.example")); len(got) != 1 {
		t.Fatalf("an outage must keep the cached addresses, got %v", got)
	}
	if f.calls["a.example"] != 1 {
		t.Fatalf("no lookup should run while the store is down, calls = %d", f.calls["a.example"])
	}
}

// countingTTLResolver is a goroutine-safe fake DNS that counts lookups.
type countingTTLResolver struct {
	calls atomic.Int32
	ttl   time.Duration
}

func (c *countingTTLResolver) LookupAddrsTTL(context.Context, string) (dnsAnswer, error) {
	c.calls.Add(1)
	return dnsAnswer{Addrs: addrs("192.0.2.5"), TTL: c.ttl}, nil
}

// TestDomainRefreshLoop_FollowsTTL drives the real timer loop: with a TTL-0
// record (floored to 1s) the loop re-resolves within a couple of seconds —
// far sooner than the old fixed 60s ticker — and exits on cancel.
func TestDomainRefreshLoop_FollowsTTL(t *testing.T) {
	store := NewMemNetworkPolicyStore()
	if err := store.Set(context.Background(), &pb.NetworkPolicy{Tenant: "acme", EgressDomains: []string{"a.example"}}); err != nil {
		t.Fatalf("store.Set: %v", err)
	}
	e := NewNetworkPolicyEnforcer("", store, NewMemTenantRegistry(), nil, nil, nil, false)
	e.ctx, e.cancel = context.WithCancel(context.Background())
	dns := &countingTTLResolver{ttl: 0}
	e.resolver = newDomainResolver(dns, time.Now)
	e.refreshDomains() // what Start does before launching the loop

	e.wg.Add(1)
	go e.domainRefreshLoop()
	deadline := time.Now().Add(5 * time.Second)
	for dns.calls.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	e.cancel()
	e.wg.Wait()
	if got := dns.calls.Load(); got < 3 {
		t.Fatalf("loop re-resolved %d times in 5s, want >= 3 (TTL-driven 1s cadence)", got)
	}
}

// TestCompiledPolicies_DomainAddrsReachEnforcerAsIPv4Only locks down #2379:
// the resolver is dual-stack, but the enforcer's BPF egress map is IPv4-only,
// so a domain's AAAA answers must never be folded into its allow-list.
func TestCompiledPolicies_DomainAddrsReachEnforcerAsIPv4Only(t *testing.T) {
	store := NewMemNetworkPolicyStore()
	if err := store.Set(context.Background(), &pb.NetworkPolicy{
		Tenant:        "acme",
		EgressDomains: []string{"dual.example"},
	}); err != nil {
		t.Fatalf("store.Set: %v", err)
	}
	e := NewNetworkPolicyEnforcer("", store, NewMemTenantRegistry(), nil, nil, nil, false)
	e.ctx = context.Background()
	e.resolver = newDomainResolver(&fakeTTLResolver{answers: map[string]dnsAnswer{
		"dual.example": {Addrs: addrs("192.0.2.5", "2001:db8::5"), TTL: 30 * time.Second},
	}}, newResolverClock().now)
	e.refreshDomains()

	if got := len(e.resolver.Addrs("dual.example")); got != 2 {
		t.Fatalf("setup: resolver should hold both families, got %d addrs", got)
	}
	compiled, err := e.compiledPolicies(context.Background())
	if err != nil {
		t.Fatalf("compiledPolicies: %v", err)
	}
	cidrs := compiled["acme"].EgressCIDRs
	if len(cidrs) != 1 || cidrs[0] != netip.MustParsePrefix("192.0.2.5/32") {
		t.Fatalf("EgressCIDRs = %v, want only [192.0.2.5/32]", cidrs)
	}
}

// fakeInspector is a containerInspector that counts GetRawInstance calls so a
// test can assert the reconcile no longer inspects every container every cycle
// (#654).
type fakeInspector struct {
	containers []incus.ContainerInfo
	veth       string
	rawCalls   map[string]int
}

func (f *fakeInspector) ListContainers() ([]incus.ContainerInfo, error) { return f.containers, nil }

func (f *fakeInspector) GetRawInstance(name string) (map[string]string, string, error) {
	f.rawCalls[name]++
	return map[string]string{"volatile.eth0.host_name": f.veth}, "", nil
}

// firstHostIface returns a host interface name that net.InterfaceByName can
// resolve, so the veth-resolution path exercises the real VethIndex lookup
// portably (the name differs across Linux/darwin, e.g. lo vs lo0).
func firstHostIface(t *testing.T) string {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil || len(ifaces) == 0 {
		t.Skipf("no host interfaces available: %v", err)
	}
	return ifaces[0].Name
}

// TestGather_CachesVethToAvoidInspect locks down the #654 fix: a steady running
// container is inspected (GetRawInstance) once, not on every reconcile; the cache
// is evicted when it stops; and it re-inspects after a restart.
func TestGather_CachesVethToAvoidInspect(t *testing.T) {
	veth := firstHostIface(t)
	insp := &fakeInspector{
		containers: []incus.ContainerInfo{{Name: "web-container", State: "running", IPAddress: "10.100.0.42"}},
		veth:       veth,
		rawCalls:   map[string]int{},
	}
	e := NewNetworkPolicyEnforcer("", nil, NewMemTenantRegistry(), insp, nil, nil, false)
	e.ctx = context.Background()

	// First gather: cache miss -> exactly one inspect, veth resolved.
	views, _, err := e.gather(context.Background())
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	if len(views) != 1 || !views[0].HasVeth {
		t.Fatalf("gather views = %+v, want 1 view with HasVeth", views)
	}
	if got := insp.rawCalls["web-container"]; got != 1 {
		t.Fatalf("GetRawInstance calls = %d, want 1 after first gather", got)
	}

	// Repeated gathers while running steady: cache hit, no further inspects.
	for i := 0; i < 5; i++ {
		if _, _, err := e.gather(context.Background()); err != nil {
			t.Fatalf("gather %d: %v", i, err)
		}
	}
	if got := insp.rawCalls["web-container"]; got != 1 {
		t.Fatalf("GetRawInstance calls = %d, want 1 (cached across reconciles)", got)
	}

	// Container stops: the cache entry is evicted so it cannot go stale.
	insp.containers[0].State = "stopped"
	if _, _, err := e.gather(context.Background()); err != nil {
		t.Fatalf("gather (stopped): %v", err)
	}
	if _, ok := e.vethCache["web-container"]; ok {
		t.Fatalf("vethCache still holds web-container after it stopped")
	}

	// Restart: running again -> re-inspect for the (possibly new) veth.
	insp.containers[0].State = "running"
	if _, _, err := e.gather(context.Background()); err != nil {
		t.Fatalf("gather (restarted): %v", err)
	}
	if got := insp.rawCalls["web-container"]; got != 2 {
		t.Fatalf("GetRawInstance calls = %d, want 2 (re-inspect after restart)", got)
	}
}

// TestGather_ExcludesControlPlaneFromTenantTagging locks down #780 step 3: the
// control plane is infrastructure, not a tenant, so gather() must drop it from
// the reconcile views entirely (keeping its IP out of ip_tenant so tenants can
// reach its API as an external dest). Other core services stay tagged/isolated.
func TestGather_ExcludesControlPlaneFromTenantTagging(t *testing.T) {
	insp := &fakeInspector{
		containers: []incus.ContainerInfo{
			{Name: "cld-tenant-container", State: "stopped", IPAddress: "10.100.0.10"},
			{Name: "core-postgres-container", State: "stopped", IPAddress: "10.100.0.11", Role: incus.RolePostgres},
			{Name: "controlplane-container", State: "stopped", IPAddress: "10.100.0.200", Role: incus.RoleControlPlane},
		},
		rawCalls: map[string]int{},
	}
	e := NewNetworkPolicyEnforcer("", nil, NewMemTenantRegistry(), insp, nil, nil, false)
	e.ctx = context.Background()

	views, _, err := e.gather(context.Background())
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	tagged := map[string]bool{}
	for _, v := range views {
		tagged[v.Name] = true
	}
	if tagged["controlplane-container"] {
		t.Error("control plane must be EXCLUDED from tenant tagging (reachable as infra, unenforced source)")
	}
	if !tagged["cld-tenant-container"] {
		t.Error("tenant box must stay tagged (isolated)")
	}
	if !tagged["core-postgres-container"] {
		t.Error("non-control-plane core services must stay tagged (still isolated from tenants)")
	}
}
