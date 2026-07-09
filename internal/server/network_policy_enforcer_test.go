package server

import (
	"context"
	"net"
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus"
)

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
