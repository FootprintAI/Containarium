package server

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/safecast"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/network"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #1462: RecipePort can now describe a raw TCP/UDP passthrough instead of an
// HTTP subdomain. These tests exercise exposePorts' branching, the
// fail-loud-on-conflict behavior, and the teardown cascade — all against
// fakes, no real Incus/Postgres needed.

// fakeGetOnlyIncusBackend answers GetContainer with a fixed ContainerInfo and
// panics on every other incus.Backend method — exposePorts only ever calls
// Manager.Get, which is the only method this needs to stand in for.
type fakeGetOnlyIncusBackend struct {
	incus.Backend
	info *incus.ContainerInfo
}

func (f *fakeGetOnlyIncusBackend) GetContainer(name string) (*incus.ContainerInfo, error) {
	return f.info, nil
}

// fakePassthroughStore is an in-memory network.PassthroughStore for tests
// that don't want a real Postgres round trip.
type fakePassthroughStore struct {
	byKey map[string]*network.PassthroughRecord // "port/protocol" -> record
}

func newFakePassthroughStore() *fakePassthroughStore {
	return &fakePassthroughStore{byKey: map[string]*network.PassthroughRecord{}}
}

func passthroughKey(port int, protocol string) string {
	return fmt.Sprintf("%s/%d", protocol, port)
}

func (f *fakePassthroughStore) Save(_ context.Context, route *network.PassthroughRecord) error {
	cp := *route
	f.byKey[passthroughKey(route.ExternalPort, route.Protocol)] = &cp
	return nil
}

func (f *fakePassthroughStore) GetByPortProtocol(_ context.Context, externalPort int, protocol string) (*network.PassthroughRecord, error) {
	r, ok := f.byKey[passthroughKey(externalPort, protocol)]
	if !ok {
		return nil, network.ErrPassthroughNotFound
	}
	return r, nil
}

func (f *fakePassthroughStore) List(_ context.Context, _ bool) ([]*network.PassthroughRecord, error) {
	out := make([]*network.PassthroughRecord, 0, len(f.byKey))
	for _, r := range f.byKey {
		out = append(out, r)
	}
	return out, nil
}

func (f *fakePassthroughStore) ListByContainer(_ context.Context, containerName string) ([]*network.PassthroughRecord, error) {
	var out []*network.PassthroughRecord
	for _, r := range f.byKey {
		if r.ContainerName == containerName {
			out = append(out, r)
		}
	}
	return out, nil
}

func (f *fakePassthroughStore) Delete(_ context.Context, externalPort int, protocol string) error {
	delete(f.byKey, passthroughKey(externalPort, protocol))
	return nil
}

func (f *fakePassthroughStore) SetActive(_ context.Context, externalPort int, protocol string, active bool) error {
	if r, ok := f.byKey[passthroughKey(externalPort, protocol)]; ok {
		r.Active = active
	}
	return nil
}

func (f *fakePassthroughStore) Count(_ context.Context, _ bool) (int32, error) {
	return safecast.I32(len(f.byKey)), nil
}

var _ network.PassthroughStore = (*fakePassthroughStore)(nil)

// adminCtx (defined in rbac_phase_1_4_tenant_test.go) is reused here: it's
// the context shape a real recipe-deploy caller must already carry to get
// ANY port exposed — AddRoute has required auth.RoleAdmin since before this
// change, so the TCP/UDP passthrough path requiring it too is the existing
// precedent, not a new bar.

func newExposePortsTestServer(ip string) (*RecipeServer, *fakePassthroughStore) {
	manager := container.NewWithBackend(&fakeGetOnlyIncusBackend{
		info: &incus.ContainerInfo{Name: "alice-container", IPAddress: ip},
	})
	store := newFakePassthroughStore()
	return &RecipeServer{
		containers: &ContainerServer{manager: manager},
		network:    &NetworkServer{baseDomain: "example.com", passthroughStore: store},
	}, store
}

func TestExposePorts_TCPPortRegistersPassthroughNotHTTPRoute(t *testing.T) {
	srv, store := newExposePortsTestServer("10.0.3.5")
	recipe := &pb.Recipe{
		Id: "risingwave",
		Ports: []*pb.RecipePort{
			{ContainerPort: 4566, Protocol: pb.RouteProtocol_ROUTE_PROTOCOL_TCP},
		},
	}

	url, endpoints, warnings := srv.exposePorts(adminCtx(), recipe, "alice")
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none", warnings)
	}
	if url != "" {
		t.Errorf("url = %q, want empty — a TCP port must not produce an HTTPS URL", url)
	}
	if len(endpoints) != 1 || !strings.Contains(endpoints[0], "4566") {
		t.Fatalf("endpoints = %v, want one entry naming port 4566", endpoints)
	}

	rec, err := store.GetByPortProtocol(context.Background(), 4566, "tcp")
	if err != nil {
		t.Fatalf("GetByPortProtocol: %v", err)
	}
	if rec.TargetIP != "10.0.3.5" || rec.TargetPort != 4566 {
		t.Errorf("passthrough record = %+v, want target 10.0.3.5:4566", rec)
	}
}

func TestExposePorts_ExternalPortDefaultsToContainerPort(t *testing.T) {
	srv, store := newExposePortsTestServer("10.0.3.5")
	recipe := &pb.Recipe{Ports: []*pb.RecipePort{
		{ContainerPort: 6379, Protocol: pb.RouteProtocol_ROUTE_PROTOCOL_TCP},
	}}

	if _, _, warnings := srv.exposePorts(adminCtx(), recipe, "alice"); len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none", warnings)
	}
	if _, err := store.GetByPortProtocol(context.Background(), 6379, "tcp"); err != nil {
		t.Fatalf("expected the passthrough at the container_port (6379) when external_port is unset: %v", err)
	}
}

func TestExposePorts_ExplicitExternalPortIsHonored(t *testing.T) {
	srv, store := newExposePortsTestServer("10.0.3.5")
	recipe := &pb.Recipe{Ports: []*pb.RecipePort{
		{ContainerPort: 5432, ExternalPort: 15432, Protocol: pb.RouteProtocol_ROUTE_PROTOCOL_TCP},
	}}

	if _, _, warnings := srv.exposePorts(adminCtx(), recipe, "alice"); len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none", warnings)
	}
	rec, err := store.GetByPortProtocol(context.Background(), 15432, "tcp")
	if err != nil {
		t.Fatalf("GetByPortProtocol(15432): %v", err)
	}
	if rec.TargetPort != 5432 {
		t.Errorf("target_port = %d, want 5432 (the container_port)", rec.TargetPort)
	}
}

// THE #1462 regression this issue's own "Open questions" section flags:
// passthrough is host-port-global, so a second box wanting the same
// external_port must fail loudly rather than silently steal the route from
// the first box.
func TestExposePorts_ConflictingExternalPortWarnsAndDoesNotStealTheRoute(t *testing.T) {
	srv, store := newExposePortsTestServer("10.0.3.5")

	// bob already holds :4566/tcp.
	if err := store.Save(context.Background(), &network.PassthroughRecord{
		ExternalPort: 4566, TargetIP: "10.0.3.9", TargetPort: 4566,
		Protocol: "tcp", ContainerName: "bob-container", Active: true,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	recipe := &pb.Recipe{Ports: []*pb.RecipePort{
		{ContainerPort: 4566, Protocol: pb.RouteProtocol_ROUTE_PROTOCOL_TCP},
	}}
	url, endpoints, warnings := srv.exposePorts(adminCtx(), recipe, "alice")
	if url != "" || len(endpoints) != 0 {
		t.Fatalf("url=%q endpoints=%v, want nothing exposed on conflict", url, endpoints)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "bob-container") {
		t.Fatalf("warnings = %v, want one naming the conflicting owner bob-container", warnings)
	}

	rec, err := store.GetByPortProtocol(context.Background(), 4566, "tcp")
	if err != nil {
		t.Fatalf("GetByPortProtocol: %v", err)
	}
	if rec.TargetIP != "10.0.3.9" || rec.ContainerName != "bob-container" {
		t.Errorf("bob's route was overwritten: %+v", rec)
	}
}

// A re-deploy (or --force recreate) of the SAME container onto the SAME
// external_port must not be treated as a conflict with itself.
func TestExposePorts_RedeployOfSameContainerIsNotAConflict(t *testing.T) {
	srv, store := newExposePortsTestServer("10.0.3.5")
	if err := store.Save(context.Background(), &network.PassthroughRecord{
		ExternalPort: 4566, TargetIP: "10.0.3.5", TargetPort: 4566,
		Protocol: "tcp", ContainerName: "alice-container", Active: true,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	recipe := &pb.Recipe{Ports: []*pb.RecipePort{
		{ContainerPort: 4566, Protocol: pb.RouteProtocol_ROUTE_PROTOCOL_TCP},
	}}
	_, endpoints, warnings := srv.exposePorts(adminCtx(), recipe, "alice")
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none — re-exposing its own route is not a conflict", warnings)
	}
	if len(endpoints) != 1 {
		t.Fatalf("endpoints = %v, want one", endpoints)
	}
}

// A port with no TCP/UDP protocol must still take the AddRoute (Caddy) path
// — not the new exposePassthroughPort branch — even though this test's
// NetworkServer only wires a passthroughStore (no routeStore/proxyManager),
// so AddRoute itself fails here. That failure is exactly the point: it
// proves the branch dispatch, and the passthrough store must stay untouched.
func TestExposePorts_HTTPPortsTakeTheRouteNotPassthroughBranch(t *testing.T) {
	srv, store := newExposePortsTestServer("10.0.3.5")
	recipe := &pb.Recipe{Ports: []*pb.RecipePort{
		{ContainerPort: 8080, Subdomain: "web"},
	}}

	url, endpoints, warnings := srv.exposePorts(adminCtx(), recipe, "alice")
	if url != "" {
		t.Errorf("url = %q, want empty — no route backend is configured in this test", url)
	}
	if len(endpoints) != 0 {
		t.Errorf("endpoints = %v, want none for an HTTP port", endpoints)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "expose port 8080") {
		t.Fatalf("warnings = %v, want one naming AddRoute's own failure for port 8080", warnings)
	}
	if all, _ := store.List(context.Background(), false); len(all) != 0 {
		t.Errorf("an HTTP port must never land in the passthrough store: %v", all)
	}
}
