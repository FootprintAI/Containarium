package server

import (
	"context"
	"errors"
	"testing"

	"github.com/footprintai/containarium/internal/sandbox/ipam"
	"github.com/footprintai/containarium/internal/sandbox/pool"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeSandboxBackend already implements CreateContainer/StartContainer/
// StopContainer/DeleteContainer, which is pool.Backend's entire (narrow)
// interface — no adapter needed to reuse it here.

func TestSpawnSandbox_ClaimsFromWarmPool(t *testing.T) {
	backend := newFakeSandboxBackend()
	allocator, err := ipam.New("10.100.0.10", "10.100.0.250", "10.100.0.1", 0)
	if err != nil {
		t.Fatalf("ipam.New: %v", err)
	}
	p := pool.New(backend, allocator, pool.Config{
		MinWarm:    map[pb.SandboxTemplate]int{pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE: 1},
		Image:      map[pb.SandboxTemplate]string{pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE: "images:ubuntu/24.04"},
		NICNetwork: "incusbr0",
	})
	p.Reconcile(context.Background())
	if got := p.ReadyCount(pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE); got != 1 {
		t.Fatalf("pool ReadyCount after warming = %d, want 1", got)
	}

	s := NewSandboxServer(backend, p)

	resp, err := s.SpawnSandbox(ctxAs("alice", false), &pb.SpawnSandboxRequest{})
	if err != nil {
		t.Fatalf("SpawnSandbox: %v", err)
	}
	sb := resp.Sandbox
	if sb.ServedFrom != pb.ServedFrom_SERVED_FROM_POOL {
		t.Errorf("served_from = %v, want POOL", sb.ServedFrom)
	}
	if sb.SandboxId == "" {
		t.Fatal("empty sandbox_id")
	}
	if p.ReadyCount(pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE) != 0 {
		t.Error("pool ReadyCount after claiming the only member should be 0")
	}

	// Ownership must now be stamped correctly — proving SetConfig(tenant)
	// + SetLabels(kind/template/ttl) together did the right thing, not
	// just that SOME call succeeded.
	info := backend.instances[sb.SandboxId]
	if info.Tenant != "alice" {
		t.Errorf("stamped tenant = %q, want alice", info.Tenant)
	}
	if info.Labels[sandboxKindLabelSuffix] != SandboxKindLabelValue {
		t.Errorf("sandbox-kind label not stamped: %+v", info.Labels)
	}

	// A pool-claimed sandbox must be usable through the same ownership
	// path as a cold-path one — exec, not just spawn, has to work.
	if _, err := s.ExecInSandbox(ctxAs("alice", false), &pb.ExecInSandboxRequest{
		SandboxId: sb.SandboxId, Command: []string{"true"},
	}); err != nil {
		t.Errorf("ExecInSandbox on a pool-claimed sandbox: %v", err)
	}
	if _, err := s.ExecInSandbox(ctxAs("bob", false), &pb.ExecInSandboxRequest{
		SandboxId: sb.SandboxId, Command: []string{"true"},
	}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("cross-tenant exec on a pool-claimed sandbox: code = %v, want PermissionDenied", status.Code(err))
	}
}

func TestSpawnSandbox_PoolExhaustedFallsBackToColdWithAllowColdStart(t *testing.T) {
	backend := newFakeSandboxBackend()
	allocator, err := ipam.New("10.100.0.10", "10.100.0.250", "10.100.0.1", 0)
	if err != nil {
		t.Fatalf("ipam.New: %v", err)
	}
	// MinWarm intentionally unset (Config{}) — the pool is configured but
	// warms nothing, matching "pool exists but has no ready member for
	// this template" rather than "no pool at all".
	p := pool.New(backend, allocator, pool.Config{})
	s := NewSandboxServer(backend, p)

	resp, err := s.SpawnSandbox(ctxAs("alice", false), &pb.SpawnSandboxRequest{AllowColdStart: true})
	if err != nil {
		t.Fatalf("SpawnSandbox: %v", err)
	}
	if resp.Sandbox.ServedFrom != pb.ServedFrom_SERVED_FROM_COLD {
		t.Errorf("served_from = %v, want COLD (pool exhausted, allow_cold_start=true)", resp.Sandbox.ServedFrom)
	}
}

func TestSpawnSandbox_PoolExhaustedReturnsResourceExhaustedWithoutAllowColdStart(t *testing.T) {
	backend := newFakeSandboxBackend()
	allocator, err := ipam.New("10.100.0.10", "10.100.0.250", "10.100.0.1", 0)
	if err != nil {
		t.Fatalf("ipam.New: %v", err)
	}
	p := pool.New(backend, allocator, pool.Config{})
	s := NewSandboxServer(backend, p)

	_, err = s.SpawnSandbox(ctxAs("alice", false), &pb.SpawnSandboxRequest{})
	if got := status.Code(err); got != codes.ResourceExhausted {
		t.Fatalf("code = %v, want ResourceExhausted (pool exhausted, allow_cold_start unset)", got)
	}
}

func TestDeleteSandbox_PoolClaimedRoutesThroughPoolRelease(t *testing.T) {
	backend := newFakeSandboxBackend()
	allocator, err := ipam.New("10.100.0.10", "10.100.0.250", "10.100.0.1", 0)
	if err != nil {
		t.Fatalf("ipam.New: %v", err)
	}
	p := pool.New(backend, allocator, pool.Config{
		MinWarm:    map[pb.SandboxTemplate]int{pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE: 1},
		Image:      map[pb.SandboxTemplate]string{pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE: "images:ubuntu/24.04"},
		NICNetwork: "incusbr0",
	})
	p.Reconcile(context.Background())
	s := NewSandboxServer(backend, p)

	resp, err := s.SpawnSandbox(ctxAs("alice", false), &pb.SpawnSandboxRequest{})
	if err != nil {
		t.Fatalf("SpawnSandbox: %v", err)
	}
	id := resp.Sandbox.SandboxId

	if _, err := s.DeleteSandbox(ctxAs("alice", false), &pb.DeleteSandboxRequest{SandboxId: id}); err != nil {
		t.Fatalf("DeleteSandbox: %v", err)
	}

	if _, ok := backend.instances[id]; ok {
		t.Error("container still present after DeleteSandbox")
	}

	// The address must have come back through IPAM too (pool.Release's
	// job, not destroy()'s) — reconciling a fresh warm at the same target
	// should succeed rather than hitting an artificially-shrunk range.
	// (This range has 241 addresses and only one was ever allocated, so
	// this mostly documents intent; ipam's own exhaustion tests cover the
	// release mechanics directly.)
	p.Reconcile(context.Background())
	if got := p.ReadyCount(pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE); got != 1 {
		t.Errorf("ReadyCount after re-reconciling post-delete = %d, want 1", got)
	}
}

// TestSpawnSandbox_ClaimSetupFailureDestroysTheMember pins that a claimed
// member which fails post-claim setup doesn't leak: it must be destroyed
// (not left claimed-but-broken, and not silently re-added to the ring —
// this package's Isolation rule applies here too), and the caller gets a
// real error, not a fabricated success.
func TestSpawnSandbox_ClaimSetupFailureDestroysTheMember(t *testing.T) {
	backend := newFakeSandboxBackend()
	backend.setLabelsErr = errors.New("incus: simulated SetLabels failure")
	allocator, err := ipam.New("10.100.0.10", "10.100.0.250", "10.100.0.1", 0)
	if err != nil {
		t.Fatalf("ipam.New: %v", err)
	}
	p := pool.New(backend, allocator, pool.Config{
		MinWarm:    map[pb.SandboxTemplate]int{pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE: 1},
		Image:      map[pb.SandboxTemplate]string{pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE: "images:ubuntu/24.04"},
		NICNetwork: "incusbr0",
	})
	p.Reconcile(context.Background())
	s := NewSandboxServer(backend, p)

	_, err = s.SpawnSandbox(ctxAs("alice", false), &pb.SpawnSandboxRequest{})
	if err == nil {
		t.Fatal("SpawnSandbox should fail when post-claim labeling fails")
	}
	if got := status.Code(err); got != codes.Internal {
		t.Errorf("code = %v, want Internal", got)
	}
	if got := backend.deleteCalls; got == 0 {
		t.Error("the half-claimed member was not destroyed")
	}
	if got := p.ReadyCount(pb.SandboxTemplate_SANDBOX_TEMPLATE_BASE); got != 0 {
		t.Errorf("ReadyCount = %d, want 0 (the failed member must not be silently re-added to the ring)", got)
	}
}
