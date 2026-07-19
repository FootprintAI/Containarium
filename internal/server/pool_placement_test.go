package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// TestPeerPool_LocalPool verifies LocalPool returns the configured tag.
func TestPeerPool_LocalPool(t *testing.T) {
	cases := []struct {
		name string
		pool string
	}{
		{"empty", ""},
		{"prod", "prod"},
		{"demo", "demo"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := NewPeerPool("local", "", nil, tc.pool)
			if got := p.LocalPool(); got != tc.pool {
				t.Errorf("LocalPool() = %q, want %q", got, tc.pool)
			}
		})
	}
}

// TestPeerPool_DiscoveryParsesPool verifies that the daemon parses the
// per-peer pool tag from /sentinel/peers.
func TestPeerPool_DiscoveryParsesPool(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"peers": []map[string]any{
				{"id": "tunnel-demo-1", "proxy_path": "/peer/tunnel-demo-1", "pool": "demo", "healthy": true},
				{"id": "tunnel-lab-1", "proxy_path": "/peer/tunnel-lab-1", "pool": "lab", "healthy": true},
				{"id": "tunnel-untagged", "proxy_path": "/peer/tunnel-untagged", "healthy": true},
			},
		})
	}))
	defer srv.Close()

	p := NewPeerPool("local", srv.URL, nil, "")
	p.discover()

	demo := p.Get("tunnel-demo-1")
	if demo == nil || demo.Pool != "demo" {
		t.Errorf("tunnel-demo-1 pool: got %v, want demo", demo)
	}
	lab := p.Get("tunnel-lab-1")
	if lab == nil || lab.Pool != "lab" {
		t.Errorf("tunnel-lab-1 pool: got %v, want lab", lab)
	}
	un := p.Get("tunnel-untagged")
	if un == nil || un.Pool != "" {
		t.Errorf("tunnel-untagged pool: got %v, want empty", un)
	}
}

// TestPeerPool_HealthyPeersInPool verifies pool filtering with health gating.
func TestPeerPool_HealthyPeersInPool(t *testing.T) {
	p := NewPeerPool("local", "", nil, "")
	p.peers["a"] = &PeerClient{ID: "a", Pool: "demo", Healthy: true}
	p.peers["b"] = &PeerClient{ID: "b", Pool: "demo", Healthy: false}
	p.peers["c"] = &PeerClient{ID: "c", Pool: "lab", Healthy: true}
	p.peers["d"] = &PeerClient{ID: "d", Pool: "", Healthy: true}

	got := p.HealthyPeersInPool("demo")
	if len(got) != 1 || got[0].ID != "a" {
		t.Errorf("HealthyPeersInPool(demo): got %+v, want [a]", got)
	}

	got = p.HealthyPeersInPool("lab")
	if len(got) != 1 || got[0].ID != "c" {
		t.Errorf("HealthyPeersInPool(lab): got %+v, want [c]", got)
	}

	// Empty pool argument matches only untagged peers (legacy behavior).
	got = p.HealthyPeersInPool("")
	if len(got) != 1 || got[0].ID != "d" {
		t.Errorf("HealthyPeersInPool(\"\"): got %+v, want [d]", got)
	}

	got = p.HealthyPeersInPool("nope")
	if len(got) != 0 {
		t.Errorf("HealthyPeersInPool(nope): got %+v, want empty", got)
	}
}

// TestContainerServer_ResolvePool exercises the lookup that turns a
// backend_id back into a pool tag for response decoration.
func TestContainerServer_ResolvePool(t *testing.T) {
	p := NewPeerPool("local-prod", "", nil, "prod")
	p.peers["tunnel-demo-1"] = &PeerClient{ID: "tunnel-demo-1", Pool: "demo", Healthy: true}
	p.peers["tunnel-lab-1"] = &PeerClient{ID: "tunnel-lab-1", Pool: "lab", Healthy: true}

	s := &ContainerServer{peerPool: p}

	cases := []struct {
		backendID string
		want      string
	}{
		{"", "prod"},              // empty resolves to local pool
		{"local-prod", "prod"},    // explicit local ID resolves to local pool
		{"tunnel-demo-1", "demo"}, // known peer
		{"tunnel-lab-1", "lab"},   // known peer
		{"never-registered", ""},  // unknown peer → empty
	}
	for _, tc := range cases {
		if got := s.resolvePool(tc.backendID); got != tc.want {
			t.Errorf("resolvePool(%q) = %q, want %q", tc.backendID, got, tc.want)
		}
	}

	// resolvePool with nil peerPool returns "".
	empty := &ContainerServer{}
	if got := empty.resolvePool("anything"); got != "" {
		t.Errorf("resolvePool with nil peerPool: got %q, want empty", got)
	}
}

// TestContainerServer_ResolvePoolPlacement exercises the placement
// chooser used by CreateContainer when req.Pool is set.
func TestContainerServer_ResolvePoolPlacement(t *testing.T) {
	t.Run("nil peer pool fails", func(t *testing.T) {
		s := &ContainerServer{}
		req := &pb.CreateContainerRequest{Pool: "demo"}
		if err := s.resolvePoolPlacement(req); err == nil {
			t.Error("expected error for nil peer pool, got nil")
		}
	})

	t.Run("backend_id consistency: matching pool", func(t *testing.T) {
		p := NewPeerPool("local-prod", "", nil, "prod")
		p.peers["tunnel-demo-1"] = &PeerClient{ID: "tunnel-demo-1", Pool: "demo", Healthy: true}
		s := &ContainerServer{peerPool: p}

		req := &pb.CreateContainerRequest{Pool: "demo", BackendId: "tunnel-demo-1"}
		if err := s.resolvePoolPlacement(req); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if req.BackendId != "tunnel-demo-1" {
			t.Errorf("BackendId changed: got %q", req.BackendId)
		}
	})

	t.Run("backend_id consistency: mismatched pool", func(t *testing.T) {
		p := NewPeerPool("local-prod", "", nil, "prod")
		p.peers["tunnel-demo-1"] = &PeerClient{ID: "tunnel-demo-1", Pool: "demo", Healthy: true}
		s := &ContainerServer{peerPool: p}

		req := &pb.CreateContainerRequest{Pool: "lab", BackendId: "tunnel-demo-1"}
		err := s.resolvePoolPlacement(req)
		if err == nil {
			t.Fatal("expected error for pool/backend mismatch, got nil")
		}
	})

	t.Run("backend_id consistency: local backend in matching pool", func(t *testing.T) {
		p := NewPeerPool("local-prod", "", nil, "prod")
		s := &ContainerServer{peerPool: p}

		req := &pb.CreateContainerRequest{Pool: "prod", BackendId: "local-prod"}
		if err := s.resolvePoolPlacement(req); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("pool only: picks healthy peer", func(t *testing.T) {
		p := NewPeerPool("local-prod", "", nil, "prod")
		p.peers["tunnel-demo-1"] = &PeerClient{ID: "tunnel-demo-1", Pool: "demo", Healthy: true}
		s := &ContainerServer{peerPool: p}

		req := &pb.CreateContainerRequest{Pool: "demo"}
		if err := s.resolvePoolPlacement(req); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if req.BackendId != "tunnel-demo-1" {
			t.Errorf("expected BackendId=tunnel-demo-1, got %q", req.BackendId)
		}
	})

	t.Run("pool only: picks local when local matches", func(t *testing.T) {
		p := NewPeerPool("local-prod", "", nil, "prod")
		// Even with peers around, local is preferred when its pool matches.
		p.peers["tunnel-prod-1"] = &PeerClient{ID: "tunnel-prod-1", Pool: "prod", Healthy: true}
		s := &ContainerServer{peerPool: p}

		req := &pb.CreateContainerRequest{Pool: "prod"}
		if err := s.resolvePoolPlacement(req); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if req.BackendId != "local-prod" {
			t.Errorf("expected BackendId=local-prod, got %q", req.BackendId)
		}
	})

	t.Run("pool only: no candidates errors", func(t *testing.T) {
		p := NewPeerPool("local-prod", "", nil, "prod")
		// Only an unhealthy peer in the requested pool.
		p.peers["tunnel-demo-1"] = &PeerClient{ID: "tunnel-demo-1", Pool: "demo", Healthy: false}
		s := &ContainerServer{peerPool: p}

		req := &pb.CreateContainerRequest{Pool: "demo"}
		err := s.resolvePoolPlacement(req)
		if err == nil {
			t.Fatal("expected error when no healthy peers in pool, got nil")
		}
	})

	// #920: the local branch above used to pick the local backend
	// unconditionally — no health check at all — even though the peer
	// branch (HealthyPeersInPool) has always required peer.Healthy. A
	// wedged local backend (e.g. CPU-starved incusd, #755) kept silently
	// absorbing every no-backend_id create in the pool even after it had
	// already dropped out of the daemon's own ListBackends fleet view. The
	// following two cases lock down the fix: local health is now checked
	// via the same localBackendHealthy signal ListBackends uses, and an
	// unhealthy local backend falls through to a healthy peer instead of
	// being chosen blindly.
	t.Run("pool only: local unhealthy falls through to peer", func(t *testing.T) {
		p := NewPeerPool("local-prod", "", nil, "prod")
		p.peers["tunnel-prod-1"] = &PeerClient{ID: "tunnel-prod-1", Pool: "prod", Healthy: true}
		s := &ContainerServer{peerPool: p, localHealthCheckFn: func() bool { return false }}

		req := &pb.CreateContainerRequest{Pool: "prod"}
		if err := s.resolvePoolPlacement(req); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if req.BackendId != "tunnel-prod-1" {
			t.Errorf("expected fallback to healthy peer tunnel-prod-1, got %q", req.BackendId)
		}
	})

	t.Run("pool only: local unhealthy and no healthy peers errors", func(t *testing.T) {
		p := NewPeerPool("local-prod", "", nil, "prod")
		// No peers at all in the "prod" pool — local is the only nominal
		// candidate, and it's unhealthy.
		s := &ContainerServer{peerPool: p, localHealthCheckFn: func() bool { return false }}

		req := &pb.CreateContainerRequest{Pool: "prod"}
		err := s.resolvePoolPlacement(req)
		if err == nil {
			t.Fatal("expected error when local is unhealthy and no healthy peers exist, got nil")
		}
		if req.BackendId != "" {
			t.Errorf("BackendId should stay unset on failure, got %q", req.BackendId)
		}
	})

	t.Run("pool only: local healthy (explicit) still picks local", func(t *testing.T) {
		p := NewPeerPool("local-prod", "", nil, "prod")
		p.peers["tunnel-prod-1"] = &PeerClient{ID: "tunnel-prod-1", Pool: "prod", Healthy: true}
		s := &ContainerServer{peerPool: p, localHealthCheckFn: func() bool { return true }}

		req := &pb.CreateContainerRequest{Pool: "prod"}
		if err := s.resolvePoolPlacement(req); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if req.BackendId != "local-prod" {
			t.Errorf("expected local-prod (local preferred over peer when healthy), got %q", req.BackendId)
		}
	})
}

// TestContainerServer_LocalBackendHealthy exercises localBackendHealthy's
// override + nil-manager paths directly (the real Incus-probing path needs
// a live daemon and isn't covered here — see #920).
func TestContainerServer_LocalBackendHealthy(t *testing.T) {
	t.Run("nil manager, no override: healthy", func(t *testing.T) {
		s := &ContainerServer{}
		if !s.localBackendHealthy() {
			t.Error("expected healthy=true when no manager is wired and no override is set")
		}
	})

	t.Run("override false wins over nil manager", func(t *testing.T) {
		s := &ContainerServer{localHealthCheckFn: func() bool { return false }}
		if s.localBackendHealthy() {
			t.Error("expected localHealthCheckFn's false to be honored")
		}
	})

	t.Run("override true", func(t *testing.T) {
		s := &ContainerServer{localHealthCheckFn: func() bool { return true }}
		if !s.localBackendHealthy() {
			t.Error("expected localHealthCheckFn's true to be honored")
		}
	})
}
