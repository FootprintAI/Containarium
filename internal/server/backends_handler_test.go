package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// TestContainerServer_ListBackends exercises the proto-first ListBackends
// RPC that replaced the hand-coded /v1/backends list handler (#354): the
// local backend plus any tunnel peers, with health and type. The local
// GetSystemInfo enrichment (OS / container count / GPUs) needs Incus, so a
// nil manager here degrades to identity + health — which is exactly what
// the method must return on a daemon that can't reach its manager.
func TestContainerServer_ListBackends(t *testing.T) {
	pool := NewPeerPool("local-spot", "", nil, "")
	pool.mu.Lock()
	pool.peers["tunnel-gpu"] = &PeerClient{
		ID:      "tunnel-gpu",
		Healthy: true,
		client:  &http.Client{},
	}
	pool.mu.Unlock()

	s := &ContainerServer{peerPool: pool, startTime: time.Now().Add(-time.Minute)}
	ctx := auth.ContextWithTestSubject(context.Background(), "ops", auth.RoleAdmin)

	resp, err := s.ListBackends(ctx, &pb.ListBackendsRequest{})
	if err != nil {
		t.Fatalf("ListBackends: %v", err)
	}
	if len(resp.Backends) != 2 {
		t.Fatalf("expected 2 backends, got %d", len(resp.Backends))
	}

	// Local backend is first, healthy, with uptime derived from startTime.
	local := resp.Backends[0]
	if local.Id != "local-spot" || local.Type != "local" {
		t.Errorf("local backend wrong: id=%q type=%q", local.Id, local.Type)
	}
	if !local.Healthy {
		t.Error("local backend should be healthy")
	}
	if local.UptimeSeconds <= 0 {
		t.Errorf("expected positive uptime, got %d", local.UptimeSeconds)
	}

	// Tunnel peer present, typed, healthy.
	found := false
	for _, b := range resp.Backends {
		if b.Id == "tunnel-gpu" {
			found = true
			if b.Type != "tunnel" {
				t.Errorf("expected type 'tunnel', got %q", b.Type)
			}
			if !b.Healthy {
				t.Error("expected tunnel-gpu to be healthy")
			}
		}
	}
	if !found {
		t.Error("expected to find tunnel-gpu in backends list")
	}
}

// TestContainerServer_ListBackends_RequiresAdmin proves the admin gate: a
// non-admin token never enumerates the fleet (topology is operator-grade).
func TestContainerServer_ListBackends_RequiresAdmin(t *testing.T) {
	s := &ContainerServer{peerPool: NewPeerPool("local-spot", "", nil, "")}
	ctx := auth.ContextWithTestSubject(context.Background(), "tenant", "member")
	if _, err := s.ListBackends(ctx, &pb.ListBackendsRequest{}); err == nil {
		t.Fatal("expected RequireRole to reject a non-admin caller")
	}
}

func TestBackendsHandler_SystemInfoRouting(t *testing.T) {
	// Mock peer that serves system info
	peerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/system/info" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"info":{"hostname":"gpu-node","totalCpus":24}}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer peerSrv.Close()

	pool := NewPeerPool("local-spot", "", nil, "")
	pool.mu.Lock()
	pool.peers["tunnel-gpu"] = &PeerClient{
		ID:      "tunnel-gpu",
		Addr:    peerSrv.Listener.Addr().String(),
		Healthy: true,
		client:  peerSrv.Client(),
	}
	pool.mu.Unlock()

	// Test: peer system info forwarding
	peer := pool.Get("tunnel-gpu")
	if peer == nil {
		t.Fatal("expected to find tunnel-gpu peer")
	}

	respBody, statusCode, err := peer.ForwardRequest("GET", "/v1/system/info", "", nil)
	if err != nil {
		t.Fatalf("ForwardRequest failed: %v", err)
	}
	if statusCode != 200 {
		t.Errorf("expected status 200, got %d", statusCode)
	}

	var resp struct {
		Info struct {
			Hostname  string `json:"hostname"`
			TotalCpus int    `json:"totalCpus"`
		} `json:"info"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp.Info.Hostname != "gpu-node" {
		t.Errorf("expected hostname 'gpu-node', got %q", resp.Info.Hostname)
	}
	if resp.Info.TotalCpus != 24 {
		t.Errorf("expected 24 CPUs, got %d", resp.Info.TotalCpus)
	}

	// Test: unknown backend
	unknownPeer := pool.Get("nonexistent")
	if unknownPeer != nil {
		t.Error("expected nil for unknown backend")
	}
}
