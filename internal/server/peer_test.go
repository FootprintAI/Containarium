package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewPeerPool(t *testing.T) {
	pool := NewPeerPool("local-vm", "", nil)
	if pool.LocalBackendID() != "local-vm" {
		t.Errorf("expected local backend ID 'local-vm', got %q", pool.LocalBackendID())
	}
	if len(pool.Peers()) != 0 {
		t.Errorf("expected 0 peers, got %d", len(pool.Peers()))
	}
}

func TestNewPeerPool_StaticPeers(t *testing.T) {
	pool := NewPeerPool("local-vm", "", []string{"10.0.0.1:8080", "10.0.0.2:8080"})
	if len(pool.Peers()) != 2 {
		t.Errorf("expected 2 peers, got %d", len(pool.Peers()))
	}
	peer := pool.Get("10.0.0.1:8080")
	if peer == nil {
		t.Fatal("expected to find peer 10.0.0.1:8080")
	}
	if peer.ID != "10.0.0.1:8080" {
		t.Errorf("expected peer ID '10.0.0.1:8080', got %q", peer.ID)
	}
}

func TestPeerPool_Get(t *testing.T) {
	pool := NewPeerPool("local", "", []string{"peer-1"})
	if pool.Get("peer-1") == nil {
		t.Error("expected to find peer-1")
	}
	if pool.Get("nonexistent") != nil {
		t.Error("expected nil for nonexistent peer")
	}
}

func TestPeerClient_ForwardRequest(t *testing.T) {
	// Mock peer server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/containers/alice/resize" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"message":"resized"}`))
	}))
	defer srv.Close()

	// Extract host:port from test server
	addr := srv.Listener.Addr().String()
	pc := &PeerClient{
		ID:      "test-peer",
		Addr:    addr,
		Healthy: true,
		client:  srv.Client(),
	}

	body := []byte(`{"cpu":"8","memory":"16GB"}`)
	respBody, statusCode, err := pc.ForwardRequest("PUT", "/v1/containers/alice/resize", "test-token", body)
	if err != nil {
		t.Fatalf("ForwardRequest failed: %v", err)
	}
	if statusCode != 200 {
		t.Errorf("expected status 200, got %d", statusCode)
	}
	if string(respBody) != `{"message":"resized"}` {
		t.Errorf("unexpected response body: %s", respBody)
	}
}

func TestPeerClient_ForwardRequest_NoAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("expected no auth header when token is empty")
		}
		w.Write([]byte(`ok`))
	}))
	defer srv.Close()

	pc := &PeerClient{
		ID:     "test-peer",
		Addr:   srv.Listener.Addr().String(),
		client: srv.Client(),
	}

	_, _, err := pc.ForwardRequest("GET", "/test", "", nil)
	if err != nil {
		t.Fatalf("ForwardRequest failed: %v", err)
	}
}

func TestPeerPool_ListContainers(t *testing.T) {
	// Mock peer that returns containers
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"containers": []map[string]interface{}{
				{
					"name":     "alice-container",
					"username": "alice",
					"state":    "CONTAINER_STATE_RUNNING",
					"resources": map[string]string{
						"cpu": "4", "memory": "8GB", "disk": "50GB",
					},
					"network": map[string]string{"ipAddress": "10.0.3.100"},
				},
			},
		})
	}))
	defer srv.Close()

	pool := NewPeerPool("local", "", nil)
	pool.mu.Lock()
	pool.peers["test-peer"] = &PeerClient{
		ID:      "test-peer",
		Addr:    srv.Listener.Addr().String(),
		Healthy: true,
		client:  srv.Client(),
	}
	pool.mu.Unlock()

	containers := pool.ListContainers("")
	if len(containers) != 1 {
		t.Fatalf("expected 1 container, got %d", len(containers))
	}
	if containers[0].Name != "alice-container" {
		t.Errorf("expected container name 'alice-container', got %q", containers[0].Name)
	}
	if containers[0].BackendID != "test-peer" {
		t.Errorf("expected backend ID 'test-peer', got %q", containers[0].BackendID)
	}
}

func TestPeerPool_ListContainers_SkipsUnhealthy(t *testing.T) {
	pool := NewPeerPool("local", "", nil)
	pool.mu.Lock()
	pool.peers["unhealthy"] = &PeerClient{
		ID:      "unhealthy",
		Healthy: false,
		client:  &http.Client{},
	}
	pool.mu.Unlock()

	containers := pool.ListContainers("")
	if len(containers) != 0 {
		t.Errorf("expected 0 containers from unhealthy peer, got %d", len(containers))
	}
}

func TestPeerPool_FindContainerPeer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"containers": []map[string]interface{}{
				{"name": "bob-container", "username": "bob", "state": "Running"},
			},
		})
	}))
	defer srv.Close()

	pool := NewPeerPool("local", "", nil)
	pool.mu.Lock()
	pool.peers["gpu-node"] = &PeerClient{
		ID:      "gpu-node",
		Addr:    srv.Listener.Addr().String(),
		Healthy: true,
		client:  srv.Client(),
	}
	pool.mu.Unlock()

	// Should find bob on gpu-node
	peer := pool.FindContainerPeer("bob", "")
	if peer == nil {
		t.Fatal("expected to find peer for bob")
	}
	if peer.ID != "gpu-node" {
		t.Errorf("expected peer ID 'gpu-node', got %q", peer.ID)
	}

	// Should not find alice
	peer = pool.FindContainerPeer("alice", "")
	if peer != nil {
		t.Error("expected nil for alice (not on any peer)")
	}
}

func TestPeerPool_PeerTerminalURL_NotFound(t *testing.T) {
	// Empty pool — no peers, should return empty URL
	pool := NewPeerPool("local", "", nil)
	url, err := pool.PeerTerminalURL("nonexistent", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if url != "" {
		t.Errorf("expected empty URL for nonexistent user, got %q", url)
	}
}

func TestPeerPool_PeerTerminalURL_Found(t *testing.T) {
	// Mock peer with a container
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"containers": []map[string]interface{}{
				{"name": "alice-container", "state": "Running"},
			},
		})
	}))
	defer srv.Close()

	pool := NewPeerPool("local", "", nil)
	pool.mu.Lock()
	pool.peers["gpu-node"] = &PeerClient{
		ID:      "gpu-node",
		Addr:    srv.Listener.Addr().String(),
		Healthy: true,
		client:  srv.Client(),
	}
	pool.mu.Unlock()

	url, err := pool.PeerTerminalURL("alice", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := "ws://" + srv.Listener.Addr().String() + "/v1/containers/alice/terminal"
	if url != expected {
		t.Errorf("expected %q, got %q", expected, url)
	}
}

func TestExtractHost(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"http://10.128.0.5:8081", "10.128.0.5"},
		{"https://example.com:443", "example.com"},
		{"http://localhost:8080/path", "localhost:8080"},
		{"10.0.0.1", "10.0.0.1"},
	}
	for _, tt := range tests {
		got := extractHost(tt.input)
		if got != tt.want {
			t.Errorf("extractHost(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestExtractPort(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"http://10.128.0.5:8081", "8081"},
		{"https://example.com:443", "443"},
		{"http://localhost:8080/path", "8080"},
		{"10.0.0.1", "8888"}, // default
	}
	for _, tt := range tests {
		got := extractPort(tt.input)
		if got != tt.want {
			t.Errorf("extractPort(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestIsDiscoveredPeer(t *testing.T) {
	if !isDiscoveredPeer("tunnel-fts-5900x-gpu") {
		t.Error("expected tunnel-fts-5900x-gpu to be discovered peer")
	}
	if isDiscoveredPeer("static-peer") {
		t.Error("expected static-peer to not be discovered peer")
	}
	if isDiscoveredPeer("short") {
		t.Error("expected short string to not be discovered peer")
	}
}
