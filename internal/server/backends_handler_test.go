package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBackendsHandler_ListBackends(t *testing.T) {
	pool := NewPeerPool("local-spot", "", nil)
	pool.mu.Lock()
	pool.peers["tunnel-gpu"] = &PeerClient{
		ID:      "tunnel-gpu",
		Healthy: true,
		client:  &http.Client{},
	}
	pool.mu.Unlock()

	// Simulate the handler logic (same as DualServer.backendsHandler)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		type backendInfo struct {
			ID      string `json:"id"`
			Type    string `json:"type"`
			Healthy bool   `json:"healthy"`
		}
		var backends []backendInfo
		backends = append(backends, backendInfo{
			ID:      pool.LocalBackendID(),
			Type:    "local",
			Healthy: true,
		})
		for _, peer := range pool.Peers() {
			backends = append(backends, backendInfo{
				ID:      peer.ID,
				Type:    "tunnel",
				Healthy: peer.Healthy,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"backends": backends})
	})

	req := httptest.NewRequest("GET", "/v1/backends", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp struct {
		Backends []struct {
			ID      string `json:"id"`
			Type    string `json:"type"`
			Healthy bool   `json:"healthy"`
		} `json:"backends"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if len(resp.Backends) != 2 {
		t.Fatalf("expected 2 backends, got %d", len(resp.Backends))
	}

	// Local backend
	if resp.Backends[0].ID != "local-spot" {
		t.Errorf("expected local backend ID 'local-spot', got %q", resp.Backends[0].ID)
	}
	if resp.Backends[0].Type != "local" {
		t.Errorf("expected type 'local', got %q", resp.Backends[0].Type)
	}

	// Tunnel backend
	found := false
	for _, b := range resp.Backends {
		if b.ID == "tunnel-gpu" {
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

	pool := NewPeerPool("local-spot", "", nil)
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
