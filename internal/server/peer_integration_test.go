package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// fakeBackend simulates a remote containarium daemon.
// It maintains an in-memory container store and handles the REST API endpoints.
type fakeBackend struct {
	id         string
	mu         sync.RWMutex
	containers []fakeContainer
	systemInfo fakeSystemInfo
	// Track received requests for assertions
	requests []fakeRequest
}

type fakeContainer struct {
	Name      string            `json:"name"`
	Username  string            `json:"username"`
	State     string            `json:"state"`
	Resources map[string]string `json:"resources"`
	Network   map[string]string `json:"network"`
	Labels    map[string]string `json:"labels"`
	GPU       string            `json:"gpuDevice"`
	BackendID string            `json:"backendId"`
}

type fakeSystemInfo struct {
	Hostname  string    `json:"hostname"`
	TotalCPUs int       `json:"totalCpus"`
	TotalMem  int64     `json:"totalMemoryBytes"`
	GPUs      []fakeGPU `json:"gpus"`
}

type fakeGPU struct {
	Vendor        string `json:"vendor"`
	Model         string `json:"model"`
	ModelName     string `json:"modelName"`
	DriverVersion string `json:"driverVersion"`
	CUDAVersion   string `json:"cudaVersion"`
}

type fakeRequest struct {
	Method string
	Path   string
	Body   string
}

func newFakeBackend(id string, containers []fakeContainer, sysInfo fakeSystemInfo) *fakeBackend {
	return &fakeBackend{
		id:         id,
		containers: containers,
		systemInfo: sysInfo,
	}
}

func (fb *fakeBackend) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fb.mu.Lock()
		fb.requests = append(fb.requests, fakeRequest{
			Method: r.Method,
			Path:   r.URL.Path,
		})
		fb.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")

		switch {
		// List containers
		case r.Method == "GET" && r.URL.Path == "/v1/containers":
			fb.mu.RLock()
			json.NewEncoder(w).Encode(map[string]interface{}{
				"containers": fb.containers,
			})
			fb.mu.RUnlock()

		// Get system info
		case r.Method == "GET" && r.URL.Path == "/v1/system/info":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"info": fb.systemInfo,
			})

		// Create container
		case r.Method == "POST" && r.URL.Path == "/v1/containers":
			var req struct {
				Username string `json:"username"`
				GPU      string `json:"gpu"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			c := fakeContainer{
				Name:      req.Username + "-container",
				Username:  req.Username,
				State:     "CONTAINER_STATE_RUNNING",
				Resources: map[string]string{"cpu": "4", "memory": "8GB", "disk": "50GB"},
				Network:   map[string]string{"ipAddress": "10.0.3.200"},
				GPU:       req.GPU,
			}
			fb.mu.Lock()
			fb.containers = append(fb.containers, c)
			fb.mu.Unlock()
			json.NewEncoder(w).Encode(map[string]interface{}{
				"container": c,
				"message":   "created",
			})

		// Resize
		case r.Method == "PUT" && len(r.URL.Path) > len("/v1/containers/") && pathEndsWith(r.URL.Path, "/resize"):
			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "resized",
			})

		// Start
		case r.Method == "POST" && pathEndsWith(r.URL.Path, "/start"):
			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "started",
			})

		// Stop
		case r.Method == "POST" && pathEndsWith(r.URL.Path, "/stop"):
			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "stopped",
			})

		// Delete
		case r.Method == "DELETE" && len(r.URL.Path) > len("/v1/containers/"):
			username := extractUsername(r.URL.Path)
			fb.mu.Lock()
			filtered := fb.containers[:0]
			for _, c := range fb.containers {
				if c.Username != username {
					filtered = append(filtered, c)
				}
			}
			fb.containers = filtered
			fb.mu.Unlock()
			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "deleted",
			})

		// Cleanup disk
		case r.Method == "POST" && pathEndsWith(r.URL.Path, "/cleanup-disk"):
			json.NewEncoder(w).Encode(map[string]interface{}{
				"message":    "disk cleaned",
				"freedBytes": 1024000,
			})

		// Collaborators
		case r.Method == "GET" && pathEndsWith(r.URL.Path, "/collaborators"):
			json.NewEncoder(w).Encode(map[string]interface{}{
				"collaborators": []map[string]string{},
				"totalCount":    0,
			})
		case r.Method == "POST" && pathEndsWith(r.URL.Path, "/collaborators"):
			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "collaborator added",
			})
		case r.Method == "DELETE" && pathContains(r.URL.Path, "/collaborators/"):
			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "collaborator removed",
			})

		default:
			http.NotFound(w, r)
		}
	})
}

func (fb *fakeBackend) requestCount() int {
	fb.mu.RLock()
	defer fb.mu.RUnlock()
	return len(fb.requests)
}

func (fb *fakeBackend) lastRequest() fakeRequest {
	fb.mu.RLock()
	defer fb.mu.RUnlock()
	if len(fb.requests) == 0 {
		return fakeRequest{}
	}
	return fb.requests[len(fb.requests)-1]
}

// --- Integration Tests ---

// TestIntegration_MultiBackendListContainers verifies that ListContainers
// fans out to all healthy peers and merges results with backend_id tagging.
func TestIntegration_MultiBackendListContainers(t *testing.T) {
	// Backend 1: GCP spot with 2 containers
	spot := newFakeBackend("gcp-spot", []fakeContainer{
		{Name: "alice-container", Username: "alice", State: "CONTAINER_STATE_RUNNING"},
		{Name: "bob-container", Username: "bob", State: "CONTAINER_STATE_STOPPED"},
	}, fakeSystemInfo{})

	// Backend 2: GPU node with 1 container
	gpu := newFakeBackend("tunnel-gpu", []fakeContainer{
		{Name: "charlie-container", Username: "charlie", State: "CONTAINER_STATE_RUNNING", GPU: "0"},
	}, fakeSystemInfo{})

	spotSrv := httptest.NewServer(spot.handler())
	defer spotSrv.Close()
	gpuSrv := httptest.NewServer(gpu.handler())
	defer gpuSrv.Close()

	pool := NewPeerPool("local", "", nil, "")
	pool.mu.Lock()
	pool.peers["gcp-spot"] = &PeerClient{
		ID: "gcp-spot", Addr: spotSrv.Listener.Addr().String(),
		Healthy: true, client: spotSrv.Client(),
	}
	pool.peers["tunnel-gpu"] = &PeerClient{
		ID: "tunnel-gpu", Addr: gpuSrv.Listener.Addr().String(),
		Healthy: true, client: gpuSrv.Client(),
	}
	pool.mu.Unlock()

	containers := pool.ListContainers("")

	if len(containers) != 3 {
		t.Fatalf("expected 3 containers across 2 backends, got %d", len(containers))
	}

	// Verify backend_id tagging
	backendCounts := make(map[string]int)
	for _, c := range containers {
		backendCounts[c.BackendID]++
	}
	if backendCounts["gcp-spot"] != 2 {
		t.Errorf("expected 2 containers from gcp-spot, got %d", backendCounts["gcp-spot"])
	}
	if backendCounts["tunnel-gpu"] != 1 {
		t.Errorf("expected 1 container from tunnel-gpu, got %d", backendCounts["tunnel-gpu"])
	}
}

// TestIntegration_PeerForwardResize verifies that resize operations
// are forwarded to the correct peer when the container is not local.
func TestIntegration_PeerForwardResize(t *testing.T) {
	gpu := newFakeBackend("tunnel-gpu", []fakeContainer{
		{Name: "charlie-container", Username: "charlie", State: "CONTAINER_STATE_RUNNING"},
	}, fakeSystemInfo{})

	gpuSrv := httptest.NewServer(gpu.handler())
	defer gpuSrv.Close()

	pool := NewPeerPool("local", "", nil, "")
	pool.mu.Lock()
	pool.peers["tunnel-gpu"] = &PeerClient{
		ID: "tunnel-gpu", Addr: gpuSrv.Listener.Addr().String(),
		Healthy: true, client: gpuSrv.Client(),
	}
	pool.mu.Unlock()

	// Find charlie's peer
	peer := pool.FindContainerPeer("charlie", "")
	if peer == nil {
		t.Fatal("expected to find charlie on tunnel-gpu")
	}
	if peer.ID != "tunnel-gpu" {
		t.Errorf("expected peer ID 'tunnel-gpu', got %q", peer.ID)
	}

	// Forward resize
	body := []byte(`{"cpu":"8","memory":"16GB","disk":"100GB"}`)
	respBody, statusCode, err := peer.ForwardRequest("PUT", "/v1/containers/charlie/resize", "", body)
	if err != nil {
		t.Fatalf("resize forward failed: %v", err)
	}
	if statusCode != 200 {
		t.Errorf("expected 200, got %d: %s", statusCode, respBody)
	}

	// Verify request reached the peer
	lastReq := gpu.lastRequest()
	if lastReq.Method != "PUT" || lastReq.Path != "/v1/containers/charlie/resize" {
		t.Errorf("unexpected request: %s %s", lastReq.Method, lastReq.Path)
	}
}

// TestIntegration_PeerForwardDelete verifies delete operations forward correctly.
func TestIntegration_PeerForwardDelete(t *testing.T) {
	gpu := newFakeBackend("tunnel-gpu", []fakeContainer{
		{Name: "charlie-container", Username: "charlie", State: "CONTAINER_STATE_RUNNING"},
	}, fakeSystemInfo{})

	gpuSrv := httptest.NewServer(gpu.handler())
	defer gpuSrv.Close()

	pool := NewPeerPool("local", "", nil, "")
	pool.mu.Lock()
	pool.peers["tunnel-gpu"] = &PeerClient{
		ID: "tunnel-gpu", Addr: gpuSrv.Listener.Addr().String(),
		Healthy: true, client: gpuSrv.Client(),
	}
	pool.mu.Unlock()

	peer := pool.FindContainerPeer("charlie", "")
	if peer == nil {
		t.Fatal("expected to find charlie")
	}

	_, statusCode, err := peer.ForwardRequest("DELETE", "/v1/containers/charlie", "", nil)
	if err != nil {
		t.Fatalf("delete forward failed: %v", err)
	}
	if statusCode != 200 {
		t.Errorf("expected 200, got %d", statusCode)
	}

	// Verify container was removed from fake backend
	gpu.mu.RLock()
	if len(gpu.containers) != 0 {
		t.Errorf("expected 0 containers after delete, got %d", len(gpu.containers))
	}
	gpu.mu.RUnlock()
}

// TestIntegration_PeerForwardCollaborators verifies collaborator operations forward correctly.
func TestIntegration_PeerForwardCollaborators(t *testing.T) {
	gpu := newFakeBackend("tunnel-gpu", []fakeContainer{
		{Name: "charlie-container", Username: "charlie", State: "CONTAINER_STATE_RUNNING"},
	}, fakeSystemInfo{})

	gpuSrv := httptest.NewServer(gpu.handler())
	defer gpuSrv.Close()

	pool := NewPeerPool("local", "", nil, "")
	pool.mu.Lock()
	pool.peers["tunnel-gpu"] = &PeerClient{
		ID: "tunnel-gpu", Addr: gpuSrv.Listener.Addr().String(),
		Healthy: true, client: gpuSrv.Client(),
	}
	pool.mu.Unlock()

	peer := pool.FindContainerPeer("charlie", "")
	if peer == nil {
		t.Fatal("expected to find charlie")
	}

	// Add collaborator
	body := []byte(`{"collaborator_username":"dave","ssh_public_key":"ssh-ed25519 AAAA_dave"}`)
	_, statusCode, err := peer.ForwardRequest("POST", "/v1/containers/charlie/collaborators", "", body)
	if err != nil {
		t.Fatalf("add collaborator failed: %v", err)
	}
	if statusCode != 200 {
		t.Errorf("expected 200, got %d", statusCode)
	}

	// List collaborators
	_, statusCode, err = peer.ForwardRequest("GET", "/v1/containers/charlie/collaborators", "", nil)
	if err != nil {
		t.Fatalf("list collaborators failed: %v", err)
	}
	if statusCode != 200 {
		t.Errorf("expected 200, got %d", statusCode)
	}

	// Remove collaborator
	_, statusCode, err = peer.ForwardRequest("DELETE", "/v1/containers/charlie/collaborators/dave", "", nil)
	if err != nil {
		t.Fatalf("remove collaborator failed: %v", err)
	}
	if statusCode != 200 {
		t.Errorf("expected 200, got %d", statusCode)
	}
}

// TestIntegration_PeerSystemInfo verifies per-backend system info forwarding.
func TestIntegration_PeerSystemInfo(t *testing.T) {
	gpu := newFakeBackend("tunnel-gpu", nil, fakeSystemInfo{
		Hostname:  "node-a",
		TotalCPUs: 24,
		TotalMem:  137438953472, // 128GB
		GPUs: []fakeGPU{
			{
				Vendor:        "GPU_VENDOR_NVIDIA",
				Model:         "GPU_MODEL_NVIDIA_RTX_4090",
				ModelName:     "NVIDIA GeForce RTX 4090",
				DriverVersion: "570.211.01",
				CUDAVersion:   "12.8",
			},
		},
	})

	gpuSrv := httptest.NewServer(gpu.handler())
	defer gpuSrv.Close()

	peer := &PeerClient{
		ID: "tunnel-gpu", Addr: gpuSrv.Listener.Addr().String(),
		Healthy: true, client: gpuSrv.Client(),
	}

	respBody, statusCode, err := peer.ForwardRequest("GET", "/v1/system/info", "", nil)
	if err != nil {
		t.Fatalf("system info forward failed: %v", err)
	}
	if statusCode != 200 {
		t.Errorf("expected 200, got %d", statusCode)
	}

	var resp struct {
		Info struct {
			Hostname  string    `json:"hostname"`
			TotalCPUs int       `json:"totalCpus"`
			TotalMem  int64     `json:"totalMemoryBytes"`
			GPUs      []fakeGPU `json:"gpus"`
		} `json:"info"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	if resp.Info.Hostname != "node-a" {
		t.Errorf("expected hostname 'node-a', got %q", resp.Info.Hostname)
	}
	if resp.Info.TotalCPUs != 24 {
		t.Errorf("expected 24 CPUs, got %d", resp.Info.TotalCPUs)
	}
	if len(resp.Info.GPUs) != 1 {
		t.Fatalf("expected 1 GPU, got %d", len(resp.Info.GPUs))
	}
	if resp.Info.GPUs[0].Model != "GPU_MODEL_NVIDIA_RTX_4090" {
		t.Errorf("expected GPU model RTX 4090, got %q", resp.Info.GPUs[0].Model)
	}
	if resp.Info.GPUs[0].CUDAVersion != "12.8" {
		t.Errorf("expected CUDA 12.8, got %q", resp.Info.GPUs[0].CUDAVersion)
	}
}

// TestIntegration_UnhealthyPeerSkipped verifies that unhealthy peers
// are skipped during list and find operations.
func TestIntegration_UnhealthyPeerSkipped(t *testing.T) {
	gpu := newFakeBackend("tunnel-gpu", []fakeContainer{
		{Name: "charlie-container", Username: "charlie"},
	}, fakeSystemInfo{})

	gpuSrv := httptest.NewServer(gpu.handler())
	defer gpuSrv.Close()

	pool := NewPeerPool("local", "", nil, "")
	pool.mu.Lock()
	pool.peers["tunnel-gpu"] = &PeerClient{
		ID: "tunnel-gpu", Addr: gpuSrv.Listener.Addr().String(),
		Healthy: false, // unhealthy!
		client:  gpuSrv.Client(),
	}
	pool.mu.Unlock()

	// List should return 0 (unhealthy peer skipped)
	containers := pool.ListContainers("")
	if len(containers) != 0 {
		t.Errorf("expected 0 containers (peer unhealthy), got %d", len(containers))
	}

	// Find should return nil
	peer := pool.FindContainerPeer("charlie", "")
	if peer != nil {
		t.Error("expected nil (peer unhealthy)")
	}

	// Verify no requests were made to the peer
	if gpu.requestCount() != 0 {
		t.Errorf("expected 0 requests to unhealthy peer, got %d", gpu.requestCount())
	}
}

// TestIntegration_AuthTokenForwarding verifies that auth tokens are
// forwarded correctly to peer backends.
func TestIntegration_AuthTokenForwarding(t *testing.T) {
	var receivedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"containers":[]}`))
	}))
	defer srv.Close()

	pool := NewPeerPool("local", "", nil, "")
	pool.mu.Lock()
	pool.peers["peer"] = &PeerClient{
		ID: "peer", Addr: srv.Listener.Addr().String(),
		Healthy: true, client: srv.Client(),
	}
	pool.mu.Unlock()

	pool.ListContainers("my-jwt-token")

	expected := "Bearer my-jwt-token"
	if receivedAuth != expected {
		t.Errorf("expected auth header %q, got %q", expected, receivedAuth)
	}
}

// TestIntegration_PeerTerminalURLResolution verifies terminal URL
// generation for containers on peer backends.
func TestIntegration_PeerTerminalURLResolution(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"containers": []map[string]interface{}{
				{"name": "alice-container", "state": "Running"},
				{"name": "bob-container", "state": "Running"},
			},
		})
	}))
	defer srv.Close()

	pool := NewPeerPool("local", "", nil, "")
	pool.mu.Lock()
	pool.peers["gpu-node"] = &PeerClient{
		ID: "gpu-node", Addr: srv.Listener.Addr().String(),
		Healthy: true, client: srv.Client(),
	}
	pool.mu.Unlock()

	// Alice's terminal should resolve to peer
	url, err := pool.PeerTerminalURL("alice", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expectedURL := fmt.Sprintf("ws://%s/v1/containers/alice/terminal", srv.Listener.Addr().String())
	if url != expectedURL {
		t.Errorf("expected %q, got %q", expectedURL, url)
	}

	// Unknown user should return empty
	url, err = pool.PeerTerminalURL("unknown", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if url != "" {
		t.Errorf("expected empty URL for unknown user, got %q", url)
	}
}

// --- Helpers ---

func pathEndsWith(path, suffix string) bool {
	return len(path) >= len(suffix) && path[len(path)-len(suffix):] == suffix
}

func pathContains(path, sub string) bool {
	for i := 0; i <= len(path)-len(sub); i++ {
		if path[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func extractUsername(path string) string {
	// /v1/containers/{username} or /v1/containers/{username}?force=true
	parts := splitPath(path)
	for i, p := range parts {
		if p == "containers" && i+1 < len(parts) {
			u := parts[i+1]
			// Strip query params
			if idx := indexOf(u, '?'); idx >= 0 {
				return u[:idx]
			}
			return u
		}
	}
	return ""
}

func splitPath(path string) []string {
	var parts []string
	start := 0
	for i := 0; i <= len(path); i++ {
		if i == len(path) || path[i] == '/' {
			if i > start {
				parts = append(parts, path[start:i])
			}
			start = i + 1
		}
	}
	return parts
}

func indexOf(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}
