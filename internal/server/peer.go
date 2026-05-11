package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	neturl "net/url"
	"strings"
	"sync"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
	metricsPackage "github.com/footprintai/containarium/internal/metrics"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// PeerClient represents a connection to a remote containarium daemon.
type PeerClient struct {
	ID         string
	Addr       string // host:port of the remote daemon's REST API
	Healthy    bool
	LastSeenAt time.Time // Timestamp of last successful health check
	client     *http.Client
	token      string // JWT token for auth (if needed)

	// Cached system info from last discovery poll
	CachedHostname       string
	CachedOS             string
	CachedVersion        string
	CachedContainerCount int32
}

// PeerPool manages connections to remote containarium daemon peers.
// The primary daemon uses this to fan out API calls to other backends.
type PeerPool struct {
	mu    sync.RWMutex
	peers map[string]*PeerClient

	// Auto-discovery from sentinel
	sentinelURL    string
	pool           string // if non-empty, only peers tagged with this pool are discovered
	discoveryStop  chan struct{}
	localBackendID string // this daemon's backend ID
}

// NewPeerPool creates a new peer pool.
// If sentinelURL is provided, it will auto-discover tunnel backends.
// localBackendID is used to tag local containers.
// pool, when non-empty, scopes auto-discovery to peers tagged with that pool only;
// pass "" to see all peers regardless of tag.
func NewPeerPool(localBackendID string, sentinelURL string, staticPeers []string, pool string) *PeerPool {
	p := &PeerPool{
		peers:          make(map[string]*PeerClient),
		sentinelURL:    sentinelURL,
		pool:           pool,
		localBackendID: localBackendID,
	}

	// Add static peers
	for _, addr := range staticPeers {
		p.peers[addr] = &PeerClient{
			ID:   addr,
			Addr: addr,
			client: &http.Client{
				Timeout: 30 * time.Second,
			},
		}
	}

	return p
}

// StartDiscovery starts background auto-discovery of peers from the sentinel.
func (p *PeerPool) StartDiscovery(ctx context.Context) {
	if p.sentinelURL == "" {
		return
	}

	p.discoveryStop = make(chan struct{})
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		// Initial discovery
		p.discover()

		for {
			select {
			case <-ctx.Done():
				return
			case <-p.discoveryStop:
				return
			case <-ticker.C:
				p.discover()
			}
		}
	}()
	log.Printf("[peers] auto-discovery started (sentinel: %s)", p.sentinelURL)
}

// discover fetches peer list from sentinel's /sentinel/peers endpoint.
// When p.pool is non-empty, ?pool=<name> is appended so the sentinel returns
// only peers tagged with that pool.
func (p *PeerPool) discover() {
	url := p.sentinelURL + "/sentinel/peers"
	if p.pool != "" {
		url += "?pool=" + neturl.QueryEscape(p.pool)
	}
	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := client.Get(url)
	if err != nil {
		log.Printf("[peers] discovery failed: %v", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	var result struct {
		Peers []struct {
			ID        string `json:"id"`
			ProxyPath string `json:"proxy_path"`
			Healthy   bool   `json:"healthy"`
		} `json:"peers"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		log.Printf("[peers] discovery parse error: %v", err)
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Build new peer set from discovery
	// Peer address is the sentinel's binary server (port 8888) + proxy path
	// e.g., "10.130.0.13:8888/peer/tunnel-fts-5900x-gpu"
	sentinelHost := extractHost(p.sentinelURL)
	sentinelPort := extractPort(p.sentinelURL)

	discovered := make(map[string]bool)
	for _, peer := range result.Peers {
		discovered[peer.ID] = true

		// The peer addr includes the proxy path prefix
		// API calls will be: http://sentinelHost:sentinelPort/peer/<id>/v1/containers
		peerAddr := fmt.Sprintf("%s:%s%s", sentinelHost, sentinelPort, peer.ProxyPath)

		if existing, ok := p.peers[peer.ID]; ok {
			existing.Addr = peerAddr
			existing.Healthy = peer.Healthy
			if peer.Healthy {
				existing.LastSeenAt = time.Now()
			}
		} else {
			pc := &PeerClient{
				ID:      peer.ID,
				Addr:    peerAddr,
				Healthy: peer.Healthy,
				client: &http.Client{
					Timeout: 30 * time.Second,
				},
			}
			if peer.Healthy {
				pc.LastSeenAt = time.Now()
			}
			p.peers[peer.ID] = pc
			log.Printf("[peers] discovered new peer: %s via %s", peer.ID, peerAddr)
		}
	}

	// Remove peers that are no longer in the sentinel's list
	// (but don't remove static peers)
	for id := range p.peers {
		if !discovered[id] && isDiscoveredPeer(id) {
			log.Printf("[peers] peer removed: %s", id)
			delete(p.peers, id)
		}
	}

	// Cache system info for healthy peers (best-effort, no auth needed for internal calls)
	for _, pc := range p.peers {
		if !pc.Healthy {
			continue
		}
		go pc.refreshCachedInfo()
	}
}

// LocalBackendID returns this daemon's backend ID.
func (p *PeerPool) LocalBackendID() string {
	return p.localBackendID
}

// Peers returns all current peers.
func (p *PeerPool) Peers() []*PeerClient {
	p.mu.RLock()
	defer p.mu.RUnlock()
	result := make([]*PeerClient, 0, len(p.peers))
	for _, peer := range p.peers {
		result = append(result, peer)
	}
	return result
}

// Get returns a peer by ID.
func (p *PeerPool) Get(id string) *PeerClient {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.peers[id]
}

// ListContainers fans out to all healthy peers and returns merged container list.
// Each container gets a backend_id field set to the peer's ID.
func (p *PeerPool) ListContainers(authToken string) []incus.ContainerInfo {
	peers := p.Peers()
	if len(peers) == 0 {
		return nil
	}

	type result struct {
		peerID     string
		containers []incus.ContainerInfo
	}

	var wg sync.WaitGroup
	results := make(chan result, len(peers))

	for _, peer := range peers {
		if !peer.Healthy {
			continue
		}
		wg.Add(1)
		go func(pc *PeerClient) {
			defer wg.Done()
			containers, err := pc.fetchContainers(authToken)
			if err != nil {
				log.Printf("[peers] failed to list containers from %s: %v", pc.ID, err)
				return
			}
			results <- result{peerID: pc.ID, containers: containers}
		}(peer)
	}

	wg.Wait()
	close(results)

	var all []incus.ContainerInfo
	for res := range results {
		all = append(all, res.containers...)
	}
	return all
}

// fetchContainers fetches containers from a single peer.
func (pc *PeerClient) fetchContainers(authToken string) ([]incus.ContainerInfo, error) {
	// Addr includes proxy path, e.g. "10.130.0.13:8888/peer/tunnel-fts-5900x-gpu"
	url := fmt.Sprintf("http://%s/v1/containers", pc.Addr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}

	resp, err := pc.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var data struct {
		Containers []struct {
			Name      string `json:"name"`
			Username  string `json:"username"`
			State     string `json:"state"`
			Resources struct {
				CPU    string `json:"cpu"`
				Memory string `json:"memory"`
				Disk   string `json:"disk"`
				GPU    string `json:"gpu"`
			} `json:"resources"`
			Network struct {
				IPAddress string `json:"ipAddress"`
			} `json:"network"`
			Labels    map[string]string `json:"labels"`
			GpuDevice string            `json:"gpuDevice"`
			BackendID string            `json:"backendId"`
		} `json:"containers"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}

	containers := make([]incus.ContainerInfo, 0, len(data.Containers))
	for _, c := range data.Containers {
		// Map state string
		state := c.State
		if state == "CONTAINER_STATE_RUNNING" {
			state = "Running"
		} else if state == "CONTAINER_STATE_STOPPED" {
			state = "Stopped"
		}

		containers = append(containers, incus.ContainerInfo{
			Name:      c.Name,
			State:     state,
			IPAddress: c.Network.IPAddress,
			CPU:       c.Resources.CPU,
			Memory:    c.Resources.Memory,
			Disk:      c.Resources.Disk,
			GPU:       c.GpuDevice,
			Labels:    c.Labels,
			BackendID: pc.ID, // Tag with peer's backend ID
		})
	}
	return containers, nil
}

// ForwardCreateContainer forwards a create container request to a specific peer.
func (pc *PeerClient) ForwardCreateContainer(authToken string, pbReq *pb.CreateContainerRequest) (*pb.CreateContainerResponse, error) {
	// Use camelCase field names — gRPC-gateway's protojson uses camelCase,
	// not snake_case, when unmarshaling JSON into proto messages.
	reqBody := map[string]interface{}{
		"username": pbReq.Username,
		"image":    pbReq.Image,
		"resources": map[string]string{
			"cpu":    pbReq.Resources.GetCpu(),
			"memory": pbReq.Resources.GetMemory(),
			"disk":   pbReq.Resources.GetDisk(),
		},
		"sshKeys":         pbReq.SshKeys,
		"enablePodman":    pbReq.EnablePodman,
		"stack":           pbReq.Stack,
		"stackParameters": pbReq.StackParameters,
		"gpu":             pbReq.Gpu,
		"staticIp":        pbReq.StaticIp,
		"labels":          pbReq.Labels,
		"async":           pbReq.Async,
		"osType":          int32(pbReq.OsType),
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	url := fmt.Sprintf("http://%s/v1/containers", pc.Addr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}

	resp, err := pc.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("peer returned status %d: %s", resp.StatusCode, string(respBody))
	}

	// Parse the response into proto format
	var data struct {
		Container struct {
			Name     string `json:"name"`
			Username string `json:"username"`
			State    string `json:"state"`
			Network  struct {
				IPAddress string `json:"ipAddress"`
			} `json:"network"`
			Resources struct {
				CPU    string `json:"cpu"`
				Memory string `json:"memory"`
				Disk   string `json:"disk"`
			} `json:"resources"`
		} `json:"container"`
		Message    string `json:"message"`
		SshCommand string `json:"sshCommand"`
	}
	if err := json.Unmarshal(respBody, &data); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return &pb.CreateContainerResponse{
		Container: &pb.Container{
			Name:     data.Container.Name,
			Username: data.Container.Username,
			BackendId: pc.ID,
			Network: &pb.NetworkInfo{
				IpAddress: data.Container.Network.IPAddress,
			},
			Resources: &pb.ResourceLimits{
				Cpu:    data.Container.Resources.CPU,
				Memory: data.Container.Resources.Memory,
				Disk:   data.Container.Resources.Disk,
			},
		},
		Message:    data.Message,
		SshCommand: data.SshCommand,
	}, nil
}

// ForwardRequest forwards an arbitrary HTTP request to the peer and returns the response body.
// GET requests use a 5s timeout to avoid blocking the UI; POST/PUT use 30s for mutations.
func (pc *PeerClient) ForwardRequest(method, path, authToken string, body []byte) ([]byte, int, error) {
	url := fmt.Sprintf("http://%s%s", pc.Addr, path)

	timeout := 5 * time.Second
	if method != "GET" {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}

	resp, err := pc.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return respBody, resp.StatusCode, nil
}

// ForwardGetMetrics fetches container metrics from a peer.
// Returns raw JSON response body for the caller to merge.
func (pc *PeerClient) ForwardGetMetrics(authToken string, username string) ([]byte, error) {
	path := "/v1/metrics"
	if username != "" {
		path = fmt.Sprintf("/v1/metrics/%s", username)
	}
	body, status, err := pc.ForwardRequest("GET", path, authToken, nil)
	if err != nil {
		return nil, fmt.Errorf("forward metrics to %s: %w", pc.ID, err)
	}
	if status >= 400 {
		return nil, fmt.Errorf("peer %s returned status %d for metrics", pc.ID, status)
	}
	return body, nil
}

// refreshCachedInfo fetches system info from a peer and caches key fields.
func (pc *PeerClient) refreshCachedInfo() {
	body, err := pc.ForwardGetSystemInfo("")
	if err != nil {
		return
	}
	var result struct {
		Info struct {
			Hostname          string `json:"hostname"`
			OS                string `json:"os"`
			IncusVersion      string `json:"incusVersion"`
			ContainersRunning int32  `json:"containersRunning"`
		} `json:"info"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return
	}
	pc.CachedHostname = result.Info.Hostname
	pc.CachedOS = result.Info.OS
	pc.CachedContainerCount = result.Info.ContainersRunning
	// Version is not in system info — peers report it separately or we skip it
}

// ForwardGetSystemInfo fetches system info from a peer.
func (pc *PeerClient) ForwardGetSystemInfo(authToken string) ([]byte, error) {
	body, status, err := pc.ForwardRequest("GET", "/v1/system/info", authToken, nil)
	if err != nil {
		return nil, fmt.Errorf("forward system-info to %s: %w", pc.ID, err)
	}
	if status >= 400 {
		return nil, fmt.Errorf("peer %s returned status %d for system-info", pc.ID, status)
	}
	return body, nil
}

// ForwardSecuritySummary fetches security summary from a peer.
func (pc *PeerClient) ForwardSecuritySummary(authToken string) ([]byte, error) {
	body, status, err := pc.ForwardRequest("GET", "/v1/security/clamav-summary", authToken, nil)
	if err != nil {
		return nil, fmt.Errorf("forward security summary to %s: %w", pc.ID, err)
	}
	if status >= 400 {
		return nil, fmt.Errorf("peer %s returned status %d for security summary", pc.ID, status)
	}
	return body, nil
}

// ForwardSecurityReports fetches ClamAV scan reports from a peer.
func (pc *PeerClient) ForwardSecurityReports(authToken string, queryParams string) ([]byte, error) {
	path := "/v1/security/clamav-reports"
	if queryParams != "" {
		path = path + "?" + queryParams
	}
	body, status, err := pc.ForwardRequest("GET", path, authToken, nil)
	if err != nil {
		return nil, fmt.Errorf("forward security reports to %s: %w", pc.ID, err)
	}
	if status >= 400 {
		return nil, fmt.Errorf("peer %s returned status %d for security reports", pc.ID, status)
	}
	return body, nil
}

// ForwardScanStatus fetches scan job status from a peer.
func (pc *PeerClient) ForwardScanStatus(authToken string) ([]byte, error) {
	body, status, err := pc.ForwardRequest("GET", "/v1/security/scan-status", authToken, nil)
	if err != nil {
		return nil, fmt.Errorf("forward scan status to %s: %w", pc.ID, err)
	}
	if status >= 400 {
		return nil, fmt.Errorf("peer %s returned status %d for scan status", pc.ID, status)
	}
	return body, nil
}

// ForwardTriggerScan triggers a ClamAV scan on a peer.
func (pc *PeerClient) ForwardTriggerScan(authToken string, containerName string) ([]byte, error) {
	payload := []byte(`{}`)
	if containerName != "" {
		payload = []byte(fmt.Sprintf(`{"container_name":"%s"}`, containerName))
	}
	body, status, err := pc.ForwardRequest("POST", "/v1/security/clamav-scan", authToken, payload)
	if err != nil {
		return nil, fmt.Errorf("forward trigger scan to %s: %w", pc.ID, err)
	}
	if status >= 400 {
		return nil, fmt.Errorf("peer %s returned status %d for trigger scan", pc.ID, status)
	}
	return body, nil
}

// ForwardContainerTraffic fetches traffic data for a container on a peer.
func (pc *PeerClient) ForwardContainerTraffic(authToken string, path string) ([]byte, error) {
	body, status, err := pc.ForwardRequest("GET", path, authToken, nil)
	if err != nil {
		return nil, fmt.Errorf("forward traffic to %s: %w", pc.ID, err)
	}
	if status >= 400 {
		return nil, fmt.Errorf("peer %s returned status %d for traffic", pc.ID, status)
	}
	return body, nil
}

// FindContainerPeer searches all peers for a container by username.
// Returns the peer that has it, or nil if not found on any peer.
func (pp *PeerPool) FindContainerPeer(username, authToken string) *PeerClient {
	containerName := username + "-container"
	for _, peer := range pp.Peers() {
		if !peer.Healthy {
			log.Printf("[FindContainerPeer] skipping unhealthy peer %s", peer.ID)
			continue
		}
		containers, err := peer.fetchContainers(authToken)
		if err != nil {
			log.Printf("[FindContainerPeer] peer %s fetchContainers failed: %v", peer.ID, err)
			continue
		}
		for _, c := range containers {
			if c.Name == containerName {
				return peer
			}
		}
	}
	return nil
}

// extractHost extracts the hostname/IP from a URL like "http://10.128.0.5:8081"
func extractHost(rawURL string) string {
	// Simple extraction — strip scheme and port
	host := rawURL
	if idx := len("http://"); len(host) > idx && host[:idx] == "http://" {
		host = host[idx:]
	}
	if idx := len("https://"); len(host) > idx && host[:idx] == "https://" {
		host = host[idx:]
	}
	// Strip port
	for i := len(host) - 1; i >= 0; i-- {
		if host[i] == ':' {
			return host[:i]
		}
		if host[i] == '/' {
			return host[:i]
		}
	}
	return host
}

// extractPort extracts the port from a URL like "http://10.128.0.5:8888"
func extractPort(rawURL string) string {
	host := rawURL
	// Strip scheme
	if idx := strings.Index(host, "://"); idx >= 0 {
		host = host[idx+3:]
	}
	// Strip path
	if idx := strings.Index(host, "/"); idx >= 0 {
		host = host[:idx]
	}
	// Extract port
	if idx := strings.LastIndex(host, ":"); idx >= 0 {
		return host[idx+1:]
	}
	return "8888" // default
}

// isDiscoveredPeer returns true if the peer ID looks like a tunnel-discovered peer.
func isDiscoveredPeer(id string) bool {
	return len(id) > 7 && id[:7] == "tunnel-"
}

// PeerTerminalURL implements gateway.PeerTerminalProxy.
// It checks if a container lives on a peer and returns the WebSocket URL for its terminal.
// Returns ("", nil) if the container is not on any peer (i.e., it's local).
func (pp *PeerPool) PeerTerminalURL(username, authToken string) (string, error) {
	peer := pp.FindContainerPeer(username, authToken)
	if peer == nil {
		return "", nil
	}
	// Build ws:// URL pointing at the peer's terminal endpoint via sentinel proxy
	wsURL := fmt.Sprintf("ws://%s/v1/containers/%s/terminal", peer.Addr, username)
	return wsURL, nil
}

// jsonReader wraps a byte slice as an io.Reader.
func jsonReader(b []byte) io.Reader {
	return io.NopCloser(io.Reader(byteReader(b)))
}

type byteReader []byte

func (b byteReader) Read(p []byte) (n int, err error) {
	return copy(p, b), io.EOF
}

// PeerMetricsFetcherAdapter adapts PeerPool to the metrics.PeerMetricsFetcher interface.
type PeerMetricsFetcherAdapter struct {
	Pool         *PeerPool
	ServiceToken string // JWT token for authenticating internal requests to peers
}

// FetchPeerMetrics implements metrics.PeerMetricsFetcher.
func (a *PeerMetricsFetcherAdapter) FetchPeerMetrics(authToken string) []peerMetricsResult {
	var results []peerMetricsResult
	if a.Pool == nil {
		return results
	}
	// Use service token if no auth token provided
	token := authToken
	if token == "" {
		token = a.ServiceToken
	}
	peers := a.Pool.Peers()
	if len(peers) == 0 {
		return results
	}
	for _, peer := range peers {
		if !peer.Healthy {
			continue
		}
		body, err := peer.ForwardGetMetrics(token, "")
		if err != nil {
			log.Printf("[peer-metrics] failed to fetch from %s: %v", peer.ID, err)
			continue
		}
		// Parse the JSON response — values may be strings or numbers from gRPC-gateway
		var resp struct {
			Metrics []struct {
				Name             string          `json:"name"`
				CpuUsageSeconds  json.Number     `json:"cpuUsageSeconds"`
				MemoryUsageBytes json.Number     `json:"memoryUsageBytes"`
				DiskUsageBytes   json.Number     `json:"diskUsageBytes"`
				NetworkRxBytes   json.Number     `json:"networkRxBytes"`
				NetworkTxBytes   json.Number     `json:"networkTxBytes"`
				ProcessCount     json.Number     `json:"processCount"`
			} `json:"metrics"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			log.Printf("[peer-metrics] parse error from %s: %v (body: %.200s)", peer.ID, err, string(body))
			continue
		}
		for _, m := range resp.Metrics {
			cpuS, _ := m.CpuUsageSeconds.Int64()
			memB, _ := m.MemoryUsageBytes.Int64()
			diskB, _ := m.DiskUsageBytes.Int64()
			netRx, _ := m.NetworkRxBytes.Int64()
			netTx, _ := m.NetworkTxBytes.Int64()
			procs, _ := m.ProcessCount.Int64()
			results = append(results, peerMetricsResult{
				ContainerName:    m.Name,
				BackendID:        peer.ID,
				CPUUsageSeconds:  cpuS,
				MemoryUsageBytes: memB,
				DiskUsageBytes:   diskB,
				NetworkRxBytes:   netRx,
				NetworkTxBytes:   netTx,
				ProcessCount:     procs,
			})
		}
	}
	return results
}

// FetchPeerSystemMetrics implements metrics.PeerMetricsFetcher.
func (a *PeerMetricsFetcherAdapter) FetchPeerSystemMetrics(authToken string) []metricsPackage.PeerSystemMetrics {
	var results []metricsPackage.PeerSystemMetrics
	if a.Pool == nil {
		return results
	}
	token := authToken
	if token == "" {
		token = a.ServiceToken
	}
	for _, peer := range a.Pool.Peers() {
		if !peer.Healthy {
			continue
		}
		body, err := peer.ForwardGetSystemInfo(token)
		if err != nil {
			continue
		}
		var resp struct {
			Info struct {
				TotalCpus            json.Number `json:"totalCpus"`
				TotalMemoryBytes     json.Number `json:"totalMemoryBytes"`
				AvailableMemoryBytes json.Number `json:"availableMemoryBytes"`
				TotalDiskBytes       json.Number `json:"totalDiskBytes"`
				AvailableDiskBytes   json.Number `json:"availableDiskBytes"`
				CpuLoad1Min          json.Number `json:"cpuLoad1min"`
				CpuLoad5Min          json.Number `json:"cpuLoad5min"`
				CpuLoad15Min         json.Number `json:"cpuLoad15min"`
				ContainersRunning    json.Number `json:"containersRunning"`
				ContainersStopped    json.Number `json:"containersStopped"`
			} `json:"info"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			continue
		}
		totalCpus, _ := resp.Info.TotalCpus.Int64()
		totalMem, _ := resp.Info.TotalMemoryBytes.Int64()
		availMem, _ := resp.Info.AvailableMemoryBytes.Int64()
		totalDisk, _ := resp.Info.TotalDiskBytes.Int64()
		availDisk, _ := resp.Info.AvailableDiskBytes.Int64()
		load1, _ := resp.Info.CpuLoad1Min.Float64()
		load5, _ := resp.Info.CpuLoad5Min.Float64()
		load15, _ := resp.Info.CpuLoad15Min.Float64()
		cRunning, _ := resp.Info.ContainersRunning.Int64()
		cStopped, _ := resp.Info.ContainersStopped.Int64()
		results = append(results, metricsPackage.PeerSystemMetrics{
			BackendID:         peer.ID,
			TotalCPUs:         totalCpus,
			TotalMemoryBytes:  totalMem,
			UsedMemoryBytes:   totalMem - availMem,
			TotalDiskBytes:    totalDisk,
			UsedDiskBytes:     totalDisk - availDisk,
			CPULoad1Min:       load1,
			CPULoad5Min:       load5,
			CPULoad15Min:      load15,
			ContainersRunning: cRunning,
			ContainersStopped: cStopped,
		})
	}
	return results
}

// FetchPeerHealth implements metrics.PeerMetricsFetcher.
func (a *PeerMetricsFetcherAdapter) FetchPeerHealth() []metricsPackage.PeerBackendHealth {
	var results []metricsPackage.PeerBackendHealth
	if a.Pool == nil {
		return results
	}
	for _, peer := range a.Pool.Peers() {
		results = append(results, metricsPackage.PeerBackendHealth{
			BackendID: peer.ID,
			Healthy:   peer.Healthy,
			LastSeen:  peer.LastSeenAt,
		})
	}
	return results
}

// peerMetricsResult matches metrics.PeerMetrics to avoid circular import.
type peerMetricsResult = metricsPackage.PeerMetrics
