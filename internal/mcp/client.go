package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is a REST API client for Containarium. Carries a small amount
// of non-HTTP deployment metadata (SentinelHost) so tool handlers that
// need it can read it without a separate config plumbing layer.
type Client struct {
	baseURL    string
	jwtToken   string
	httpClient *http.Client

	// SentinelHost, when set, is the public SSH endpoint for this
	// deployment (e.g. "sentinel.example.com" or "34.42.156.100").
	// create_container's response uses it to construct a complete
	// ready-to-paste ssh command. Empty means the response falls
	// back to a placeholder.
	SentinelHost string
}

// NewClient creates a new Containarium REST API client
func NewClient(baseURL, jwtToken string) *Client {
	return &Client{
		baseURL:  baseURL,
		jwtToken: jwtToken,
		httpClient: &http.Client{
			Timeout: 120 * time.Second, // Container creation can take time
		},
	}
}

// doRequest performs an HTTP request with JWT authentication
func (c *Client) doRequest(method, path string, body interface{}) ([]byte, error) {
	url := c.baseURL + path

	var reqBody io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request: %w", err)
		}
		reqBody = bytes.NewReader(jsonData)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add JWT token
	req.Header.Set("Authorization", "Bearer "+c.jwtToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// CreateContainer creates a new container
func (c *Client) CreateContainer(req CreateContainerRequest) (*CreateContainerResponse, error) {
	respBody, err := c.doRequest("POST", "/v1/containers", req)
	if err != nil {
		return nil, err
	}

	var resp CreateContainerResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &resp, nil
}

// ListContainers lists all containers
func (c *Client) ListContainers() (*ListContainersResponse, error) {
	respBody, err := c.doRequest("GET", "/v1/containers", nil)
	if err != nil {
		return nil, err
	}

	var resp ListContainersResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &resp, nil
}

// GetContainer gets a specific container
func (c *Client) GetContainer(username string) (*GetContainerResponse, error) {
	respBody, err := c.doRequest("GET", "/v1/containers/"+username, nil)
	if err != nil {
		return nil, err
	}

	var resp GetContainerResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &resp, nil
}

// DebugContainer returns a diagnostic report for a container's SSH path.
// One layer deeper than the agent's raw ssh error — surfaces host-side
// state the agent can't see directly (user account, shell file, sshd logs).
func (c *Client) DebugContainer(username string) (*DebugContainerResponse, error) {
	respBody, err := c.doRequest("GET", "/v1/containers/"+username+"/debug", nil)
	if err != nil {
		return nil, err
	}

	var resp DebugContainerResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &resp, nil
}

// DeleteContainer deletes a container
func (c *Client) DeleteContainer(username string, force bool) (*DeleteContainerResponse, error) {
	path := fmt.Sprintf("/v1/containers/%s?force=%v", username, force)
	respBody, err := c.doRequest("DELETE", path, nil)
	if err != nil {
		return nil, err
	}

	var resp DeleteContainerResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &resp, nil
}

// StartContainer starts a stopped container
func (c *Client) StartContainer(username string) (*StartContainerResponse, error) {
	respBody, err := c.doRequest("POST", "/v1/containers/"+username+"/start", nil)
	if err != nil {
		return nil, err
	}

	var resp StartContainerResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &resp, nil
}

// StopContainer stops a running container
func (c *Client) StopContainer(username string, force bool) (*StopContainerResponse, error) {
	req := map[string]interface{}{
		"force": force,
	}
	respBody, err := c.doRequest("POST", "/v1/containers/"+username+"/stop", req)
	if err != nil {
		return nil, err
	}

	var resp StopContainerResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &resp, nil
}

// GetMetrics gets container metrics
func (c *Client) GetMetrics(username string) (*GetMetricsResponse, error) {
	path := "/v1/metrics"
	if username != "" {
		path = "/v1/metrics/" + username
	}

	respBody, err := c.doRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}

	var resp GetMetricsResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &resp, nil
}

// GetSystemInfo gets system information
func (c *Client) GetSystemInfo() (*GetSystemInfoResponse, error) {
	respBody, err := c.doRequest("GET", "/v1/system/info", nil)
	if err != nil {
		return nil, err
	}

	var resp GetSystemInfoResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &resp, nil
}

// AddRoute creates a domain → container:port mapping in the sentinel
// reverse proxy. Used by the expose_port tool to make a container
// reachable on the public internet under a chosen hostname.
func (c *Client) AddRoute(req AddRouteRequest) (*AddRouteResponse, error) {
	respBody, err := c.doRequest("POST", "/v1/network/routes", req)
	if err != nil {
		return nil, err
	}

	var resp AddRouteResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &resp, nil
}

// ListBackends returns the cluster topology — the local daemon plus any
// tunnel-connected peers. Used by the list_backends MCP tool so an
// agent can reason about peer health, container counts, and GPU
// inventory without inferring topology from container IPs.
func (c *Client) ListBackends() (*ListBackendsResponse, error) {
	respBody, err := c.doRequest("GET", "/v1/backends", nil)
	if err != nil {
		return nil, err
	}

	var resp ListBackendsResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &resp, nil
}

// GetBackend returns a single backend by ID. The daemon doesn't have a
// dedicated /v1/backends/{id} endpoint (the only path-with-id route is
// /v1/backends/{id}/system-info, which forwards to that backend), so
// we implement it client-side as a list-and-filter. The list is small
// (typically a handful of peers), and this keeps the wire surface
// stable for now — easy to swap for a dedicated endpoint later.
func (c *Client) GetBackend(id string) (*Backend, error) {
	resp, err := c.ListBackends()
	if err != nil {
		return nil, err
	}
	for i := range resp.Backends {
		if resp.Backends[i].ID == id {
			return &resp.Backends[i], nil
		}
	}
	return nil, fmt.Errorf("backend %q not found", id)
}

// API Request/Response types

type CreateContainerRequest struct {
	Username     string            `json:"username"`
	Resources    *ResourceLimits   `json:"resources,omitempty"`
	SSHKeys      []string          `json:"sshKeys,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
	Image        string            `json:"image,omitempty"`
	EnablePodman bool              `json:"enablePodman,omitempty"`
	GPU          string            `json:"gpu,omitempty"`
}

type ResourceLimits struct {
	CPU    string `json:"cpu,omitempty"`
	Memory string `json:"memory,omitempty"`
	Disk   string `json:"disk,omitempty"`
}

type CreateContainerResponse struct {
	Container  Container `json:"container"`
	Message    string    `json:"message"`
	SSHCommand string    `json:"sshCommand,omitempty"`
}

type ListContainersResponse struct {
	Containers []Container `json:"containers"`
	TotalCount int         `json:"totalCount"`
}

type GetContainerResponse struct {
	Container Container         `json:"container"`
	Metrics   *ContainerMetrics `json:"metrics,omitempty"`
}

type DebugContainerResponse struct {
	ContainerState       string   `json:"containerState"`
	HostUserExists       bool     `json:"hostUserExists"`
	HostUserShell        string   `json:"hostUserShell"`
	HostUserShellExists  bool     `json:"hostUserShellExists"`
	RecentSshdRejections []string `json:"recentSshdRejections"`
	LikelyCause          string   `json:"likelyCause"`
	NextActions          []string `json:"nextActions"`
	SourceRepo           string   `json:"sourceRepo,omitempty"`
	DaemonVersion        string   `json:"daemonVersion,omitempty"`
}

type DeleteContainerResponse struct {
	Message       string `json:"message"`
	ContainerName string `json:"containerName"`
}

type StartContainerResponse struct {
	Message   string    `json:"message"`
	Container Container `json:"container"`
}

type StopContainerResponse struct {
	Message   string    `json:"message"`
	Container Container `json:"container"`
}

type GetMetricsResponse struct {
	Metrics []ContainerMetrics `json:"metrics"`
}

type GetSystemInfoResponse struct {
	Info SystemInfo `json:"info"`
}

// ListBackendsResponse mirrors the hand-coded /v1/backends handler. The
// shape isn't proto-generated, so JSON tag conventions follow what the
// handler emits (camelCase, not snake_case). int64 fields here are
// emitted as numbers (the handler is hand-coded, not grpc-gateway), so
// no `,string` tags needed.
type ListBackendsResponse struct {
	Backends []Backend `json:"backends"`
}

type Backend struct {
	ID             string       `json:"id"`
	Type           string       `json:"type"` // "local" or "tunnel"
	Healthy        bool         `json:"healthy"`
	Version        string       `json:"version,omitempty"`
	Hostname       string       `json:"hostname,omitempty"`
	UptimeSeconds  int64        `json:"uptimeSeconds,omitempty"`
	LastSeenAt     string       `json:"lastSeenAt,omitempty"`
	OS             string       `json:"os,omitempty"`
	ContainerCount int32        `json:"containerCount"`
	GPUs           []BackendGPU `json:"gpus,omitempty"`
}

type BackendGPU struct {
	Vendor    string `json:"vendor,omitempty"`
	ModelName string `json:"modelName,omitempty"`
	VRAMBytes int64  `json:"vramBytes,omitempty"`
}

// AddRouteRequest mirrors network.proto's AddRouteRequest. JSON field
// names match the grpc-gateway HTTP shape (camelCase) so requests
// serialized with encoding/json land at /v1/network/routes correctly.
type AddRouteRequest struct {
	Domain        string `json:"domain"`
	TargetIP      string `json:"targetIp"`
	TargetPort    int32  `json:"targetPort"`
	ContainerName string `json:"containerName,omitempty"`
	Description   string `json:"description,omitempty"`
	// Protocol is "ROUTE_PROTOCOL_HTTP" by default on the server side;
	// expose_port doesn't surface it because the demo path is HTTP.
}

type AddRouteResponse struct {
	Route   ProxyRoute `json:"route"`
	Message string     `json:"message,omitempty"`
}

type ProxyRoute struct {
	Domain        string `json:"domain"`
	ContainerIP   string `json:"containerIp"`
	Port          int32  `json:"port"`
	ContainerName string `json:"containerName,omitempty"`
	Description   string `json:"description,omitempty"`
}

type Container struct {
	Name      string          `json:"name"`
	Username  string          `json:"username"`
	State     string          `json:"state"`
	Resources *ResourceLimits `json:"resources,omitempty"`
	SSHKeys   []string        `json:"sshKeys,omitempty"`
	Network   *NetworkInfo    `json:"network,omitempty"`
	// CreatedAt / UpdatedAt come back as JSON strings from the platform's
	// grpc-gateway HTTP layer — int64 protobuf scalars are emitted as
	// strings to avoid JavaScript number-precision loss. The `,string`
	// tag makes encoding/json round-trip them correctly on both sides.
	CreatedAt     int64             `json:"createdAt,string"`
	UpdatedAt     int64             `json:"updatedAt,string,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
	Image         string            `json:"image,omitempty"`
	PodmanEnabled bool              `json:"podmanEnabled"`
}

type NetworkInfo struct {
	IPAddress  string `json:"ipAddress,omitempty"`
	MacAddress string `json:"macAddress,omitempty"`
	Interface  string `json:"interface,omitempty"`
	Bridge     string `json:"bridge,omitempty"`
}

type ContainerMetrics struct {
	Name string `json:"name"`
	// All int64 fields below come back as JSON strings from grpc-gateway
	// (see Container.CreatedAt for rationale). int32 fields like
	// ProcessCount stay numeric.
	CPUUsageSeconds  int64 `json:"cpuUsageSeconds,string"`
	MemoryUsageBytes int64 `json:"memoryUsageBytes,string"`
	MemoryPeakBytes  int64 `json:"memoryPeakBytes,string"`
	DiskUsageBytes   int64 `json:"diskUsageBytes,string"`
	NetworkRxBytes   int64 `json:"networkRxBytes,string"`
	NetworkTxBytes   int64 `json:"networkTxBytes,string"`
	ProcessCount     int32 `json:"processCount"`
}

type SystemInfo struct {
	IncusVersion      string `json:"incusVersion"`
	OS                string `json:"os"`
	KernelVersion     string `json:"kernelVersion"`
	ContainersRunning int    `json:"containersRunning"`
	ContainersStopped int    `json:"containersStopped"`
	ContainersTotal   int    `json:"containersTotal"`
	Hostname          string `json:"hostname"`
}
