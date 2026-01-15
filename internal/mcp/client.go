package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is a REST API client for Containarium
type Client struct {
	baseURL    string
	jwtToken   string
	httpClient *http.Client
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

// API Request/Response types

type CreateContainerRequest struct {
	Username  string                 `json:"username"`
	Resources *ResourceLimits        `json:"resources,omitempty"`
	SSHKeys   []string               `json:"sshKeys,omitempty"`
	Labels    map[string]string      `json:"labels,omitempty"`
	Image     string                 `json:"image,omitempty"`
	EnableDocker bool                `json:"enableDocker,omitempty"`
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

type Container struct {
	Name          string            `json:"name"`
	Username      string            `json:"username"`
	State         string            `json:"state"`
	Resources     *ResourceLimits   `json:"resources,omitempty"`
	SSHKeys       []string          `json:"sshKeys,omitempty"`
	Network       *NetworkInfo      `json:"network,omitempty"`
	CreatedAt     int64             `json:"createdAt"`
	UpdatedAt     int64             `json:"updatedAt,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
	Image         string            `json:"image,omitempty"`
	DockerEnabled bool              `json:"dockerEnabled"`
}

type NetworkInfo struct {
	IPAddress  string `json:"ipAddress,omitempty"`
	MacAddress string `json:"macAddress,omitempty"`
	Interface  string `json:"interface,omitempty"`
	Bridge     string `json:"bridge,omitempty"`
}

type ContainerMetrics struct {
	Name             string `json:"name"`
	CPUUsageSeconds  int64  `json:"cpuUsageSeconds"`
	MemoryUsageBytes int64  `json:"memoryUsageBytes"`
	MemoryPeakBytes  int64  `json:"memoryPeakBytes"`
	DiskUsageBytes   int64  `json:"diskUsageBytes"`
	NetworkRxBytes   int64  `json:"networkRxBytes"`
	NetworkTxBytes   int64  `json:"networkTxBytes"`
	ProcessCount     int32  `json:"processCount"`
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
