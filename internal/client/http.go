package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/incus"
)

// HTTPClient wraps an HTTP connection to the containarium REST API
type HTTPClient struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// NewHTTPClient creates a new HTTP client
func NewHTTPClient(baseURL string, token string) (*HTTPClient, error) {
	// Ensure baseURL has proper format
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "http://" + baseURL
	}
	// Remove trailing slash
	baseURL = strings.TrimSuffix(baseURL, "/")

	return &HTTPClient{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: 15 * time.Minute, // Match gRPC client timeout for container creation
		},
	}, nil
}

// Close closes the HTTP client (no-op for HTTP, kept for interface compatibility)
func (c *HTTPClient) Close() error {
	return nil
}

// doRequest performs an HTTP request with authentication
func (c *HTTPClient) doRequest(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	return c.httpClient.Do(req)
}

// parseResponse reads and parses the response body
func parseResponse[T any](resp *http.Response) (*T, error) {
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		// Try to parse error response
		var errResp struct {
			Error string `json:"error"`
			Code  int    `json:"code"`
		}
		if json.Unmarshal(bodyBytes, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("%s", errResp.Error)
		}
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result T
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// Container response types matching the protobuf JSON output
type containerResponse struct {
	Name          string            `json:"name"`
	Username      string            `json:"username"`
	State         string            `json:"state"`
	Resources     *resourceLimits   `json:"resources"`
	Network       *networkInfo      `json:"network"`
	CreatedAt     string            `json:"createdAt"`
	Labels        map[string]string `json:"labels"`
	Image         string            `json:"image"`
	DockerEnabled bool              `json:"dockerEnabled"`
}

type resourceLimits struct {
	CPU    string `json:"cpu"`
	Memory string `json:"memory"`
	Disk   string `json:"disk"`
}

type networkInfo struct {
	IPAddress  string `json:"ipAddress"`
	MACAddress string `json:"macAddress"`
	Interface  string `json:"interface"`
	Bridge     string `json:"bridge"`
}

type listContainersResponse struct {
	Containers []containerResponse `json:"containers"`
}

type createContainerResponse struct {
	Container *containerResponse `json:"container"`
}

type getContainerResponse struct {
	Container *containerResponse `json:"container"`
}

type getSystemInfoResponse struct {
	Info *systemInfo `json:"info"`
}

type systemInfo struct {
	IncusVersion         string `json:"incusVersion"`
	KernelVersion        string `json:"kernelVersion"`
	OperatingSystem      string `json:"operatingSystem"`
	TotalContainers      int32  `json:"totalContainers"`
	RunningContainers    int32  `json:"runningContainers"`
	TotalCPUCores        int32  `json:"totalCpuCores"`
	TotalMemoryBytes     int64  `json:"totalMemoryBytes"`
	AvailableMemoryBytes int64  `json:"availableMemoryBytes"`
}

// containerToIncusInfo converts API response to incus.ContainerInfo
func containerToIncusInfo(c *containerResponse) incus.ContainerInfo {
	info := incus.ContainerInfo{
		Name:   c.Name,
		State:  c.State,
		Labels: c.Labels,
	}

	if c.Network != nil {
		info.IPAddress = c.Network.IPAddress
	}

	if c.Resources != nil {
		info.CPU = c.Resources.CPU
		info.Memory = c.Resources.Memory
	}

	// Parse createdAt timestamp (RFC3339 format from protobuf JSON)
	if c.CreatedAt != "" {
		// CreatedAt may be a Unix timestamp string or RFC3339
		if t, err := time.Parse(time.RFC3339, c.CreatedAt); err == nil {
			info.CreatedAt = t
		}
	}

	return info
}

// ListContainers lists all containers via HTTP
func (c *HTTPClient) ListContainers() ([]incus.ContainerInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := c.doRequest(ctx, http.MethodGet, "/v1/containers", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	result, err := parseResponse[listContainersResponse](resp)
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	var containers []incus.ContainerInfo
	for _, container := range result.Containers {
		containers = append(containers, containerToIncusInfo(&container))
	}

	return containers, nil
}

// CreateContainer creates a container via HTTP
func (c *HTTPClient) CreateContainer(username, image, cpu, memory, disk string, sshKeys []string, enableDocker bool) (*incus.ContainerInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	reqBody := map[string]interface{}{
		"username": username,
		"resources": map[string]string{
			"cpu":    cpu,
			"memory": memory,
			"disk":   disk,
		},
		"sshKeys":      sshKeys,
		"image":        image,
		"enableDocker": enableDocker,
	}

	resp, err := c.doRequest(ctx, http.MethodPost, "/v1/containers", reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create container: %w", err)
	}

	result, err := parseResponse[createContainerResponse](resp)
	if err != nil {
		return nil, fmt.Errorf("failed to create container: %w", err)
	}

	if result.Container == nil {
		return nil, fmt.Errorf("no container returned in response")
	}

	info := containerToIncusInfo(result.Container)
	return &info, nil
}

// DeleteContainer deletes a container via HTTP
func (c *HTTPClient) DeleteContainer(username string, force bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	path := fmt.Sprintf("/v1/containers/%s", url.PathEscape(username))
	if force {
		path += "?force=true"
	}

	resp, err := c.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return fmt.Errorf("failed to delete container: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		var errResp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(bodyBytes, &errResp) == nil && errResp.Error != "" {
			return fmt.Errorf("%s", errResp.Error)
		}
		return fmt.Errorf("failed to delete container: status %d", resp.StatusCode)
	}

	return nil
}

// GetContainer gets information about a specific container via HTTP
func (c *HTTPClient) GetContainer(username string) (*incus.ContainerInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	path := fmt.Sprintf("/v1/containers/%s", url.PathEscape(username))
	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get container: %w", err)
	}

	result, err := parseResponse[getContainerResponse](resp)
	if err != nil {
		return nil, fmt.Errorf("failed to get container: %w", err)
	}

	if result.Container == nil {
		return nil, fmt.Errorf("no container returned in response")
	}

	info := containerToIncusInfo(result.Container)
	return &info, nil
}

// GetSystemInfo gets system information via HTTP
func (c *HTTPClient) GetSystemInfo() (*incus.ServerInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := c.doRequest(ctx, http.MethodGet, "/v1/system/info", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get system info: %w", err)
	}

	result, err := parseResponse[getSystemInfoResponse](resp)
	if err != nil {
		return nil, fmt.Errorf("failed to get system info: %w", err)
	}

	if result.Info == nil {
		return nil, fmt.Errorf("no system info returned in response")
	}

	info := &incus.ServerInfo{
		Version:       result.Info.IncusVersion,
		KernelVersion: result.Info.KernelVersion,
	}

	return info, nil
}

// labelResponse is the response from label operations
type labelResponse struct {
	Container string            `json:"container"`
	Labels    map[string]string `json:"labels"`
	Message   string            `json:"message,omitempty"`
}

// SetLabels sets labels on a container via HTTP
func (c *HTTPClient) SetLabels(username string, labels map[string]string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	path := fmt.Sprintf("/v1/containers/%s/labels", url.PathEscape(username))
	reqBody := map[string]interface{}{
		"labels": labels,
	}

	resp, err := c.doRequest(ctx, http.MethodPut, path, reqBody)
	if err != nil {
		return fmt.Errorf("failed to set labels: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		var errResp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(bodyBytes, &errResp) == nil && errResp.Error != "" {
			return fmt.Errorf("%s", errResp.Error)
		}
		return fmt.Errorf("failed to set labels: status %d", resp.StatusCode)
	}

	return nil
}

// RemoveLabel removes a label from a container via HTTP
func (c *HTTPClient) RemoveLabel(username string, key string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	path := fmt.Sprintf("/v1/containers/%s/labels/%s", url.PathEscape(username), url.PathEscape(key))

	resp, err := c.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return fmt.Errorf("failed to remove label: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		var errResp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(bodyBytes, &errResp) == nil && errResp.Error != "" {
			return fmt.Errorf("%s", errResp.Error)
		}
		return fmt.Errorf("failed to remove label: status %d", resp.StatusCode)
	}

	return nil
}

// GetLabels gets labels for a container via HTTP
func (c *HTTPClient) GetLabels(username string) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	path := fmt.Sprintf("/v1/containers/%s/labels", url.PathEscape(username))
	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get labels: %w", err)
	}

	result, err := parseResponse[labelResponse](resp)
	if err != nil {
		return nil, fmt.Errorf("failed to get labels: %w", err)
	}

	return result.Labels, nil
}
