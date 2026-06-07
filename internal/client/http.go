package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/footprintai/containarium/pkg/version"
	"google.golang.org/protobuf/encoding/protojson"
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

	// Pin HTTP/1.1. Go's default client negotiates HTTP/2 via ALPN against
	// an HTTPS server, but a long-running request (a container create can
	// take minutes) carried on an HTTP/2 connection through a fronting TLS
	// edge intermittently gets the connection reset with
	// `remote error: tls: internal error` — the server still completes the
	// work (the box is provisioned), only the response connection dies. The
	// identical request over HTTP/1.1 (e.g. curl's default) is clean. This
	// REST client issues one request per process, so HTTP/2 multiplexing
	// buys nothing here. Clearing TLSNextProto on a cloned default transport
	// is the documented way to force HTTP/1.1 on net/http while keeping the
	// default dial/timeout/proxy behaviour. See FootprintAI/Containarium#422.
	//
	// Clearing TLSNextProto only removes the h2 *handler* — it does NOT
	// constrain ALPN. A fronting edge that defaults to h2 when the client
	// advertises no ALPN protocols (e.g. Cloudflare) then still negotiates
	// HTTP/2, the server sends h2 frames, and the h1 parser chokes on them:
	// `malformed HTTP response "\x00\x00\x12\x04..."` (an h2 SETTINGS frame),
	// deterministically. Pin the ALPN offer to http/1.1 so the edge serves
	// HTTP/1.1 — matching the clean `curl --http1.1` path.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ForceAttemptHTTP2 = false
	transport.TLSNextProto = map[string]func(authority string, c *tls.Conn) http.RoundTripper{}
	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	}

	return &HTTPClient{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout:   15 * time.Minute, // Match gRPC client timeout for container creation
			Transport: transport,
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
	// Advertise the client version so the daemon can log it and, if it
	// chooses, gate on a minimum-supported client. Both the conventional
	// User-Agent and the explicit header are set; a server reads whichever
	// it prefers.
	req.Header.Set("User-Agent", version.UserAgent())
	req.Header.Set(version.ClientVersionHeader, version.GetVersion())

	return c.httpClient.Do(req)
}

// drainClose fully drains then closes an HTTP response body. Draining
// before Close matters for HTTP/2: a body closed while still unread makes
// Go send a RST_STREAM (plus a PING) to cancel the stream, which
// Cloudflare and similar edges treat as abusive client behaviour and
// answer by tearing down the whole connection (GOAWAY ENHANCE_YOUR_CALM)
// — see FootprintAI/Containarium#422 and
// https://blog.cloudflare.com/go-and-enhance-your-calm/. This REST client
// is pinned to HTTP/1.1 today (where the concern is moot), but draining on
// every path keeps it correct if HTTP/2 is ever re-enabled, and it's a
// no-op cost when the caller already read the body to EOF.
func drainClose(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

// parseResponse reads and parses the response body
func parseResponse[T any](resp *http.Response) (*T, error) {
	defer drainClose(resp)

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
	Name                 string            `json:"name"`
	Username             string            `json:"username"`
	State                string            `json:"state"`
	Resources            *resourceLimits   `json:"resources"`
	Network              *networkInfo      `json:"network"`
	CreatedAt            string            `json:"createdAt"`
	Labels               map[string]string `json:"labels"`
	Image                string            `json:"image"`
	PodmanEnabled        bool              `json:"dockerEnabled"`
	GpuDevice            string            `json:"gpuDevice"`
	MonitoringEnabled    bool              `json:"monitoringEnabled"`
	AutoSleepEnabled     bool              `json:"autoSleepEnabled"`
	IdleThresholdMinutes int32             `json:"idleThresholdMinutes"`
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
		Name:                 c.Name,
		Username:             c.Username,
		State:                c.State,
		Labels:               c.Labels,
		MonitoringEnabled:    c.MonitoringEnabled,
		AutoSleepEnabled:     c.AutoSleepEnabled,
		IdleThresholdMinutes: c.IdleThresholdMinutes,
	}

	if c.Network != nil {
		info.IPAddress = c.Network.IPAddress
	}

	if c.Resources != nil {
		info.CPU = c.Resources.CPU
		info.Memory = c.Resources.Memory
	}

	info.GPU = c.GpuDevice

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
// GitSourceOpts carries the optional create-time git provisioning
// parameters. Zero value (Source == "") means "no git source" and the
// daemon skips provisioning. Kept as a struct so CreateContainer's
// already-long signature doesn't grow four more positional strings.
type GitSourceOpts struct {
	Source        string // clone URL; empty disables git provisioning
	Ref           string // SHA / branch / tag / refs/pull/N/merge; empty = default branch
	Credential    string // bearer token for private repos
	WorkspacePath string // empty defaults to /workspace
}

func (c *HTTPClient) CreateContainer(username, image, cpu, memory, disk string, sshKeys []string, enablePodman bool, stack, gpu string, osType pb.OSType, monitoring bool, pool, backendID string, git GitSourceOpts, ttlSeconds int64, idleStopMinutes int32) (*incus.ContainerInfo, error) {
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
		"enablePodman": enablePodman,
		"stack":        stack,
		"gpu":          gpu,
		"osType":       osType,
		"monitoring":   monitoring,
		"pool":         pool,
		"backendId":    backendID,
	}
	if git.Source != "" {
		reqBody["gitSource"] = git.Source
		reqBody["gitRef"] = git.Ref
		reqBody["gitCredential"] = git.Credential
		reqBody["workspacePath"] = git.WorkspacePath
	}
	// Birth TTL (#523): only include when set, so an unset TTL stays absent
	// on the wire (0 = no TTL) rather than forcing a "ttlSeconds":0 the
	// daemon would treat the same but that needlessly differs from a plain
	// create's body.
	if ttlSeconds > 0 {
		reqBody["ttlSeconds"] = ttlSeconds
	}
	// Birth idle-stop (#524): same posture — only include when enabling
	// auto-sleep, so a plain create's body is unchanged.
	if idleStopMinutes > 0 {
		reqBody["idleStopMinutes"] = idleStopMinutes
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

// ToggleAutoSleep writes the per-container auto-sleep opt-in
// metadata via HTTP. See GRPCClient.ToggleAutoSleep for semantics.
func (c *HTTPClient) ToggleAutoSleep(username string, enabled bool, idleThresholdMinutes int32) (*pb.ToggleAutoSleepResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	path := fmt.Sprintf("/v1/containers/%s/auto-sleep", url.PathEscape(username))
	body := map[string]interface{}{
		"enabled":                enabled,
		"idle_threshold_minutes": idleThresholdMinutes,
	}
	resp, err := c.doRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, fmt.Errorf("toggle auto-sleep: %w", err)
	}
	defer drainClose(resp)

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		var errResp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(bodyBytes, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("%s", errResp.Error)
		}
		return nil, fmt.Errorf("toggle auto-sleep: status %d", resp.StatusCode)
	}

	out := &pb.ToggleAutoSleepResponse{}
	if err := protojson.Unmarshal(bodyBytes, out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return out, nil
}

// StartContainer starts a stopped container via HTTP. When
// waitForReady is true the daemon blocks until the container's
// primary TCP port accepts (or readyTimeoutSeconds elapses).
func (c *HTTPClient) StartContainer(username string, waitForReady bool, readyTimeoutSeconds int32) (*pb.StartContainerResponse, error) {
	timeout := 60 * time.Second
	if waitForReady && readyTimeoutSeconds > 0 {
		timeout = time.Duration(readyTimeoutSeconds+10) * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	path := fmt.Sprintf("/v1/containers/%s/start", url.PathEscape(username))
	body := map[string]interface{}{
		"wait_for_ready":        waitForReady,
		"ready_timeout_seconds": readyTimeoutSeconds,
	}
	resp, err := c.doRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, fmt.Errorf("start container: %w", err)
	}
	defer drainClose(resp)

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		var errResp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(bodyBytes, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("%s", errResp.Error)
		}
		return nil, fmt.Errorf("start container: status %d", resp.StatusCode)
	}

	out := &pb.StartContainerResponse{}
	if err := protojson.Unmarshal(bodyBytes, out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return out, nil
}

// StopContainer stops a running container via HTTP.
func (c *HTTPClient) StopContainer(username string, force bool) (*pb.StopContainerResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	path := fmt.Sprintf("/v1/containers/%s/stop", url.PathEscape(username))
	body := map[string]interface{}{"force": force}
	resp, err := c.doRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, fmt.Errorf("stop container: %w", err)
	}
	defer drainClose(resp)

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		var errResp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(bodyBytes, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("%s", errResp.Error)
		}
		return nil, fmt.Errorf("stop container: status %d", resp.StatusCode)
	}

	out := &pb.StopContainerResponse{}
	if err := protojson.Unmarshal(bodyBytes, out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return out, nil
}

// ToggleMonitoring enables / disables OTel app telemetry on an
// existing container via HTTP. Returns (message, monitoring_enabled, error).
func (c *HTTPClient) ToggleMonitoring(username string, enabled bool) (string, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	path := fmt.Sprintf("/v1/containers/%s/monitoring", url.PathEscape(username))
	body, err := json.Marshal(map[string]bool{"enabled": enabled})
	if err != nil {
		return "", false, fmt.Errorf("marshal request: %w", err)
	}
	resp, err := c.doRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return "", false, fmt.Errorf("toggle monitoring: %w", err)
	}
	defer drainClose(resp)

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		var errResp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(bodyBytes, &errResp) == nil && errResp.Error != "" {
			return "", false, fmt.Errorf("%s", errResp.Error)
		}
		return "", false, fmt.Errorf("toggle monitoring: status %d", resp.StatusCode)
	}

	var result struct {
		Message           string `json:"message"`
		MonitoringEnabled bool   `json:"monitoring_enabled"`
	}
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		return "", false, fmt.Errorf("decode response: %w", err)
	}
	return result.Message, result.MonitoringEnabled, nil
}

// RefreshToken exchanges a refresh token for a new
// (access, refresh) pair. Unauthenticated endpoint —
// the refresh token in the body IS the credential.
// Returns (access, refresh, accessExpUnix, refreshExpUnix, error).
func (c *HTTPClient) RefreshToken(refreshTok string) (string, string, int64, int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	body := map[string]string{"refresh_token": refreshTok}
	resp, err := c.doRequest(ctx, http.MethodPost, "/v1/tokens/refresh", body)
	if err != nil {
		return "", "", 0, 0, fmt.Errorf("refresh token: %w", err)
	}
	defer drainClose(resp)
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return "", "", 0, 0, parseErr(b, resp.StatusCode, "refresh token")
	}
	var result struct {
		AccessToken           string `json:"accessToken"`
		RefreshToken          string `json:"refreshToken"`
		AccessTokenExpiresAt  int64  `json:"accessTokenExpiresAt,string"`
		RefreshTokenExpiresAt int64  `json:"refreshTokenExpiresAt,string"`
	}
	if err := json.Unmarshal(b, &result); err != nil {
		return "", "", 0, 0, fmt.Errorf("decode refresh response: %w", err)
	}
	return result.AccessToken, result.RefreshToken, result.AccessTokenExpiresAt, result.RefreshTokenExpiresAt, nil
}

// Revocation is the CLI-facing shape of one revocation
// row returned by ListRevokedTokens. Timestamps are
// RFC3339 strings, matching the wire format.
type Revocation struct {
	JTI       string `json:"jti"`
	ExpiresAt string `json:"expiresAt"`
	RevokedAt string `json:"revokedAt"`
	Reason    string `json:"reason"`
}

// ListRevokedTokens enumerates active revocations.
// Admin-only on the server side; the daemon checks role +
// tokens:write scope. `limit` 0 → server default (100);
// server caps at 1000.
func (c *HTTPClient) ListRevokedTokens(limit int32, includeExpired bool, jtiPrefix string) ([]Revocation, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	q := url.Values{}
	if limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", limit))
	}
	if includeExpired {
		q.Set("includeExpired", "true")
	}
	if jtiPrefix != "" {
		q.Set("jtiPrefix", jtiPrefix)
	}
	path := "/v1/tokens/revoked"
	if encoded := q.Encode(); encoded != "" {
		path += "?" + encoded
	}
	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("list revoked tokens: %w", err)
	}
	defer drainClose(resp)
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, parseErr(b, resp.StatusCode, "list revoked tokens")
	}
	var result struct {
		Revocations []Revocation `json:"revocations"`
	}
	if err := json.Unmarshal(b, &result); err != nil {
		return nil, fmt.Errorf("decode revocations: %w", err)
	}
	return result.Revocations, nil
}

// RevokeToken adds a JWT's jti to the daemon's revocation
// list. Phase 1.2 follow-up — admin-only on the server side.
// `reason` is free-form and recorded for forensics; pass ""
// to let the daemon default it.
func (c *HTTPClient) RevokeToken(jti, reason, expiresAt string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	body := map[string]string{"jti": jti}
	if reason != "" {
		body["reason"] = reason
	}
	if expiresAt != "" {
		body["expires_at"] = expiresAt
	}
	resp, err := c.doRequest(ctx, http.MethodPost, "/v1/tokens/revoke", body)
	if err != nil {
		return "", fmt.Errorf("revoke token: %w", err)
	}
	defer drainClose(resp)
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return "", parseErr(b, resp.StatusCode, "revoke token")
	}
	var result struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(b, &result)
	return result.Message, nil
}

// SetSecret creates or updates a tenant secret via HTTP.
// `delivery` is one of "" (server normalizes to env), "env",
// or "file" (Phase 4.3 — Phase A lands the field; Phase B
// switches behavior on it).
func (c *HTTPClient) SetSecret(username, name, value, delivery string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	payload := map[string]string{
		"username": username,
		"name":     name,
		"value":    value,
	}
	if delivery != "" {
		payload["delivery"] = delivery
	}
	body, _ := json.Marshal(payload)
	resp, err := c.doRequest(ctx, http.MethodPost, "/v1/secrets", body)
	if err != nil {
		return "", fmt.Errorf("set secret: %w", err)
	}
	defer drainClose(resp)
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return "", parseErr(b, resp.StatusCode, "set secret")
	}
	var result struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(b, &result)
	return result.Message, nil
}

// GetSecret reads a single secret's plaintext value via HTTP.
func (c *HTTPClient) GetSecret(username, name string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	path := fmt.Sprintf("/v1/secrets/%s/%s", url.PathEscape(username), url.PathEscape(name))
	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return "", fmt.Errorf("get secret: %w", err)
	}
	defer drainClose(resp)
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return "", parseErr(b, resp.StatusCode, "get secret")
	}
	var result struct {
		Value string `json:"value"`
	}
	_ = json.Unmarshal(b, &result)
	return result.Value, nil
}

// ListSecrets returns metadata for every secret owned by the tenant.
// Each entry is the name/version/timestamps tuple — values are only
// readable via GetSecret per-name.
func (c *HTTPClient) ListSecrets(username string) ([]map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	path := fmt.Sprintf("/v1/secrets/%s", url.PathEscape(username))
	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}
	defer drainClose(resp)
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, parseErr(b, resp.StatusCode, "list secrets")
	}
	var result struct {
		Secrets []map[string]interface{} `json:"secrets"`
	}
	_ = json.Unmarshal(b, &result)
	return result.Secrets, nil
}

// DeleteSecret removes a tenant secret via HTTP.
func (c *HTTPClient) DeleteSecret(username, name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	path := fmt.Sprintf("/v1/secrets/%s/%s", url.PathEscape(username), url.PathEscape(name))
	resp, err := c.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return fmt.Errorf("delete secret: %w", err)
	}
	defer drainClose(resp)
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return parseErr(b, resp.StatusCode, "delete secret")
	}
	return nil
}

// RefreshSecrets re-stamps the tenant's secrets into the LXC env.
func (c *HTTPClient) RefreshSecrets(username string) (string, int32, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	path := fmt.Sprintf("/v1/secrets/%s/refresh", url.PathEscape(username))
	resp, err := c.doRequest(ctx, http.MethodPost, path, []byte("{}"))
	if err != nil {
		return "", 0, fmt.Errorf("refresh secrets: %w", err)
	}
	defer drainClose(resp)
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return "", 0, parseErr(b, resp.StatusCode, "refresh secrets")
	}
	var result struct {
		Message string `json:"message"`
		Stamped int32  `json:"stamped"`
	}
	_ = json.Unmarshal(b, &result)
	return result.Message, result.Stamped, nil
}

// parseErr is a tiny helper used across the secrets HTTP methods to
// surface the server's structured error body (`{"error":"..."}`)
// when present, falling back to the status code otherwise.
func parseErr(body []byte, status int, op string) error {
	var errResp struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
		return fmt.Errorf("%s", errResp.Error)
	}
	return fmt.Errorf("%s: status %d", op, status)
}

// ResizeContainer changes a container's CPU / memory / disk via HTTP.
// Empty string for any field means "no change". Disk can only grow.
func (c *HTTPClient) ResizeContainer(username, cpu, memory, disk string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	path := fmt.Sprintf("/v1/containers/%s/resize", url.PathEscape(username))
	body, err := json.Marshal(map[string]string{
		"cpu":    cpu,
		"memory": memory,
		"disk":   disk,
	})
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}
	resp, err := c.doRequest(ctx, http.MethodPut, path, body)
	if err != nil {
		return "", fmt.Errorf("resize container: %w", err)
	}
	defer drainClose(resp)

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		var errResp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(bodyBytes, &errResp) == nil && errResp.Error != "" {
			return "", fmt.Errorf("%s", errResp.Error)
		}
		return "", fmt.Errorf("resize container: status %d", resp.StatusCode)
	}

	var result struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	return result.Message, nil
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
	defer drainClose(resp)

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

// DebugContainer returns a diagnostic report for a container's SSH path.
func (c *HTTPClient) DebugContainer(username string) (*pb.DebugContainerResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	path := fmt.Sprintf("/v1/containers/%s/debug", url.PathEscape(username))
	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to debug container: %w", err)
	}
	defer drainClose(resp)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("debug container request failed (%d): %s", resp.StatusCode, string(body))
	}

	out := &pb.DebugContainerResponse{}
	if err := protojson.Unmarshal(body, out); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return out, nil
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

// InstallStack installs a stack or base script on a running container via HTTP
func (c *HTTPClient) InstallStack(username, stackID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	path := fmt.Sprintf("/v1/containers/%s/install-stack", url.PathEscape(username))
	reqBody := map[string]interface{}{
		"stackId": stackID,
	}

	resp, err := c.doRequest(ctx, http.MethodPost, path, reqBody)
	if err != nil {
		return fmt.Errorf("failed to install stack: %w", err)
	}
	defer drainClose(resp)

	if resp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		var errResp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(bodyBytes, &errResp) == nil && errResp.Error != "" {
			return fmt.Errorf("%s", errResp.Error)
		}
		return fmt.Errorf("failed to install stack: status %d", resp.StatusCode)
	}

	return nil
}

// ListRecipes lists all built-in recipes via HTTP.
func (c *HTTPClient) ListRecipes() ([]*pb.Recipe, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := c.doRequest(ctx, http.MethodGet, "/v1/recipes", nil)
	if err != nil {
		return nil, fmt.Errorf("list recipes: %w", err)
	}
	defer drainClose(resp)

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, httpError(bodyBytes, resp.StatusCode, "list recipes")
	}
	out := &pb.ListRecipesResponse{}
	if err := protojson.Unmarshal(bodyBytes, out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return out.Recipes, nil
}

// GetRecipe fetches a single recipe definition via HTTP.
func (c *HTTPClient) GetRecipe(id string) (*pb.Recipe, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	path := fmt.Sprintf("/v1/recipes/%s", url.PathEscape(id))
	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("get recipe: %w", err)
	}
	defer drainClose(resp)

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, httpError(bodyBytes, resp.StatusCode, "get recipe")
	}
	out := &pb.GetRecipeResponse{}
	if err := protojson.Unmarshal(bodyBytes, out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return out.Recipe, nil
}

// DeployRecipe provisions a new dedicated container from a recipe via HTTP.
func (c *HTTPClient) DeployRecipe(recipeID, name, gpu, backendID, pool string, params map[string]string) (*pb.DeployRecipeResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute) // image + model pulls can take time
	defer cancel()

	path := fmt.Sprintf("/v1/recipes/%s/deploy", url.PathEscape(recipeID))
	body := map[string]interface{}{
		"recipe_id":  recipeID,
		"name":       name,
		"gpu":        gpu,
		"backend_id": backendID,
		"pool":       pool,
		"parameters": params,
	}
	resp, err := c.doRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, fmt.Errorf("deploy recipe: %w", err)
	}
	defer drainClose(resp)

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, httpError(bodyBytes, resp.StatusCode, "deploy recipe")
	}
	out := &pb.DeployRecipeResponse{}
	if err := protojson.Unmarshal(bodyBytes, out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return out, nil
}

// CreateBackup dumps a tenant's database and stores it off-host via HTTP.
func (c *HTTPClient) CreateBackup(req *pb.CreateBackupRequest) (*pb.CreateBackupResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	body, err := protojson.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}
	resp, err := c.doRequest(ctx, http.MethodPost, "/v1/backups", json.RawMessage(body))
	if err != nil {
		return nil, fmt.Errorf("create backup: %w", err)
	}
	defer drainClose(resp)

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, httpError(bodyBytes, resp.StatusCode, "create backup")
	}
	out := &pb.CreateBackupResponse{}
	if err := protojson.Unmarshal(bodyBytes, out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return out, nil
}

// ListBackups lists stored backups via HTTP.
func (c *HTTPClient) ListBackups(username string) ([]*pb.BackupRecord, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	path := "/v1/backups"
	if username != "" {
		path += "?username=" + url.QueryEscape(username)
	}
	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("list backups: %w", err)
	}
	defer drainClose(resp)

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, httpError(bodyBytes, resp.StatusCode, "list backups")
	}
	out := &pb.ListBackupsResponse{}
	if err := protojson.Unmarshal(bodyBytes, out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return out.Records, nil
}

// GetBackup fetches a single backup record via HTTP.
func (c *HTTPClient) GetBackup(id string) (*pb.BackupRecord, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	path := fmt.Sprintf("/v1/backups/%s", url.PathEscape(id))
	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("get backup: %w", err)
	}
	defer drainClose(resp)

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, httpError(bodyBytes, resp.StatusCode, "get backup")
	}
	out := &pb.GetBackupResponse{}
	if err := protojson.Unmarshal(bodyBytes, out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return out.Record, nil
}

// RestoreBackup restores a stored dump via HTTP.
func (c *HTTPClient) RestoreBackup(req *pb.RestoreBackupRequest) (*pb.RestoreBackupResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	body, err := protojson.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}
	path := fmt.Sprintf("/v1/backups/%s/restore", url.PathEscape(req.Id))
	resp, err := c.doRequest(ctx, http.MethodPost, path, json.RawMessage(body))
	if err != nil {
		return nil, fmt.Errorf("restore backup: %w", err)
	}
	defer drainClose(resp)

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, httpError(bodyBytes, resp.StatusCode, "restore backup")
	}
	out := &pb.RestoreBackupResponse{}
	if err := protojson.Unmarshal(bodyBytes, out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return out, nil
}

// DeleteBackup removes a stored dump and its index entry via HTTP.
func (c *HTTPClient) DeleteBackup(id string) (*pb.DeleteBackupResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	path := fmt.Sprintf("/v1/backups/%s", url.PathEscape(id))
	resp, err := c.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, fmt.Errorf("delete backup: %w", err)
	}
	defer drainClose(resp)

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, httpError(bodyBytes, resp.StatusCode, "delete backup")
	}
	out := &pb.DeleteBackupResponse{}
	if err := protojson.Unmarshal(bodyBytes, out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return out, nil
}

// GetKMSStatus reports the active KMS backend + envelope state via HTTP.
func (c *HTTPClient) GetKMSStatus() (*pb.GetKMSStatusResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := c.doRequest(ctx, http.MethodGet, "/v1/kms/status", nil)
	if err != nil {
		return nil, fmt.Errorf("get kms status: %w", err)
	}
	defer drainClose(resp)

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, httpError(bodyBytes, resp.StatusCode, "get kms status")
	}
	out := &pb.GetKMSStatusResponse{}
	if err := protojson.Unmarshal(bodyBytes, out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return out, nil
}

// GetEnvelopeCoverage reports secret counts by encryption mode via HTTP.
func (c *HTTPClient) GetEnvelopeCoverage() (*pb.GetEnvelopeCoverageResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := c.doRequest(ctx, http.MethodGet, "/v1/kms/envelope-coverage", nil)
	if err != nil {
		return nil, fmt.Errorf("get envelope coverage: %w", err)
	}
	defer drainClose(resp)

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, httpError(bodyBytes, resp.StatusCode, "get envelope coverage")
	}
	out := &pb.GetEnvelopeCoverageResponse{}
	if err := protojson.Unmarshal(bodyBytes, out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return out, nil
}

// MigrateToEnvelope triggers the legacy→envelope re-wrap via HTTP.
func (c *HTTPClient) MigrateToEnvelope(req *pb.MigrateToEnvelopeRequest) (*pb.MigrateToEnvelopeResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	body, err := protojson.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}
	resp, err := c.doRequest(ctx, http.MethodPost, "/v1/kms/migrate-to-envelope", json.RawMessage(body))
	if err != nil {
		return nil, fmt.Errorf("migrate to envelope: %w", err)
	}
	defer drainClose(resp)

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, httpError(bodyBytes, resp.StatusCode, "migrate to envelope")
	}
	out := &pb.MigrateToEnvelopeResponse{}
	if err := protojson.Unmarshal(bodyBytes, out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return out, nil
}

// httpError extracts a JSON {"error": ...} message from a gateway error body,
// falling back to the status code.
func httpError(bodyBytes []byte, statusCode int, op string) error {
	var errResp struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(bodyBytes, &errResp) == nil && errResp.Error != "" {
		return fmt.Errorf("%s", errResp.Error)
	}
	return fmt.Errorf("%s: status %d", op, statusCode)
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
	defer drainClose(resp)

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
	defer drainClose(resp)

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
