package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Client is a REST API client for Containarium. Carries a small amount
// of non-HTTP deployment metadata (SentinelHost) so tool handlers that
// need it can read it without a separate config plumbing layer.
type Client struct {
	baseURL string

	// jwtToken is the static token used when jwtTokenFile is empty.
	// Captured at NewClient time; doesn't survive operator-side
	// rotation without an MCP restart.
	jwtToken string

	// jwtTokenFile, when set, is the path the client reads the JWT
	// from on every request. Operators rotating the token can just
	// overwrite the file in place — the next call picks up the new
	// content. Empty falls back to jwtToken.
	jwtTokenFile string

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

// SetTokenFile switches the client to file-based token mode: every
// request re-reads `path` to get the current JWT. Empty disables
// file mode and falls back to the static jwtToken captured at
// NewClient time. Used by the MCP server when the operator set
// CONTAINARIUM_JWT_TOKEN_FILE.
func (c *Client) SetTokenFile(path string) {
	c.jwtTokenFile = path
}

// readToken returns the JWT to use for the next request. When a
// tokenFile is configured, reads it fresh from disk (whitespace
// trimmed) on every call so token rotation works without a restart.
// Otherwise returns the static token captured at construction.
func (c *Client) readToken() (string, error) {
	if c.jwtTokenFile == "" {
		return c.jwtToken, nil
	}
	b, err := os.ReadFile(c.jwtTokenFile)
	if err != nil {
		return "", fmt.Errorf("read JWT from %s: %w", c.jwtTokenFile, err)
	}
	token := strings.TrimSpace(string(b))
	if token == "" {
		return "", fmt.Errorf("JWT file %s is empty", c.jwtTokenFile)
	}
	return token, nil
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

	// Add JWT token. readToken() may re-read from disk if a token file
	// was configured — that's the file-rotation-without-restart path.
	token, err := c.readToken()
	if err != nil {
		return nil, fmt.Errorf("authenticate: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
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

// ToggleMonitoring enables / disables OTel app telemetry on an
// existing container. Returns the response with message +
// monitoring_enabled state.
func (c *Client) ToggleMonitoring(username string, enabled bool) (*ToggleMonitoringResponse, error) {
	body, err := json.Marshal(map[string]bool{"enabled": enabled})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	respBody, err := c.doRequest("POST", fmt.Sprintf("/v1/containers/%s/monitoring", username), body)
	if err != nil {
		return nil, err
	}
	var resp ToggleMonitoringResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	return &resp, nil
}

// ResizeContainer changes a container's CPU / memory / disk
// allocation. Empty string for any field means "no change"; disk
// can only grow (server rejects shrinks).
func (c *Client) ResizeContainer(username, cpu, memory, disk string) (*ResizeContainerResponse, error) {
	body, err := json.Marshal(map[string]string{
		"cpu":    cpu,
		"memory": memory,
		"disk":   disk,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	respBody, err := c.doRequest("PUT", fmt.Sprintf("/v1/containers/%s/resize", username), body)
	if err != nil {
		return nil, err
	}
	var resp ResizeContainerResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	return &resp, nil
}

// SetSecret creates or updates a tenant secret. Idempotent —
// repeated calls with the same (username, name) bump the version.
func (c *Client) SetSecret(username, name, value string) (*SecretResponse, error) {
	body, err := json.Marshal(map[string]string{
		"username": username, "name": name, "value": value,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	respBody, err := c.doRequest("POST", "/v1/secrets", body)
	if err != nil {
		return nil, err
	}
	var resp SecretResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return &resp, nil
}

// GetSecret reads a single secret's plaintext value.
func (c *Client) GetSecret(username, name string) (string, error) {
	respBody, err := c.doRequest("GET", fmt.Sprintf("/v1/secrets/%s/%s", username, name), nil)
	if err != nil {
		return "", err
	}
	var resp struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return "", fmt.Errorf("decode: %w", err)
	}
	return resp.Value, nil
}

// ListSecrets returns metadata for every tenant secret.
func (c *Client) ListSecrets(username string) ([]map[string]interface{}, error) {
	respBody, err := c.doRequest("GET", fmt.Sprintf("/v1/secrets/%s", username), nil)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Secrets []map[string]interface{} `json:"secrets"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return resp.Secrets, nil
}

// DeleteSecret removes a tenant secret.
func (c *Client) DeleteSecret(username, name string) error {
	if _, err := c.doRequest("DELETE", fmt.Sprintf("/v1/secrets/%s/%s", username, name), nil); err != nil {
		return err
	}
	return nil
}

// RefreshSecrets re-stamps env vars on the LXC.
func (c *Client) RefreshSecrets(username string) (*RefreshSecretsResponse, error) {
	respBody, err := c.doRequest("POST", fmt.Sprintf("/v1/secrets/%s/refresh", username), []byte("{}"))
	if err != nil {
		return nil, err
	}
	var resp RefreshSecretsResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
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

// ListRoutes returns all proxy routes the sentinel currently serves. Both
// filter params are optional — empty `username` or `activeOnly=false`
// means "no filter on that dimension". Mirrors GET /v1/network/routes.
func (c *Client) ListRoutes(username string, activeOnly bool) (*ListRoutesResponse, error) {
	path := "/v1/network/routes"
	q := ""
	if username != "" {
		q = "username=" + username
	}
	if activeOnly {
		if q != "" {
			q += "&"
		}
		q += "activeOnly=true"
	}
	if q != "" {
		path += "?" + q
	}
	respBody, err := c.doRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}
	var resp ListRoutesResponse
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

// TriggerSecurityScan posts to the daemon's scan-trigger endpoints. For
// kind="all" it runs the three trigger endpoints sequentially and rolls
// up the queued counts. Errors from individual triggers are collected
// but don't abort the others — a partial scan is better than none.
func (c *Client) TriggerSecurityScan(kind, containerName, username string) (*SecurityScanResponse, error) {
	kinds := []string{kind}
	if kind == scanKindAll {
		kinds = []string{scanKindClamav, scanKindPentest, scanKindZap}
	}

	type triggerOk struct {
		Message      string `json:"message"`
		ScannedCount int    `json:"scannedCount"`
	}

	var msgs []string
	var totalQueued int
	for _, k := range kinds {
		var path string
		var body interface{}
		switch k {
		case scanKindClamav:
			path = "/v1/security/clamav-scan"
			body = map[string]string{"containerName": containerName}
		case scanKindPentest:
			// TriggerPentestScanRequest carries containerName as an
			// optional scope. Empty would trigger a cluster-wide scan;
			// the MCP tool requires `username` so we always pass the
			// container through here.
			path = "/v1/pentest/scan"
			body = map[string]string{"containerName": containerName}
		case scanKindZap:
			// Same shape as pentest — containerName scopes the scan.
			path = "/v1/zap/scan"
			body = map[string]string{"containerName": containerName}
		}
		respBody, err := c.doRequest("POST", path, body)
		if err != nil {
			msgs = append(msgs, fmt.Sprintf("%s: error: %v", k, err))
			continue
		}
		var resp triggerOk
		_ = json.Unmarshal(respBody, &resp)
		if resp.Message != "" {
			msgs = append(msgs, fmt.Sprintf("%s: %s", k, resp.Message))
		} else {
			msgs = append(msgs, fmt.Sprintf("%s: triggered", k))
		}
		totalQueued += resp.ScannedCount
		if resp.ScannedCount == 0 {
			totalQueued++ // some triggers don't return a count
		}
	}

	poll := "Call security_findings in ~30s for ClamAV/pentest; ZAP runs minutes."
	if kind == scanKindClamav {
		poll = "ClamAV is fast — call security_findings in ~5s."
	}
	if kind == scanKindZap {
		poll = "ZAP can take 1-5 minutes. Call security_findings periodically."
	}
	return &SecurityScanResponse{
		Kind:     kind,
		Message:  strings.Join(msgs, "; "),
		Queued:   totalQueued,
		PollHint: poll,
	}, nil
}

// ListSecurityFindings fetches findings from one or all scanner kinds and
// normalizes them into the unified SecurityFinding shape.
func (c *Client) ListSecurityFindings(kind, containerName string) ([]SecurityFinding, error) {
	kinds := []string{kind}
	if kind == scanKindAll {
		kinds = []string{scanKindClamav, scanKindPentest, scanKindZap}
	}

	var out []SecurityFinding
	for _, k := range kinds {
		rows, err := c.listOneScanner(k, containerName)
		if err != nil {
			// Per-scanner failures shouldn't abort the others — surface
			// them as a synthetic "info" row so the agent sees why.
			out = append(out, SecurityFinding{
				Kind:        k,
				Severity:    "info",
				Title:       fmt.Sprintf("scanner %s unreachable", k),
				Description: err.Error(),
			})
			continue
		}
		out = append(out, rows...)
	}
	return out, nil
}

// listOneScanner pulls + normalizes findings from one scanner.
func (c *Client) listOneScanner(kind, containerName string) ([]SecurityFinding, error) {
	switch kind {
	case scanKindClamav:
		path := "/v1/security/clamav-reports?containerName=" + containerName
		body, err := c.doRequest("GET", path, nil)
		if err != nil {
			return nil, err
		}
		var resp struct {
			Reports []struct {
				// grpc-gateway emits int64 as a JSON string — see the
				// pentest comment below for why this matters.
				ID            int64  `json:"id,string"`
				ContainerName string `json:"containerName"`
				Status        string `json:"status"`
				FindingsCount int    `json:"findingsCount"`
				Findings      string `json:"findings"`
			} `json:"reports"`
		}
		_ = json.Unmarshal(body, &resp)
		var out []SecurityFinding
		for _, r := range resp.Reports {
			if r.Status != "infected" || r.FindingsCount == 0 {
				continue
			}
			out = append(out, SecurityFinding{
				Kind:          scanKindClamav,
				ID:            r.ID,
				Severity:      "critical", // infected = critical by default
				Title:         fmt.Sprintf("ClamAV found %d infected file(s)", r.FindingsCount),
				Description:   r.Findings,
				ContainerName: r.ContainerName,
				FixAvailable:  false, // ClamAV findings require quarantine workflow, not auto-fix
			})
		}
		return out, nil

	case scanKindPentest:
		// The pentest proto has no container_name filter, so we pull
		// all findings and filter client-side on the target prefix.
		// Sending ?containerName= would just be ignored by grpc-gateway.
		body, err := c.doRequest("GET", "/v1/pentest/findings", nil)
		if err != nil {
			return nil, err
		}
		var resp struct {
			Findings []struct {
				// grpc-gateway emits proto int64 as a JSON string per
				// protojson spec — without `,string` this silently
				// decodes to 0, which breaks RemediatePentestFinding.
				ID          int64  `json:"id,string"`
				Category    string `json:"category"`
				Severity    string `json:"severity"`
				Title       string `json:"title"`
				Description string `json:"description"`
				Target      string `json:"target"`
				Suppressed  bool   `json:"suppressed"`
			} `json:"findings"`
		}
		_ = json.Unmarshal(body, &resp)
		var out []SecurityFinding
		for _, f := range resp.Findings {
			if f.Suppressed {
				continue
			}
			// Trivy findings encode container in their target as
			// "<container> (path/to/binary)". Domain-level findings
			// (SPF, missing CSP, etc.) don't belong to any container,
			// so they're intentionally absent from per-container queries.
			if !strings.HasPrefix(f.Target, containerName+" ") {
				continue
			}
			out = append(out, SecurityFinding{
				Kind:        scanKindPentest,
				ID:          f.ID,
				Severity:    f.Severity,
				Title:       f.Title,
				Description: f.Description,
				Target:      f.Target,
				// Only trivy findings have an auto-fix path —
				// RemediatePentestFinding refuses other categories.
				FixAvailable: f.Category == "trivy",
			})
		}
		return out, nil

	case scanKindZap:
		// ZAP proto has no container_name filter either; same
		// client-side filter pattern as pentest. We match alerts whose
		// URL contains the container name as a hostname-ish prefix —
		// ZAP scans by URL, so the linkage to a container is via the
		// hostname the scan was pointed at.
		body, err := c.doRequest("GET", "/v1/zap/alerts", nil)
		if err != nil {
			return nil, err
		}
		var resp struct {
			Alerts []struct {
				// See the pentest comment on `,string` — int64 over
				// protojson arrives as a JSON string.
				ID          int64  `json:"id,string"`
				AlertName   string `json:"alertName"`
				Risk        string `json:"risk"`
				Description string `json:"description"`
				URL         string `json:"url"`
				Suppressed  bool   `json:"suppressed"`
			} `json:"alerts"`
		}
		_ = json.Unmarshal(body, &resp)
		var out []SecurityFinding
		for _, a := range resp.Alerts {
			if a.Suppressed {
				continue
			}
			if !strings.Contains(a.URL, containerName) {
				continue
			}
			out = append(out, SecurityFinding{
				Kind:         scanKindZap,
				ID:           a.ID,
				Severity:     normalizeZapRisk(a.Risk),
				Title:        a.AlertName,
				Description:  a.Description,
				Target:       a.URL,
				FixAvailable: false, // ZAP findings need web-app code fixes; no auto-remediation today
			})
		}
		return out, nil
	}
	return nil, fmt.Errorf("unknown kind: %s", kind)
}

// normalizeZapRisk maps ZAP's "high|medium|low|informational" onto our
// shared severity set.
func normalizeZapRisk(r string) string {
	switch strings.ToLower(r) {
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	case "informational", "info":
		return "info"
	}
	return "info"
}

// RemediateSecurityFinding calls the daemon's RemediatePentestFinding
// RPC. Only valid for pentest findings; ClamAV/ZAP findings are
// rejected with FixAvailable=false at security_findings time.
func (c *Client) RemediateSecurityFinding(findingID int64) (*SecurityRemediateResponse, error) {
	path := fmt.Sprintf("/v1/pentest/findings/%d/remediate", findingID)
	body, err := c.doRequest("POST", path, struct{}{})
	if err != nil {
		return nil, err
	}
	var resp SecurityRemediateResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse remediate response: %w", err)
	}
	return &resp, nil
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

	// Monitoring opts the container into application-emitted
	// OpenTelemetry. When true, the daemon stamps the LXC with
	// OTEL_EXPORTER_OTLP_ENDPOINT etc., pointing at the core
	// collector. Default false (opt-in). See
	// docs/OTEL-COLLECTOR-DESIGN.md for the full design.
	Monitoring bool `json:"monitoring,omitempty"`

	// Pool selects placement by pool tag. When set with an empty
	// BackendID, the daemon picks any healthy backend in the pool.
	// When set with BackendID, the daemon validates that BackendID
	// belongs to this pool.
	Pool string `json:"pool,omitempty"`

	// BackendID pins the container to a specific peer. Use Pool
	// when any backend in a group will do; use BackendID for an
	// exact placement.
	BackendID string `json:"backendId,omitempty"`
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

type ToggleMonitoringResponse struct {
	Message           string `json:"message"`
	MonitoringEnabled bool   `json:"monitoring_enabled"`
}

type ResizeContainerResponse struct {
	Message   string    `json:"message"`
	Container Container `json:"container"`
}

type SecretResponse struct {
	Message string                 `json:"message"`
	Secret  map[string]interface{} `json:"secret"`
}

type RefreshSecretsResponse struct {
	Message string `json:"message"`
	Stamped int32  `json:"stamped"`
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
	// Domain (the one expose_port sets) and the proto's richer fields
	// (subdomain, fullDomain, active, appId, appName) — accept both shapes
	// because AddRoute echoes one set and GetRoutes returns the other.
	Domain        string `json:"domain,omitempty"`
	Subdomain     string `json:"subdomain,omitempty"`
	FullDomain    string `json:"fullDomain,omitempty"`
	ContainerIP   string `json:"containerIp"`
	Port          int32  `json:"port"`
	Active        bool   `json:"active,omitempty"`
	ContainerName string `json:"containerName,omitempty"`
	Description   string `json:"description,omitempty"`
	AppID         string `json:"appId,omitempty"`
	AppName       string `json:"appName,omitempty"`
}

// ListRoutesResponse mirrors the daemon's GetRoutesResponse.
type ListRoutesResponse struct {
	Routes     []ProxyRoute `json:"routes"`
	TotalCount int          `json:"totalCount"`
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
	BackendID     string            `json:"backendId,omitempty"`
	Pool          string            `json:"pool,omitempty"`
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
