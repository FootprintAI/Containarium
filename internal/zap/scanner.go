package zap

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	// zapAPIPort is the port ZAP daemon listens on for its REST API
	zapAPIPort = 8090
)

// Scanner wraps the ZAP daemon running inside the security container
type Scanner struct {
	apiBase    string // set after discovering the container IP
	httpClient *http.Client
}

// NewScanner creates a new ZAP scanner
func NewScanner() *Scanner {
	return &Scanner{
		httpClient: &http.Client{
			Timeout: 120 * time.Second,
		},
	}
}

// Available returns whether ZAP is installed in the security container
func (s *Scanner) Available() bool {
	installer := NewInstaller()
	return installer.IsInstalled()
}

// Version returns the ZAP version string
func (s *Scanner) Version() string {
	if s.apiBase == "" {
		return ""
	}
	resp, err := s.apiGet("/JSON/core/view/version/")
	if err != nil {
		return ""
	}
	if v, ok := resp["version"].(string); ok {
		return v
	}
	return ""
}

// getContainerIP returns the IP of the security container
func getContainerIP() (string, error) {
	cmd := exec.Command("incus", "list", SecurityContainerName, "--format=csv", "-c4")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get security container IP: %w", err)
	}
	// Output format: "10.0.3.8 (eth0)"
	ip := strings.TrimSpace(string(out))
	if idx := strings.Index(ip, " "); idx > 0 {
		ip = ip[:idx]
	}
	if ip == "" {
		return "", fmt.Errorf("security container has no IP address")
	}
	return ip, nil
}

// EnsureDaemonRunning starts the ZAP daemon in the security container if it's not already running
func (s *Scanner) EnsureDaemonRunning(ctx context.Context) error {
	// Get container IP
	ip, err := getContainerIP()
	if err != nil {
		return err
	}
	s.apiBase = fmt.Sprintf("http://%s:%d", ip, zapAPIPort)

	// Check if already running
	if s.isRunning() {
		return nil
	}

	log.Printf("ZAP: Starting daemon in security container on port %d", zapAPIPort)

	// Clean stale lock files from any previous crashed ZAP instance
	cleanCmd := exec.CommandContext(ctx, "incus", "exec", SecurityContainerName, "--",
		"bash", "-c", "rm -f /root/.ZAP/.homelock /root/.ZAP/session/*.lck /root/.ZAP/db/*.lck 2>/dev/null; pkill -f zap-2 2>/dev/null; true")
	cleanCmd.CombinedOutput() // ignore errors

	// Start ZAP daemon inside the security container (background)
	// -host 0.0.0.0 makes ZAP listen on all interfaces so the host can reach it
	cmd := exec.CommandContext(ctx, "incus", "exec", SecurityContainerName, "--",
		"bash", "-c", fmt.Sprintf(
			"nohup %s/ZAP/zap.sh -daemon -host 0.0.0.0 -port %d -config api.disablekey=true -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true > /var/log/zap.log 2>&1 &",
			zapInstallDir, zapAPIPort,
		))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to start ZAP daemon: %w (%s)", err, string(out))
	}

	// Wait for ZAP to be ready (up to 120 seconds — ZAP is slow to start)
	for i := 0; i < 120; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
		if s.isRunning() {
			log.Printf("ZAP: Daemon ready at %s", s.apiBase)
			return nil
		}
	}

	return fmt.Errorf("ZAP daemon did not become ready within 120 seconds")
}

// isRunning checks if ZAP daemon is responding
func (s *Scanner) isRunning() bool {
	if s.apiBase == "" {
		return false
	}
	_, err := s.apiGet("/JSON/core/view/version/")
	return err == nil
}

// ScanURL performs a full spider + active scan on a URL and returns alerts
func (s *Scanner) ScanURL(ctx context.Context, targetURL string) ([]Alert, error) {
	// Step 1: Spider the URL to discover pages
	log.Printf("ZAP: Spidering %s", targetURL)
	spiderScanID, err := s.startSpider(targetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to start spider: %w", err)
	}

	if err := s.waitForSpider(ctx, spiderScanID); err != nil {
		return nil, fmt.Errorf("spider failed: %w", err)
	}
	log.Printf("ZAP: Spider completed for %s", targetURL)

	// Step 2: Active scan the URL
	log.Printf("ZAP: Active scanning %s", targetURL)
	activeScanID, err := s.startActiveScan(targetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to start active scan: %w", err)
	}

	if err := s.waitForActiveScan(ctx, activeScanID); err != nil {
		return nil, fmt.Errorf("active scan failed: %w", err)
	}
	log.Printf("ZAP: Active scan completed for %s", targetURL)

	// Step 3: Collect alerts for this URL
	return s.getAlerts(targetURL)
}

// GenerateHTMLReport generates an HTML report from ZAP
func (s *Scanner) GenerateHTMLReport() (string, error) {
	resp, err := s.apiGetRaw("/OTHER/core/other/htmlreport/")
	if err != nil {
		return "", fmt.Errorf("failed to generate HTML report: %w", err)
	}
	return resp, nil
}

// GenerateJSONReport generates a JSON report from ZAP
func (s *Scanner) GenerateJSONReport() (string, error) {
	resp, err := s.apiGetRaw("/OTHER/core/other/jsonreport/")
	if err != nil {
		return "", fmt.Errorf("failed to generate JSON report: %w", err)
	}
	return resp, nil
}

// startSpider initiates a ZAP spider scan
func (s *Scanner) startSpider(url string) (string, error) {
	resp, err := s.apiGet(fmt.Sprintf("/JSON/spider/action/scan/?url=%s&maxChildren=10&recurse=true&subtreeOnly=true", url))
	if err != nil {
		return "", err
	}
	scanID, ok := resp["scan"].(string)
	if !ok {
		if num, ok := resp["scan"].(float64); ok {
			scanID = strconv.Itoa(int(num))
		} else {
			return "", fmt.Errorf("unexpected spider response: %v", resp)
		}
	}
	return scanID, nil
}

// waitForSpider waits for a spider scan to complete
func (s *Scanner) waitForSpider(ctx context.Context, scanID string) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}

		resp, err := s.apiGet(fmt.Sprintf("/JSON/spider/view/status/?scanId=%s", scanID))
		if err != nil {
			return err
		}
		statusStr, _ := resp["status"].(string)
		status, _ := strconv.Atoi(statusStr)
		if status >= 100 {
			return nil
		}
	}
}

// startActiveScan initiates a ZAP active scan
func (s *Scanner) startActiveScan(url string) (string, error) {
	resp, err := s.apiGet(fmt.Sprintf("/JSON/ascan/action/scan/?url=%s&recurse=true&inScopeOnly=false", url))
	if err != nil {
		return "", err
	}
	scanID, ok := resp["scan"].(string)
	if !ok {
		if num, ok := resp["scan"].(float64); ok {
			scanID = strconv.Itoa(int(num))
		} else {
			return "", fmt.Errorf("unexpected active scan response: %v", resp)
		}
	}
	return scanID, nil
}

// waitForActiveScan waits for an active scan to complete
func (s *Scanner) waitForActiveScan(ctx context.Context, scanID string) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}

		resp, err := s.apiGet(fmt.Sprintf("/JSON/ascan/view/status/?scanId=%s", scanID))
		if err != nil {
			return err
		}
		statusStr, _ := resp["status"].(string)
		status, _ := strconv.Atoi(statusStr)
		if status >= 100 {
			return nil
		}
	}
}

// zapAlertJSON represents a ZAP alert from the API
type zapAlertJSON struct {
	PluginID    string `json:"pluginId"`
	Alert       string `json:"alert"`
	Risk        string `json:"risk"`       // "High", "Medium", "Low", "Informational"
	Confidence  string `json:"confidence"` // "High", "Medium", "Low", "False Positive"
	Description string `json:"description"`
	URL         string `json:"url"`
	Method      string `json:"method"`
	Evidence    string `json:"evidence"`
	Solution    string `json:"solution"`
	Reference   string `json:"reference"`
	CWEId       string `json:"cweid"`
	WASCId      string `json:"wascid"`
}

// getAlerts retrieves all alerts for a URL from ZAP's API
func (s *Scanner) getAlerts(baseURL string) ([]Alert, error) {
	resp, err := s.apiGetRaw(fmt.Sprintf("/JSON/core/view/alerts/?baseurl=%s&start=0&count=500", baseURL))
	if err != nil {
		return nil, err
	}

	var result struct {
		Alerts []zapAlertJSON `json:"alerts"`
	}
	if err := json.Unmarshal([]byte(resp), &result); err != nil {
		return nil, fmt.Errorf("failed to parse ZAP alerts: %w", err)
	}

	var alerts []Alert
	for _, za := range result.Alerts {
		risk := strings.ToLower(za.Risk)
		if risk == "" {
			risk = "informational"
		}

		fp := AlertFingerprint(za.PluginID, za.URL, za.Alert)

		cweIDs := ""
		if za.CWEId != "" && za.CWEId != "0" {
			cweIDs = "CWE-" + za.CWEId
		}

		alerts = append(alerts, Alert{
			Fingerprint: fp,
			PluginID:    za.PluginID,
			AlertName:   za.Alert,
			Risk:        risk,
			Confidence:  strings.ToLower(za.Confidence),
			Description: za.Description,
			URL:         za.URL,
			Method:      za.Method,
			Evidence:    za.Evidence,
			Solution:    za.Solution,
			CWEIDs:      cweIDs,
			References:  za.Reference,
		})
	}

	return alerts, nil
}

// apiGet makes a GET request to ZAP's REST API and returns parsed JSON
func (s *Scanner) apiGet(path string) (map[string]interface{}, error) {
	raw, err := s.apiGetRaw(path)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, fmt.Errorf("failed to parse ZAP API response: %w", err)
	}
	return result, nil
}

// apiGetRaw makes a GET request to ZAP's REST API and returns the raw body
func (s *Scanner) apiGetRaw(path string) (string, error) {
	if s.apiBase == "" {
		return "", fmt.Errorf("ZAP API base URL not set — daemon not running")
	}

	resp, err := s.httpClient.Get(s.apiBase + path)
	if err != nil {
		return "", fmt.Errorf("ZAP API request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read ZAP API response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ZAP API returned status %d: %s", resp.StatusCode, string(body))
	}

	return string(body), nil
}

// AlertFingerprint generates a SHA-256 fingerprint for deduplication
func AlertFingerprint(pluginID, url, alert string) string {
	data := fmt.Sprintf("%s|%s|%s", pluginID, url, alert)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)
}
