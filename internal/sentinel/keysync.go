package sentinel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/footprintai/containarium/internal/gateway"
	"github.com/footprintai/containarium/internal/sentinel/wakeproxy"
)

const (
	sshpiperConfigDir   = "/etc/sshpiper"
	sshpiperUpstreamKey = "/etc/sshpiper/upstream_key"

	// wake-on-SSH (#539): sshpiper routes each user's upstream through
	// the local ssh-wake-proxy at 127.0.0.1:<wakePort> instead of the
	// box directly; the proxy reads wakeRoutesFile to know where to wake
	// + splice. Ports are assigned deterministically from the sorted
	// user list as wakeProxyBasePort+index, so the config stays
	// byte-stable across reruns with the same user set.
	wakeProxyHost     = "127.0.0.1"
	wakeProxyBasePort = 40000
)

// File paths Apply writes. Vars (not const) so tests can redirect them
// to a temp dir; production values are the /etc/sshpiper defaults.
var (
	sshpiperConfigFile = "/etc/sshpiper/config.yaml"
	sshpiperUsersDir   = "/etc/sshpiper/users"
	wakeRoutesFile     = "/etc/sshpiper/wake-routes.json"
)

// backendKeys holds the users fetched from a single backend.
type backendKeys struct {
	backendID string
	backendIP string
	httpPort  int // daemon HTTP port — used by wake-on-SSH (#539) to reach /ssh-wake
	users     []gateway.UserKeys
	lastSync  time.Time
	lastErr   error
}

// KeyStore syncs SSH authorized keys from one or more backends and generates
// sshpiper YAML configuration with per-user routing to the correct backend.
type KeyStore struct {
	mu            sync.RWMutex
	backends      map[string]*backendKeys // keyed by backend ID
	configChanged bool
}

// NewKeyStore creates a new KeyStore.
func NewKeyStore() *KeyStore {
	return &KeyStore{
		backends: make(map[string]*backendKeys),
	}
}

// Sync fetches authorized keys from a backend's /authorized-keys endpoint.
// Each backend's users are tracked separately for per-user routing.
func (ks *KeyStore) Sync(backendID, backendIP string, httpPort int) error {
	url := fmt.Sprintf("http://%s:%d/authorized-keys", backendIP, httpPort)

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := newSignedRequest(http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("key sync: build request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		ks.mu.Lock()
		ks.ensureBackendLocked(backendID, backendIP).lastErr = err
		ks.mu.Unlock()
		return fmt.Errorf("key sync GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("key sync: unexpected status %d from %s", resp.StatusCode, url)
		ks.mu.Lock()
		ks.ensureBackendLocked(backendID, backendIP).lastErr = err
		ks.mu.Unlock()
		return err
	}

	var keysResp gateway.KeysResponse
	if err := json.NewDecoder(resp.Body).Decode(&keysResp); err != nil {
		ks.mu.Lock()
		ks.ensureBackendLocked(backendID, backendIP).lastErr = err
		ks.mu.Unlock()
		return fmt.Errorf("key sync: decode response: %w", err)
	}

	ks.mu.Lock()
	bk := ks.ensureBackendLocked(backendID, backendIP)
	bk.httpPort = httpPort
	bk.users = keysResp.Keys
	bk.lastSync = time.Now()
	bk.lastErr = nil
	ks.mu.Unlock()

	return nil
}

// SyncLegacy is the backward-compatible Sync that uses a default backend ID.
// Used in single-backend mode.
func (ks *KeyStore) SyncLegacy(backendIP string, httpPort int) error {
	return ks.Sync("default", backendIP, httpPort)
}

// RemoveBackend removes all user data for a backend.
func (ks *KeyStore) RemoveBackend(backendID string) {
	ks.mu.Lock()
	delete(ks.backends, backendID)
	ks.mu.Unlock()
}

// Apply writes the sshpiper YAML config with per-user routing.
// Each user is routed to the backend they were synced from.
// If the same username appears on multiple backends, GCP takes priority
// (lower backend priority value wins).
func (ks *KeyStore) Apply() error {
	ks.mu.RLock()
	// Build a merged user list with per-user backend IP routing
	type userRoute struct {
		username       string
		authorizedKeys string
		backendIP      string
		httpPort       int
	}
	seen := make(map[string]bool)
	var routes []userRoute

	// Collect from all backends — sort backend IDs for deterministic iteration
	// so the generated config is byte-stable and we can skip the rewrite when
	// nothing actually changed.
	backendIDs := make([]string, 0, len(ks.backends))
	for id := range ks.backends {
		backendIDs = append(backendIDs, id)
	}
	sort.Strings(backendIDs)
	for _, id := range backendIDs {
		bk := ks.backends[id]
		for _, u := range bk.users {
			if seen[u.Username] {
				continue // first backend to claim a user wins
			}
			seen[u.Username] = true
			routes = append(routes, userRoute{
				username:       u.Username,
				authorizedKeys: u.AuthorizedKeys,
				backendIP:      bk.backendIP,
				httpPort:       bk.httpPort,
			})
		}
	}
	ks.mu.RUnlock()

	// Sort routes by username for deterministic config output
	sort.Slice(routes, func(i, j int) bool {
		return routes[i].username < routes[j].username
	})

	if len(routes) == 0 {
		return fmt.Errorf("no users to configure")
	}

	// Ensure directories exist
	if err := os.MkdirAll(sshpiperUsersDir, 0755); err != nil { // #nosec G301 -- sshpiper needs world-readable dirs for authorized_keys lookup
		return fmt.Errorf("failed to create sshpiper users dir: %w", err)
	}

	// Write per-user authorized_keys
	for _, r := range routes {
		userDir := filepath.Join(sshpiperUsersDir, r.username)
		if err := os.MkdirAll(userDir, 0755); err != nil { // #nosec G301 -- sshpiper requires world-readable user dirs
			log.Printf("[keysync] failed to create dir for %s: %v", r.username, err)
			continue
		}
		akPath := filepath.Join(userDir, "authorized_keys")
		// Strip blank lines and comment lines before writing — sshpiper's
		// authorized_keys parser may stop at a blank line, causing key match failures.
		cleanedKeys := cleanAuthorizedKeys(r.authorizedKeys)
		if err := os.WriteFile(akPath, []byte(cleanedKeys+"\n"), 0600); err != nil {
			log.Printf("[keysync] failed to write authorized_keys for %s: %v", r.username, err)
			continue
		}
	}

	// Generate sshpiper YAML config. Each user's upstream is routed
	// through the local ssh-wake-proxy at 127.0.0.1:<wakePort> instead
	// of the box directly, so an SSH connection to a slept box wakes it
	// first (#539, wake-on-SSH). The proxy reads wakeRoutesFile to learn
	// the real box address + how to reach the daemon's /ssh-wake.
	var buf bytes.Buffer
	buf.WriteString("version: \"1.0\"\npipes:\n")

	wakeRoutes := make([]wakeproxy.Route, 0, len(routes))
	for i, r := range routes {
		// Tunnel backends use loopback aliases (127.0.0.x where x >= 10) with
		// SSH on port 20022 to avoid conflicting with sshpiper's *:22 listener.
		// Direct backends (e.g., 10.x.x.x) use the standard port 22.
		sshPort := 22
		if isTunnelLoopback(r.backendIP) {
			sshPort = 20022
		}
		// Deterministic per-user wake port (sorted user order → stable
		// config across reruns with the same user set).
		wakePort := wakeProxyBasePort + i

		akPath := filepath.Join(sshpiperUsersDir, r.username, "authorized_keys")
		fmt.Fprintf(&buf, "  - from:\n")
		fmt.Fprintf(&buf, "      - username: %q\n", r.username)
		fmt.Fprintf(&buf, "        authorized_keys:\n")
		fmt.Fprintf(&buf, "          - %s\n", akPath)
		fmt.Fprintf(&buf, "    to:\n")
		fmt.Fprintf(&buf, "      host: %s:%d\n", wakeProxyHost, wakePort)
		fmt.Fprintf(&buf, "      username: %q\n", r.username)
		fmt.Fprintf(&buf, "      ignore_hostkey: true\n")
		fmt.Fprintf(&buf, "      private_key: %s\n", sshpiperUpstreamKey)

		wakeRoutes = append(wakeRoutes, wakeproxy.Route{
			Username:        r.username,
			WakePort:        wakePort,
			BackendIP:       r.backendIP,
			SSHPort:         sshPort,
			BackendHTTPPort: r.httpPort,
		})
	}

	newContent := buf.Bytes()
	wakeRoutesContent, err := json.MarshalIndent(wakeproxy.RouteFile{Routes: wakeRoutes}, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal wake routes: %w", err)
	}

	// The sshpiper config is the change trigger; the wake-routes file
	// derives from the same data, so we also reconcile it when it drifts
	// (e.g. missing on the first run after upgrade).
	oldContent, _ := os.ReadFile(sshpiperConfigFile)
	oldWake, _ := os.ReadFile(wakeRoutesFile)
	if bytes.Equal(oldContent, newContent) && bytes.Equal(oldWake, wakeRoutesContent) {
		ks.mu.Lock()
		ks.configChanged = false
		ks.mu.Unlock()
		return nil
	}

	if err := os.WriteFile(sshpiperConfigFile, newContent, 0600); err != nil {
		return fmt.Errorf("failed to write sshpiper config: %w", err)
	}
	if err := os.WriteFile(wakeRoutesFile, wakeRoutesContent, 0600); err != nil {
		return fmt.Errorf("failed to write wake routes: %w", err)
	}

	ks.mu.Lock()
	ks.configChanged = true
	ks.mu.Unlock()

	log.Printf("[keysync] sshpiper config updated: %d users across %d backends", len(routes), ks.backendCount())
	return nil
}

// PushSentinelKey sends the sentinel's upstream public key to a backend.
func (ks *KeyStore) PushSentinelKey(backendIP string, httpPort int) error {
	pubKeyPath := sshpiperUpstreamKey + ".pub"
	pubKey, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read sentinel upstream public key %s: %w", pubKeyPath, err)
	}

	url := fmt.Sprintf("http://%s:%d/authorized-keys/sentinel", backendIP, httpPort)
	body, _ := json.Marshal(gateway.SentinelKeyRequest{PublicKey: strings.TrimSpace(string(pubKey))})

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := newSignedRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("push sentinel key: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("push sentinel key POST %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("push sentinel key: unexpected status %d", resp.StatusCode)
	}

	log.Printf("[keysync] sentinel upstream key pushed to backend %s", backendIP)
	return nil
}

// RunSyncLoop periodically syncs keys from a specific backend.
// Blocks until ctx is cancelled.
func (ks *KeyStore) RunSyncLoop(ctx context.Context, backendID, backendIP string, httpPort int, interval time.Duration) {
	log.Printf("[keysync] starting sync loop for backend %s (%s:%d, interval=%s)", backendID, backendIP, httpPort, interval)

	ks.syncAndApply(backendID, backendIP, httpPort)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("[keysync] sync loop stopped for backend %s", backendID)
			return
		case <-ticker.C:
			ks.syncAndApply(backendID, backendIP, httpPort)
		}
	}
}

// RunSyncLoopLegacy is backward-compatible: uses "default" as backend ID.
func (ks *KeyStore) RunSyncLoopLegacy(ctx context.Context, backendIP string, httpPort int, interval time.Duration) {
	ks.RunSyncLoop(ctx, "default", backendIP, httpPort, interval)
}

func (ks *KeyStore) syncAndApply(backendID, backendIP string, httpPort int) {
	if err := ks.Sync(backendID, backendIP, httpPort); err != nil {
		log.Printf("[keysync] sync failed for %s: %v", backendID, err)
		return
	}

	ks.mu.RLock()
	count := 0
	if bk, ok := ks.backends[backendID]; ok {
		count = len(bk.users)
	}
	ks.mu.RUnlock()
	log.Printf("[keysync] sync OK for %s: %d users", backendID, count)

	if err := ks.PushSentinelKey(backendIP, httpPort); err != nil {
		log.Printf("[keysync] push sentinel key failed for %s: %v", backendID, err)
	}

	if err := ks.Apply(); err != nil {
		log.Printf("[keysync] apply failed: %v", err)
		return
	}

	ks.mu.RLock()
	changed := ks.configChanged
	ks.mu.RUnlock()

	// No sshpiper restart on a routing change. The sshpiperd `yaml` plugin
	// re-reads /etc/sshpiper/config.yaml on every incoming connection (its
	// listPipe → loadConfig path does an os.ReadFile per connect), so a fresh
	// config is picked up by new connections automatically while in-flight
	// sessions stay live. The previous `systemctl restart sshpiper` tore down
	// every live SSH session on each container create/delete (issue #301).
	if changed {
		log.Printf("[keysync] sshpiper routing table updated; new connections pick it up on next connect (no restart)")
	}
}

func (ks *KeyStore) ensureBackendLocked(backendID, backendIP string) *backendKeys {
	bk, ok := ks.backends[backendID]
	if !ok {
		bk = &backendKeys{backendID: backendID, backendIP: backendIP}
		ks.backends[backendID] = bk
	}
	bk.backendIP = backendIP
	return bk
}

// cleanAuthorizedKeys strips blank lines and comment lines from an authorized_keys
// string. sshpiper's parser may stop at a blank line, causing key match failures
// when the client's key appears after one.
func cleanAuthorizedKeys(raw string) string {
	var lines []string
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

// isTunnelLoopback returns true if the IP is a tunnel loopback alias (127.0.0.x, x >= 10).
// These addresses are assigned by the TunnelRegistry for tunnel-connected backends.
func isTunnelLoopback(ip string) bool {
	return strings.HasPrefix(ip, "127.0.0.") && len(ip) > 8 && ip != "127.0.0.1"
}

func (ks *KeyStore) backendCount() int {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return len(ks.backends)
}

// --- Exported state getters ---

// SyncedCount returns the total number of users across all backends.
func (ks *KeyStore) SyncedCount() int {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	count := 0
	for _, bk := range ks.backends {
		count += len(bk.users)
	}
	return count
}

// LastSync returns the most recent sync time across all backends.
func (ks *KeyStore) LastSync() time.Time {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	var latest time.Time
	for _, bk := range ks.backends {
		if bk.lastSync.After(latest) {
			latest = bk.lastSync
		}
	}
	return latest
}

// LastSyncErr returns the first error from any backend, or nil.
func (ks *KeyStore) LastSyncErr() error {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	for _, bk := range ks.backends {
		if bk.lastErr != nil {
			return bk.lastErr
		}
	}
	return nil
}
