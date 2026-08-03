package sentinel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/gateway"
)

func TestKeyStore_Sync(t *testing.T) {
	// Mock backend server
	mockKeys := gateway.KeysResponse{
		Keys: []gateway.UserKeys{
			{Username: "alice", AuthorizedKeys: "ssh-ed25519 AAAA_alice alice@laptop"},
			{Username: "bob", AuthorizedKeys: "ssh-rsa AAAA_bob bob@workstation"},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/authorized-keys" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mockKeys)
	}))
	defer srv.Close()

	// Parse host:port from test server URL
	host := srv.Listener.Addr().String()
	parts := strings.Split(host, ":")
	ip := parts[0]
	// httptest uses a dynamic port, we pass the full URL differently
	// For simplicity, use the full host as backendIP and port 0

	ks := NewKeyStore()

	// We need to test with the actual URL the mock server provides
	// Sync expects backendIP:httpPort, but our mock is on localhost:random
	// Let's test the response parsing logic directly
	client := &http.Client{}
	resp, err := client.Get(srv.URL + "/authorized-keys")
	if err != nil {
		t.Fatalf("failed to GET: %v", err)
	}
	defer resp.Body.Close()

	var keysResp gateway.KeysResponse
	if err := json.NewDecoder(resp.Body).Decode(&keysResp); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}

	if len(keysResp.Keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keysResp.Keys))
	}

	_ = ip // used above
	_ = ks
}

func TestKeyStore_Apply(t *testing.T) {
	// Use temp directory instead of real /etc/sshpiper
	tmpDir := t.TempDir()

	// Override the config paths for testing
	origConfigFile := sshpiperConfigFile
	origUsersDir := sshpiperUsersDir
	origUpstreamKey := sshpiperUpstreamKey
	defer func() {
		// These are constants, so we can't actually restore them,
		// but we test Apply logic via direct file inspection
		_ = origConfigFile
		_ = origUsersDir
		_ = origUpstreamKey
	}()

	// Test the YAML generation logic directly
	users := []gateway.UserKeys{
		{Username: "alice", AuthorizedKeys: "ssh-ed25519 AAAA_alice alice@laptop"},
		{Username: "bob", AuthorizedKeys: "ssh-rsa AAAA_bob bob@workstation"},
	}

	// Write per-user authorized_keys (mimicking Apply)
	usersDir := filepath.Join(tmpDir, "users")
	for _, u := range users {
		userDir := filepath.Join(usersDir, u.Username)
		if err := os.MkdirAll(userDir, 0755); err != nil {
			t.Fatal(err)
		}
		akPath := filepath.Join(userDir, "authorized_keys")
		if err := os.WriteFile(akPath, []byte(u.AuthorizedKeys+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	// Verify files exist
	for _, u := range users {
		akPath := filepath.Join(usersDir, u.Username, "authorized_keys")
		data, err := os.ReadFile(akPath)
		if err != nil {
			t.Errorf("failed to read authorized_keys for %s: %v", u.Username, err)
			continue
		}
		if !strings.Contains(string(data), u.AuthorizedKeys) {
			t.Errorf("authorized_keys for %s missing expected content", u.Username)
		}
	}
}

func TestKeyStore_YAMLConfigGeneration(t *testing.T) {
	users := []gateway.UserKeys{
		{Username: "alice", AuthorizedKeys: "ssh-ed25519 AAAA_alice"},
		{Username: "bob", AuthorizedKeys: "ssh-rsa AAAA_bob"},
	}
	backendIP := "192.0.2.15"

	// Simulate the YAML generation from Apply()
	var lines []string
	lines = append(lines, `version: "1.0"`)
	lines = append(lines, "pipes:")

	for _, u := range users {
		akPath := filepath.Join("/etc/sshpiper/users", u.Username, "authorized_keys")
		lines = append(lines, "  - from:")
		lines = append(lines, "      - username: \""+u.Username+"\"")
		lines = append(lines, "        authorized_keys:")
		lines = append(lines, "          - "+akPath)
		lines = append(lines, "    to:")
		lines = append(lines, "      host: "+backendIP+":22")
		lines = append(lines, "      username: \""+u.Username+"\"")
		lines = append(lines, "      ignore_hostkey: true")
		lines = append(lines, "      private_key: /etc/sshpiper/upstream_key")
	}

	yaml := strings.Join(lines, "\n")

	// Verify structure
	if !strings.Contains(yaml, `version: "1.0"`) {
		t.Error("YAML missing version")
	}
	if !strings.Contains(yaml, "username: \"alice\"") {
		t.Error("YAML missing alice")
	}
	if !strings.Contains(yaml, "username: \"bob\"") {
		t.Error("YAML missing bob")
	}
	if !strings.Contains(yaml, "host: 192.0.2.15:22") {
		t.Error("YAML missing backend host")
	}
	if !strings.Contains(yaml, "ignore_hostkey: true") {
		t.Error("YAML missing ignore_hostkey")
	}
	if !strings.Contains(yaml, "private_key: /etc/sshpiper/upstream_key") {
		t.Error("YAML missing upstream key path")
	}

	// Count pipes (should be 2)
	pipeCount := strings.Count(yaml, "  - from:")
	if pipeCount != 2 {
		t.Errorf("expected 2 pipes, got %d", pipeCount)
	}

	t.Logf("Generated YAML:\n%s", yaml)
}

func TestKeyStore_SyncedCount(t *testing.T) {
	ks := NewKeyStore()

	if ks.SyncedCount() != 0 {
		t.Errorf("expected 0 synced count, got %d", ks.SyncedCount())
	}

	if !ks.LastSync().IsZero() {
		t.Error("expected zero last sync time")
	}

	if ks.LastSyncErr() != nil {
		t.Error("expected nil last sync error")
	}
}

func TestKeyStore_SyncError(t *testing.T) {
	ks := NewKeyStore()

	// Sync to a non-existent server
	err := ks.Sync("test", "192.0.2.1", 99999)
	if err == nil {
		t.Error("expected error when syncing to unreachable server")
	}

	if ks.LastSyncErr() == nil {
		t.Error("expected LastSyncErr to be set after failed sync")
	}
}

func TestKeyStore_PushSentinelKey(t *testing.T) {
	// Mock backend that accepts sentinel key
	var receivedKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/authorized-keys/sentinel" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req gateway.SentinelKeyRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		receivedKey = req.PublicKey
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"updated": 3}`))
	}))
	defer srv.Close()

	// Create a temp upstream key
	tmpDir := t.TempDir()
	pubKeyPath := filepath.Join(tmpDir, "upstream_key.pub")
	testKey := "ssh-ed25519 AAAA_test_sentinel_key sentinel@test"
	if err := os.WriteFile(pubKeyPath, []byte(testKey+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// We can't easily test PushSentinelKey since it reads from a hardcoded path,
	// but we can test the server-side acceptance
	t.Logf("Mock server would receive key: %s", testKey)
	t.Logf("Mock server URL: %s", srv.URL)

	// Verify the mock server works
	_ = receivedKey
}

// TestRenderSSHPiperConfig pins the generated sshpiper YAML directly (the real
// function, not a mirror). The no-CA case must be byte-identical to the
// historical output — Apply skips the rewrite when bytes are unchanged, so any
// drift there would churn the live config. The CA case is additive: every pipe
// gains trusted_user_ca_keys while keeping its authorized_keys.
func TestRenderSSHPiperConfig(t *testing.T) {
	routes := []userRoute{
		{username: "alice", authorizedKeys: "ssh-ed25519 AAAA_alice", backendIP: "192.0.2.15"},
		{username: "bob", authorizedKeys: "ssh-rsa AAAA_bob", backendIP: "192.0.2.15"},
	}

	t.Run("no CA installed — byte-identical to authorized_keys-only output", func(t *testing.T) {
		const golden = `version: "1.0"
pipes:
  - from:
      - username: "alice"
        authorized_keys:
          - /etc/sshpiper/users/alice/authorized_keys
    to:
      host: 192.0.2.15:22
      username: "alice"
      ignore_hostkey: true
      private_key: /etc/sshpiper/upstream_key
  - from:
      - username: "bob"
        authorized_keys:
          - /etc/sshpiper/users/bob/authorized_keys
    to:
      host: 192.0.2.15:22
      username: "bob"
      ignore_hostkey: true
      private_key: /etc/sshpiper/upstream_key
`
		if got := string(renderSSHPiperConfig(routes, "")); got != golden {
			t.Errorf("no-CA output drifted from historical config.\n--- got ---\n%s\n--- want ---\n%s", got, golden)
		}
	})

	t.Run("CA installed — additive: every pipe trusts the CA and keeps authorized_keys", func(t *testing.T) {
		const caPath = "/etc/sshpiper/trusted_user_ca_keys"
		out := string(renderSSHPiperConfig(routes, caPath))
		if c := strings.Count(out, "trusted_user_ca_keys:"); c != len(routes) {
			t.Errorf("expected trusted_user_ca_keys in each of %d pipes, got %d", len(routes), c)
		}
		if c := strings.Count(out, "- "+caPath); c != len(routes) {
			t.Errorf("expected the CA keys path in each of %d pipes, got %d", len(routes), c)
		}
		if c := strings.Count(out, "authorized_keys:"); c != len(routes) {
			t.Errorf("authorized_keys must be retained in each pipe (additive), got %d", c)
		}
		// The CA line belongs inside the `from:` matcher, before `to:`.
		fromIdx := strings.Index(out, "trusted_user_ca_keys:")
		toIdx := strings.Index(out, "    to:")
		if fromIdx < 0 || toIdx < 0 || fromIdx > toIdx {
			t.Error("trusted_user_ca_keys must appear within the from: block, before to:")
		}
	})
}
