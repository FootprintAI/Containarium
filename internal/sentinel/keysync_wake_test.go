package sentinel

import (
	"os"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/gateway"
	"github.com/footprintai/containarium/internal/sentinel/wakeproxy"
)

// TestApply_RoutesThroughWakeProxy verifies wake-on-SSH wiring (#539):
// the generated sshpiper config sends each user's upstream to the local
// wake-proxy port, and the wake-routes file records the real box address
// + the daemon HTTP port so the proxy can wake and splice.
func TestApply_RoutesThroughWakeProxy(t *testing.T) {
	dir := t.TempDir()
	oldCfg, oldUsers, oldWake := sshpiperConfigFile, sshpiperUsersDir, wakeRoutesFile
	sshpiperConfigFile = dir + "/config.yaml"
	sshpiperUsersDir = dir + "/users"
	wakeRoutesFile = dir + "/wake-routes.json"
	defer func() {
		sshpiperConfigFile, sshpiperUsersDir, wakeRoutesFile = oldCfg, oldUsers, oldWake
	}()

	ks := NewKeyStore()
	ks.mu.Lock()
	bk := ks.ensureBackendLocked("b1", "10.0.0.5")
	bk.httpPort = 8080
	bk.users = []gateway.UserKeys{{Username: "alice", AuthorizedKeys: "ssh-ed25519 AAAAkey alice"}}
	ks.mu.Unlock()

	if err := ks.Apply(); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	cfg, err := os.ReadFile(sshpiperConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cfg), "host: 127.0.0.1:40000") {
		t.Errorf("sshpiper config should route through the wake proxy port, got:\n%s", cfg)
	}
	// It must NOT dial the box directly anymore.
	if strings.Contains(string(cfg), "host: 10.0.0.5:22") {
		t.Errorf("sshpiper config still dials the box directly:\n%s", cfg)
	}

	routes, err := wakeproxy.LoadRoutes(wakeRoutesFile)
	if err != nil {
		t.Fatalf("LoadRoutes: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("want 1 route, got %d", len(routes))
	}
	r := routes[0]
	if r.Username != "alice" || r.WakePort != 40000 || r.BackendIP != "10.0.0.5" || r.SSHPort != 22 || r.BackendHTTPPort != 8080 {
		t.Errorf("wake route = %+v", r)
	}

	// Re-running with the same state is a no-op (byte-stable config).
	if err := ks.Apply(); err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	ks.mu.RLock()
	changed := ks.configChanged
	ks.mu.RUnlock()
	if changed {
		t.Error("second Apply with unchanged state should not mark config changed")
	}
}
