package sentinel

import (
	"fmt"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/gateway"
)

func TestIsTunnelLoopback(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.10", true},
		{"127.0.0.11", true},
		{"127.0.0.99", true},
		{"127.0.0.1", false},   // localhost, not a tunnel alias
		{"127.0.0.2", true},    // loopback alias
		{"10.130.0.15", false}, // VPC internal IP
		{"192.168.1.1", false},
		{"", false},
	}
	for _, tt := range tests {
		got := isTunnelLoopback(tt.ip)
		if got != tt.want {
			t.Errorf("isTunnelLoopback(%q) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestApply_TunnelPortRouting(t *testing.T) {
	ks := NewKeyStore()

	// Add a VPC backend (direct, port 22)
	ks.mu.Lock()
	ks.backends["gcp-spot"] = &backendKeys{
		backendID: "gcp-spot",
		backendIP: "10.130.0.15",
		users: []gateway.UserKeys{
			{Username: "alice", AuthorizedKeys: "ssh-ed25519 AAAA_alice"},
		},
	}
	// Add a tunnel backend (loopback, port 20022)
	ks.backends["tunnel-gpu"] = &backendKeys{
		backendID: "tunnel-gpu",
		backendIP: "127.0.0.10",
		users: []gateway.UserKeys{
			{Username: "bob", AuthorizedKeys: "ssh-ed25519 AAAA_bob"},
		},
	}
	ks.mu.Unlock()

	// Build the config YAML in-memory (same logic as Apply but without file I/O)
	ks.mu.RLock()
	type userRoute struct {
		username  string
		backendIP string
	}
	seen := make(map[string]bool)
	var routes []userRoute
	for _, bk := range ks.backends {
		for _, u := range bk.users {
			if seen[u.Username] {
				continue
			}
			seen[u.Username] = true
			routes = append(routes, userRoute{
				username:  u.Username,
				backendIP: bk.backendIP,
			})
		}
	}
	ks.mu.RUnlock()

	// Verify port selection per backend
	for _, r := range routes {
		sshPort := 22
		if isTunnelLoopback(r.backendIP) {
			sshPort = 20022
		}
		// Verify port assignment
		if r.username == "alice" && sshPort != 22 {
			t.Errorf("alice (VPC backend) should use port 22, got %d", sshPort)
		}
		if r.username == "bob" && sshPort != 20022 {
			t.Errorf("bob (tunnel backend) should use port 20022, got %d", sshPort)
		}
	}
}

func TestApply_YAMLContainsTunnelPort(t *testing.T) {
	ks := NewKeyStore()

	ks.mu.Lock()
	ks.backends["gcp-spot"] = &backendKeys{
		backendID: "gcp-spot",
		backendIP: "10.130.0.15",
		users: []gateway.UserKeys{
			{Username: "alice", AuthorizedKeys: "ssh-ed25519 AAAA_alice"},
		},
	}
	ks.backends["tunnel-gpu"] = &backendKeys{
		backendID: "tunnel-gpu",
		backendIP: "127.0.0.10",
		users: []gateway.UserKeys{
			{Username: "bob", AuthorizedKeys: "ssh-ed25519 AAAA_bob"},
		},
	}
	ks.mu.Unlock()

	// Simulate YAML generation (same as Apply but capture output)
	ks.mu.RLock()
	type route struct {
		username  string
		backendIP string
	}
	seen := make(map[string]bool)
	var routes []route
	for _, bk := range ks.backends {
		for _, u := range bk.users {
			if !seen[u.Username] {
				seen[u.Username] = true
				routes = append(routes, route{u.Username, bk.backendIP})
			}
		}
	}
	ks.mu.RUnlock()

	var yaml strings.Builder
	yaml.WriteString("version: \"1.0\"\npipes:\n")
	for _, r := range routes {
		sshPort := 22
		if isTunnelLoopback(r.backendIP) {
			sshPort = 20022
		}
		yaml.WriteString("  - from:\n")
		yaml.WriteString("      - username: \"" + r.username + "\"\n")
		yaml.WriteString("    to:\n")
		yaml.WriteString("      host: " + r.backendIP + ":" + portStr(sshPort) + "\n")
	}

	config := yaml.String()

	// VPC user should have port 22
	if !strings.Contains(config, "host: 10.130.0.15:22") {
		t.Error("expected VPC backend to use port 22 in YAML config")
	}

	// Tunnel user should have port 20022
	if !strings.Contains(config, "host: 127.0.0.10:20022") {
		t.Error("expected tunnel backend to use port 20022 in YAML config")
	}
}

func portStr(p int) string {
	return fmt.Sprintf("%d", p)
}

// TestRouteTargetPort pins the forwarding-port resolution: legacy backends
// (no advertised port) keep the 22/20022 convention; a backend-advertised
// ingress (a K8s node's in-cluster gateway, e.g. 32022) is used as-is on
// both direct and tunnel paths, because tunnel listeners for non-22 ports
// keep their advertised number.
func TestRouteTargetPort(t *testing.T) {
	tests := []struct {
		name       string
		backendIP  string
		advertised int
		want       int
	}{
		{"legacy direct", "10.130.0.15", 0, 22},
		{"legacy tunnel", "127.0.0.10", 0, 20022},
		{"advertised 22 direct", "10.130.0.15", 22, 22},
		{"advertised 22 tunnel remaps", "127.0.0.10", 22, 20022},
		{"k8s gateway direct", "10.130.0.15", 32022, 32022},
		{"k8s gateway via tunnel", "127.0.0.10", 32022, 32022},
	}
	for _, tt := range tests {
		if got := routeTargetPort(tt.backendIP, tt.advertised); got != tt.want {
			t.Errorf("%s: routeTargetPort(%q, %d) = %d, want %d",
				tt.name, tt.backendIP, tt.advertised, got, tt.want)
		}
	}
}

// TestApply_AdvertisedPortRouting drives Sync's decode of ssh_port through
// to the route emission shape (the same simulation style as
// TestApply_TunnelPortRouting): a K8s-runtime backend advertising 32022
// must be routed to backendIP:32022, not the legacy 22.
func TestApply_AdvertisedPortRouting(t *testing.T) {
	ks := NewKeyStore()
	ks.mu.Lock()
	ks.backends["k8s-node"] = &backendKeys{
		backendID: "k8s-node",
		backendIP: "10.130.0.20",
		sshPort:   32022,
		users: []gateway.UserKeys{
			{Username: "mybox", AuthorizedKeys: "ssh-ed25519 AAAA_mybox agent@laptop"},
		},
	}
	ks.mu.Unlock()

	// Mirror Apply's route-emission logic (Apply itself writes to
	// /etc/sshpiper — not testable here; same approach as the tunnel test).
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	for _, bk := range ks.backends {
		for range bk.users {
			port := routeTargetPort(bk.backendIP, bk.sshPort)
			hostLine := fmt.Sprintf("host: %s:%d", bk.backendIP, port)
			if !strings.Contains(hostLine, "10.130.0.20:32022") {
				t.Errorf("route host = %q, want 10.130.0.20:32022", hostLine)
			}
		}
	}
}
