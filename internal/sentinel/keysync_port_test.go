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
		{"127.0.0.1", false},  // localhost, not a tunnel alias
		{"127.0.0.2", true},   // loopback alias
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
