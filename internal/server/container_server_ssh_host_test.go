package server

import (
	"testing"

	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/incus/incustest"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// newSSHHostTestServer wires a ContainerServer over a MockBackend seeded
// with one running container, with the daemon's --ssh-host value set to
// sshHost. Mirrors newTTLTestServer's shape.
func newSSHHostTestServer(t *testing.T, sshHost string) *ContainerServer {
	t.Helper()
	mock := incustest.NewMockBackend()
	mock.Containers["alice-container"] = &incus.ContainerInfo{
		Name:      "alice-container",
		State:     "Running",
		IPAddress: "10.0.0.5",
	}
	return &ContainerServer{manager: container.NewWithBackend(mock), sshHost: sshHost}
}

// TestGetContainer_StampsSSHHost — sentinel-jump mode: a configured
// --ssh-host is surfaced verbatim on Container.ssh_host so a client can
// build the connect target username@ssh_host without inferring the host.
func TestGetContainer_StampsSSHHost(t *testing.T) {
	s := newSSHHostTestServer(t, "region-a.example.com")
	resp, err := s.GetContainer(testCtx(), &pb.GetContainerRequest{Username: "alice"})
	if err != nil {
		t.Fatalf("GetContainer: %v", err)
	}
	if got := resp.GetContainer().GetSshHost(); got != "region-a.example.com" {
		t.Fatalf("ssh_host = %q, want %q", got, "region-a.example.com")
	}
}

// TestGetContainer_EmptySSHHostDirectMode — direct mode: with no
// --ssh-host configured, ssh_host is left empty so clients fall back to
// network.ip_address. This keeps the wire byte-for-byte identical to
// pre-field behavior for direct/local deployments.
func TestGetContainer_EmptySSHHostDirectMode(t *testing.T) {
	s := newSSHHostTestServer(t, "")
	resp, err := s.GetContainer(testCtx(), &pb.GetContainerRequest{Username: "alice"})
	if err != nil {
		t.Fatalf("GetContainer: %v", err)
	}
	if got := resp.GetContainer().GetSshHost(); got != "" {
		t.Fatalf("ssh_host = %q, want empty (direct mode)", got)
	}
	// The fallback source the client uses must still be present.
	if got := resp.GetContainer().GetNetwork().GetIpAddress(); got != "10.0.0.5" {
		t.Fatalf("ip_address = %q, want 10.0.0.5 (direct-mode fallback)", got)
	}
}

// TestSSHCommandFor — CreateContainer's ssh_command must name the reachable
// target: the sentinel ssh_host when set (so off-LAN callers like MCP agents
// can actually connect), and only the container IP for direct deployments.
// Regression guard for #658, where the command always used the private IP.
func TestSSHCommandFor(t *testing.T) {
	cases := []struct {
		name    string
		sshHost string
		ip      string
		want    string
	}{
		{"sentinel mode uses ssh_host", "region-a.example.com", "10.0.0.5", "ssh alice@region-a.example.com"},
		{"direct mode falls back to ip", "", "10.0.0.5", "ssh alice@10.0.0.5"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sshCommandFor("alice", c.sshHost, c.ip); got != c.want {
				t.Fatalf("sshCommandFor = %q, want %q", got, c.want)
			}
		})
	}
}

// TestSetSSHHost — the DualServer wiring setter stores the value the read
// path stamps.
func TestSetSSHHost(t *testing.T) {
	s := &ContainerServer{}
	s.SetSSHHost("sentinel.example.com")
	if s.sshHost != "sentinel.example.com" {
		t.Fatalf("sshHost = %q, want %q", s.sshHost, "sentinel.example.com")
	}
}
