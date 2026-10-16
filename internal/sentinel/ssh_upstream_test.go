package sentinel

import (
	"context"
	"github.com/footprintai/containarium/internal/sentinel/sshcontrol"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/durationpb"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSSHUpstreamUsesAuthoritativeEndpointIdentity respects advertised ingress.
func TestSSHUpstreamUsesAuthoritativeEndpointIdentity(t *testing.T) {
	ks := NewKeyStore()
	ks.backends["direct"] = &backendKeys{backendID: "direct", backendIP: "192.0.2.1", sshPort: 32022}
	ks.backends["tunnel"] = &backendKeys{backendID: "tunnel", backendIP: "127.0.0.10", sshPort: 22}
	for endpoint, want := range map[string]string{"192.0.2.1:32022": "direct", "127.0.0.10:20022": "tunnel"} {
		if got, err := ks.BackendForEndpoint(endpoint); err != nil || got != want {
			t.Fatalf("route %s: %q %v", endpoint, got, err)
		}
	}
	if _, err := ks.BackendForEndpoint("192.0.2.1:22"); err == nil {
		t.Fatal("unadvertised port became an enforcement route")
	}
	ks.RemoveBackend("direct")
	if _, err := ks.BackendForEndpoint("192.0.2.1:32022"); err == nil {
		t.Fatal("removed backend remained authoritative")
	}
}

// TestSSHUpstreamSupervisorRecoversStartup retries after an operator repairs config.
func TestSSHUpstreamSupervisorRecoversStartup(t *testing.T) {
	dir, err := os.MkdirTemp("", "sshsupervisor-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	path := filepath.Join(dir, "policy.json")
	m := NewManager(Config{SSHUpstreamPolicy: path, SSHUpstreamState: filepath.Join(dir, "risk.json"), SSHUpstreamSocket: filepath.Join(dir, "control.sock")}, &fakeRecoveryProvider{})
	stop := m.superviseSSHUpstream(t.Context(), 10*time.Millisecond)
	defer stop()
	if !m.sshUpstreamStartupFault.Load() {
		t.Fatal("missing policy did not expose startup fault")
	}
	p := &pb.SSHUpstreamPolicy{InitialDelay: durationpb.New(time.Second), MaxDelay: durationpb.New(8 * time.Second), Window: durationpb.New(time.Minute), SetupTimeout: durationpb.New(5 * time.Second), FailureBudget: 2, RiskPerAttempt: 1, MaxBackends: 8, MaxPending: 8, MaxConnections: 32, EgressGroup: "test"}
	data, err := protojson.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	poll := time.NewTicker(10 * time.Millisecond)
	defer poll.Stop()
	for m.sshUpstreamController() == nil || m.sshUpstreamStartupFault.Load() {
		select {
		case <-deadline.C:
			t.Fatal("repair did not restart only the controller")
		case <-poll.C:
		}
	}
}

// TestSSHUpstreamFaultDoesNotExitManager isolates SSH startup from other services.
func TestSSHUpstreamFaultDoesNotExitManager(t *testing.T) {
	m := NewManager(Config{TunnelMode: true, CheckInterval: time.Hour, SSHUpstreamPolicy: filepath.Join(t.TempDir(), "missing.json")}, &fakeRecoveryProvider{})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := m.Run(ctx); err != nil {
		t.Fatalf("SSH controller fault terminated the sentinel: %v", err)
	}
	r := httptest.NewRecorder()
	m.MetricsHandler()(r, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(r.Body.String(), "sentinel_ssh_upstream_faulted 1\n") {
		t.Fatal("startup failure was not observable")
	}
}

// TestSSHUpstreamFaultMetricReportsClosedOwner exposes a persistence-fault alert.
func TestSSHUpstreamFaultMetricReportsClosedOwner(t *testing.T) {
	m := NewManager(Config{}, &fakeRecoveryProvider{})
	m.sshUpstream = &sshcontrol.Controller{}
	for _, want := range []string{"0", "1"} {
		r := httptest.NewRecorder()
		m.MetricsHandler()(r, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		if !strings.Contains(r.Body.String(), "sentinel_ssh_upstream_faulted "+want+"\n") {
			t.Fatalf("missing controller fault health=%s", want)
		}
		if err := m.sshUpstream.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

// TestSSHUpstreamManagerRejectsMalformedPolicy prevents silently unguarded startup.
func TestSSHUpstreamManagerRejectsMalformedPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(`{"failureBudegt":2}`), 0600); err != nil {
		t.Fatal(err)
	}
	m := &Manager{config: Config{SSHUpstreamPolicy: path}, keyStore: NewKeyStore()}
	stop, err := m.startSSHUpstream()
	if stop != nil {
		defer stop()
	}
	if err == nil {
		t.Fatal("malformed policy silently started")
	}
}
