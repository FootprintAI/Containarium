package sentinel

import (
	"github.com/footprintai/containarium/internal/sentinel/sshcontrol"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
