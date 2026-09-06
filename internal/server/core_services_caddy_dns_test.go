package server

import (
	"strings"
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// #1597 — Caddy expands {env.VAR} in ITS OWN process environment (a separate
// Incus container), not the daemon's. Before this, nothing ever propagated a
// configured DNS-01 provider credential there at all: the daemon emitted a
// TLS policy referencing {env.CF_API_TOKEN}, built Caddy with the right
// caddy-dns module, and then never set CF_API_TOKEN anywhere Caddy could see
// it. Every DNS-01 attempt failed with a message that read like a
// token-scope problem instead of "nothing was ever set".

// originalCaddyServiceUnit is exactly the unit text this file's setupCaddy
// wrote before #1597 — the byte-for-byte baseline every non-DNS-01 host
// (the common case) must keep getting, so this change doesn't restart Caddy
// on every host that never configured DNS-01 at all.
const originalCaddyServiceUnit = `[Unit]
Description=Caddy
After=network.target network-online.target
Requires=network-online.target

[Service]
Type=notify
User=caddy
Group=caddy
ExecStart=/usr/bin/caddy run --environ --config /etc/caddy/Caddyfile
ExecReload=/usr/bin/caddy reload --config /etc/caddy/Caddyfile --force
TimeoutStopSec=5s
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
`

func TestCaddyServiceUnit_EmptyEnvMatchesOriginal(t *testing.T) {
	for _, envVars := range []map[string]string{nil, {}} {
		if got := caddyServiceUnit(envVars); got != originalCaddyServiceUnit {
			t.Errorf("caddyServiceUnit(%#v) changed the unit for a host with no DNS-01 credentials to "+
				"propagate:\n got: %q\nwant: %q", envVars, got, originalCaddyServiceUnit)
		}
	}
}

func TestCaddyServiceUnit_RendersSortedEnvironmentLines(t *testing.T) {
	got := caddyServiceUnit(map[string]string{
		"CF_ZONE_ID":   "zone123",
		"CF_API_TOKEN": "secret-token",
	})

	wantOrder := "Environment=CF_API_TOKEN=secret-token\nEnvironment=CF_ZONE_ID=zone123\n"
	if !strings.Contains(got, wantOrder) {
		t.Errorf("Environment= lines missing or not sorted:\n%s", got)
	}
	// Must still land between Group=caddy and ExecStart=, and the rest of
	// the unit must be untouched.
	if !strings.Contains(got, "Group=caddy\n"+wantOrder+"ExecStart=") {
		t.Errorf("Environment= lines not positioned correctly:\n%s", got)
	}
	if !strings.HasPrefix(got, "[Unit]\n") || !strings.HasSuffix(got, "WantedBy=multi-user.target\n") {
		t.Errorf("unit no longer starts/ends the same way:\n%s", got)
	}
}

func TestCaddyDNSProviderEnv_SplitsPresentAndMissing(t *testing.T) {
	t.Run("no DNS-01 provider configured → nothing to resolve", func(t *testing.T) {
		t.Setenv("CONTAINARIUM_ACME_DNS_PROVIDER", "")
		present, missing := caddyDNSProviderEnv()
		if len(present) != 0 || len(missing) != 0 {
			t.Errorf("present=%v missing=%v, want both empty", present, missing)
		}
	})

	t.Run("cloudflare with the token set", func(t *testing.T) {
		t.Setenv("CONTAINARIUM_ACME_DNS_PROVIDER", "cloudflare")
		t.Setenv("CONTAINARIUM_ACME_DNS_PROVIDER_CONFIG", "")
		t.Setenv("CF_API_TOKEN", "real-token-value")
		present, missing := caddyDNSProviderEnv()
		if present["CF_API_TOKEN"] != "real-token-value" {
			t.Errorf("present[CF_API_TOKEN] = %q, want real-token-value", present["CF_API_TOKEN"])
		}
		if len(missing) != 0 {
			t.Errorf("missing = %v, want none — the credential IS set", missing)
		}
	})

	t.Run("cloudflare with the token unset — the #1597 failure mode", func(t *testing.T) {
		t.Setenv("CONTAINARIUM_ACME_DNS_PROVIDER", "cloudflare")
		t.Setenv("CONTAINARIUM_ACME_DNS_PROVIDER_CONFIG", "")
		t.Setenv("CF_API_TOKEN", "")
		present, missing := caddyDNSProviderEnv()
		if len(present) != 0 {
			t.Errorf("present = %v, want none — CF_API_TOKEN is empty", present)
		}
		if len(missing) != 1 || missing[0] != "CF_API_TOKEN" {
			t.Errorf("missing = %v, want [CF_API_TOKEN]", missing)
		}
	})
}

// fakeCaddyDNSBackend is a minimal incus.Backend fake for reconcileCaddyDNSEnv:
// a ReadFile that returns configurable content, and a WriteFile/Exec that
// record what they were called with so a test can assert on both the
// rewritten unit's content and that daemon-reload + restart actually ran.
type fakeCaddyDNSBackend struct {
	incus.Backend
	readFileContent []byte
	readFileErr     error

	writtenPath    string
	writtenContent []byte
	writeFileErr   error

	execCalls [][]string
	execErr   error
}

func (b *fakeCaddyDNSBackend) ReadFile(string, string) ([]byte, error) {
	return b.readFileContent, b.readFileErr
}

func (b *fakeCaddyDNSBackend) WriteFile(_ string, path string, content []byte, _ string) error {
	b.writtenPath = path
	b.writtenContent = content
	return b.writeFileErr
}

func (b *fakeCaddyDNSBackend) Exec(_ string, command []string) error {
	b.execCalls = append(b.execCalls, command)
	return b.execErr
}

func TestReconcileCaddyDNSEnv_NoOpWhenAlreadyInSync(t *testing.T) {
	t.Setenv("CONTAINARIUM_ACME_DNS_PROVIDER", "cloudflare")
	t.Setenv("CONTAINARIUM_ACME_DNS_PROVIDER_CONFIG", "")
	t.Setenv("CF_API_TOKEN", "real-token-value")

	backend := &fakeCaddyDNSBackend{
		readFileContent: []byte(caddyServiceUnit(map[string]string{"CF_API_TOKEN": "real-token-value"})),
	}
	cs := NewCoreServices(backend, CoreServicesConfig{})

	cs.reconcileCaddyDNSEnv()

	if backend.writtenContent != nil {
		t.Errorf("WriteFile was called though the unit already matched: %s", backend.writtenContent)
	}
	if len(backend.execCalls) != 0 {
		t.Errorf("Exec was called (%v) though nothing changed — this would restart caddy on every daemon start", backend.execCalls)
	}
}

func TestReconcileCaddyDNSEnv_WritesAndRestartsWhenCredentialAppears(t *testing.T) {
	// The exact #1597 scenario: an operator sets CONTAINARIUM_ACME_DNS_PROVIDER
	// (and the credential) on an ALREADY-provisioned host — setupCaddy already
	// ran once, long ago, with no DNS-01 configured at all.
	t.Setenv("CONTAINARIUM_ACME_DNS_PROVIDER", "cloudflare")
	t.Setenv("CONTAINARIUM_ACME_DNS_PROVIDER_CONFIG", "")
	t.Setenv("CF_API_TOKEN", "freshly-configured-token")

	backend := &fakeCaddyDNSBackend{
		readFileContent: []byte(originalCaddyServiceUnit), // pre-#1597 unit, no Environment= lines
	}
	cs := NewCoreServices(backend, CoreServicesConfig{})

	cs.reconcileCaddyDNSEnv()

	want := caddyServiceUnit(map[string]string{"CF_API_TOKEN": "freshly-configured-token"})
	if string(backend.writtenContent) != want {
		t.Errorf("written unit:\n%s\nwant:\n%s", backend.writtenContent, want)
	}
	if backend.writtenPath != "/etc/systemd/system/caddy.service" {
		t.Errorf("written path = %q, want /etc/systemd/system/caddy.service", backend.writtenPath)
	}
	if len(backend.execCalls) != 2 {
		t.Fatalf("Exec called %d times, want 2 (daemon-reload, restart): %v", len(backend.execCalls), backend.execCalls)
	}
	if backend.execCalls[0][0] != "systemctl" || backend.execCalls[0][1] != "daemon-reload" {
		t.Errorf("first Exec = %v, want systemctl daemon-reload", backend.execCalls[0])
	}
	if backend.execCalls[1][0] != "systemctl" || backend.execCalls[1][1] != "restart" {
		t.Errorf("second Exec = %v, want systemctl restart caddy", backend.execCalls[1])
	}
}

// Confirms the missing-credential ERROR path doesn't stop the reconcile
// dead — it must still keep whatever unit content is otherwise correct (no
// partial/corrupt state), and this is the visibility #1597 asks for even
// when there is nothing to write yet.
func TestReconcileCaddyDNSEnv_LogsAndDoesNotWriteWhenCredentialUnset(t *testing.T) {
	t.Setenv("CONTAINARIUM_ACME_DNS_PROVIDER", "cloudflare")
	t.Setenv("CONTAINARIUM_ACME_DNS_PROVIDER_CONFIG", "")
	t.Setenv("CF_API_TOKEN", "")

	backend := &fakeCaddyDNSBackend{
		readFileContent: []byte(originalCaddyServiceUnit),
	}
	cs := NewCoreServices(backend, CoreServicesConfig{})

	cs.reconcileCaddyDNSEnv()

	// Nothing resolved (CF_API_TOKEN is empty), so the desired unit is
	// identical to what's already there — no write, no restart, just the
	// ERROR log line (exercised directly in TestLogMissingDNSProviderCredentials).
	if backend.writtenContent != nil {
		t.Errorf("WriteFile was called with nothing new to add: %s", backend.writtenContent)
	}
	if len(backend.execCalls) != 0 {
		t.Errorf("Exec was called though nothing changed: %v", backend.execCalls)
	}
}
