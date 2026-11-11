package hosting

import (
	"os"
	"runtime"
	"strings"
	"testing"
)

// #3631: the xcaddy build dir must be an unpredictable 0700 directory.
func TestNewCaddyBuildDir_Mode0700AndUnpredictable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix file mode bits not meaningful on windows")
	}
	dir, err := newCaddyBuildDir()
	if err != nil {
		t.Fatalf("newCaddyBuildDir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	if dir == "/tmp/caddy-build" {
		t.Fatalf("build dir is the predictable path %q", dir)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o700 {
		t.Errorf("build dir mode = %o, want 700", got)
	}
	dir2, err := newCaddyBuildDir()
	if err != nil {
		t.Fatalf("second newCaddyBuildDir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir2) })
	if dir == dir2 {
		t.Errorf("two build dirs share the path %q", dir)
	}
}

// #3631: `caddy run --environ` prints the process environment (including the
// DNS credential) to the journal; the rendered unit must not use it.
func TestRenderSystemdUnit_NoEnvironAndCredentialNotInExecStart(t *testing.T) {
	const secret = "s3cr3t-dns-token"
	m := &CaddyManager{config: CaddyConfig{
		CaddyBin:           "/usr/local/bin/caddy",
		Caddyfile:          "/etc/caddy/Caddyfile",
		ProviderEnvVar:     "CLOUDFLARE_API_TOKEN",
		ProviderCredential: secret,
	}}
	unit, err := m.renderSystemdUnit()
	if err != nil {
		t.Fatalf("renderSystemdUnit: %v", err)
	}
	if strings.Contains(unit, "--environ") {
		t.Errorf("unit still uses --environ:\n%s", unit)
	}
	for _, line := range strings.Split(unit, "\n") {
		if strings.HasPrefix(line, "ExecStart=") && strings.Contains(line, secret) {
			t.Errorf("credential on ExecStart line: %s", line)
		}
	}
}
