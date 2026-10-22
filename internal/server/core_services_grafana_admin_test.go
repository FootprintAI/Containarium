package server

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus/incustest"
)

func TestGenerateSecret(t *testing.T) {
	a, err := generateSecret(32)
	if err != nil {
		t.Fatal(err)
	}
	b, err := generateSecret(32)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 32 || len(b) != 32 {
		t.Fatalf("lengths = %d, %d; want 32", len(a), len(b))
	}
	if !regexp.MustCompile(`^[A-Za-z0-9]+$`).MatchString(a) {
		t.Errorf("secret %q is not alphanumeric (it must be safe in URLs, SQL and ini files)", a)
	}
	if a == b {
		t.Error("two generated secrets were identical")
	}
	if _, err := generateSecret(0); err == nil {
		t.Error("a zero-length secret must be refused")
	}
}

func TestEnsureGrafanaAdminPassword(t *testing.T) {
	t.Run("missing → generated, persisted 0600, then reused", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "etc", "grafana-admin.password") // parent dir does not exist yet

		pw, created, err := ensureGrafanaAdminPassword(path)
		if err != nil {
			t.Fatal(err)
		}
		if !created || pw == "" || pw == "containarium" {
			t.Fatalf("pw=%q created=%v; want a fresh non-default password", pw, created)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("file mode = %#o, want 0600", info.Mode().Perm())
		}
		if onDisk, _ := os.ReadFile(path); strings.TrimSpace(string(onDisk)) != pw {
			t.Errorf("file holds %q, returned %q", onDisk, pw)
		}

		// A re-provision (container recreated) must keep the same password, or
		// the operator's saved copy stops working.
		again, createdAgain, err := ensureGrafanaAdminPassword(path)
		if err != nil || createdAgain || again != pw {
			t.Fatalf("second call: pw=%q created=%v err=%v; want the same password, not created", again, createdAgain, err)
		}
	})
	t.Run("an existing world-readable file is refused, not trusted", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "pw")
		if err := os.WriteFile(path, []byte("leaked"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, _, err := ensureGrafanaAdminPassword(path); err == nil {
			t.Fatal("a 0644 password file must be refused")
		}
	})
	t.Run("an empty existing file is refused", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "pw")
		if err := os.WriteFile(path, []byte("\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := ensureGrafanaAdminPassword(path); err == nil {
			t.Fatal("an empty password file must not become an empty password")
		}
	})
}

func TestRenderGrafanaIni_AdminPassword(t *testing.T) {
	t.Run("the given password is used, not a literal default", func(t *testing.T) {
		ini := renderGrafanaIni("10.100.0.242", "containarium", "dbpw", "AdminPw123")
		if !strings.Contains(ini, "admin_password = AdminPw123") {
			t.Fatalf("admin password missing:\n%s", ini)
		}
		if strings.Contains(ini, "admin_password = containarium") {
			t.Fatalf("the literal default admin password is still in the template:\n%s", ini)
		}
	})
	t.Run("empty omits the key so Grafana forces a first-login change", func(t *testing.T) {
		ini := renderGrafanaIni("10.100.0.242", "containarium", "dbpw", "")
		if strings.Contains(ini, "admin_password") {
			t.Fatalf("an empty admin password must omit the key:\n%s", ini)
		}
		if !strings.Contains(ini, "admin_user = admin") {
			t.Errorf("admin_user was lost:\n%s", ini)
		}
	})
	t.Run("a value Grafana would read as a comment is quoted", func(t *testing.T) {
		ini := renderGrafanaIni("10.100.0.242", "containarium", "dbpw", "a#b;c")
		if !strings.Contains(ini, `admin_password = """a#b;c"""`) {
			t.Fatalf("admin password not quoted:\n%s", ini)
		}
	})
}

func TestGrafanaAdminPasswordForProvisioning(t *testing.T) {
	t.Run("persists a generated password at the configured path", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "grafana-admin.password")
		t.Setenv("CONTAINARIUM_GRAFANA_ADMIN_PASSWORD_FILE", path)

		cs := NewCoreServices(incustest.NewMockBackend(), CoreServicesConfig{})
		pw := cs.grafanaAdminPasswordForProvisioning()

		if pw == "" {
			t.Fatal("expected a generated password")
		}
		if onDisk, err := os.ReadFile(path); err != nil || strings.TrimSpace(string(onDisk)) != pw {
			t.Fatalf("password not persisted at %s (err=%v)", path, err)
		}
	})
	t.Run("cannot persist → omit and say so, never a silent default", func(t *testing.T) {
		// A path whose parent is a regular file cannot be created.
		blocker := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("CONTAINARIUM_GRAFANA_ADMIN_PASSWORD_FILE", filepath.Join(blocker, "sub", "pw"))
		var buf bytes.Buffer
		log.SetOutput(&buf)
		t.Cleanup(func() { log.SetOutput(os.Stderr) })

		cs := NewCoreServices(incustest.NewMockBackend(), CoreServicesConfig{})
		if pw := cs.grafanaAdminPasswordForProvisioning(); pw != "" {
			t.Fatalf("pw = %q, want empty when it cannot be saved (an unrecoverable password locks the operator out)", pw)
		}
		if !strings.Contains(buf.String(), "Grafana") || !strings.Contains(buf.String(), "first login") {
			t.Errorf("the operator must be told what happens instead:\n%s", buf.String())
		}
	})
}
