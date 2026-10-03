package server

import (
	"bytes"
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus/incustest"
)

// grafanaIniWithPassword is a provisioned grafana.ini whose [database]
// password is pw. A second section carries its own `password` key, to prove
// the rewrite touches only [database].
func grafanaIniWithPassword(pw string) string {
	return "[database]\ntype = postgres\nhost = 10.100.0.242:5432\nname = grafana\nuser = containarium\npassword = " + pw + "\nssl_mode = disable\n\n" +
		"[smtp]\npassword = keep-me\n\n[auth.anonymous]\nenabled = false\n"
}

func TestGrafanaDBSettings(t *testing.T) {
	host, user, pw, ok := grafanaDBSettings(grafanaIniWithPassword("old-pass"))
	if !ok {
		t.Fatal("ok = false for a provisioned ini")
	}
	if host != "10.100.0.242:5432" || user != "containarium" || pw != "old-pass" {
		t.Fatalf("got host=%q user=%q pw=%q", host, user, pw)
	}

	if _, _, _, ok := grafanaDBSettings("[server]\nhttp_port = 3000\n"); ok {
		t.Error("an ini with no [database] section must report ok=false")
	}
	// A password key in another section is not the database password.
	if _, _, _, ok := grafanaDBSettings("[smtp]\npassword = x\n[database]\nhost = h:5432\nuser = u\n"); ok {
		t.Error("an ini with no [database] password must report ok=false")
	}
}

func TestGrafanaDBSettings_TripleQuotedValue(t *testing.T) {
	ini := "[database]\nhost = h:5432\nuser = u\npassword = \"\"\"pa#ss;word\"\"\"\n"
	_, _, pw, ok := grafanaDBSettings(ini)
	if !ok || pw != "pa#ss;word" {
		t.Fatalf("pw = %q ok=%v, want the unquoted value", pw, ok)
	}
}

func TestWithGrafanaDBPassword(t *testing.T) {
	t.Run("rewrites only the [database] password", func(t *testing.T) {
		in := grafanaIniWithPassword("old-pass")
		out, changed := withGrafanaDBPassword(in, "new-pass")
		if !changed {
			t.Fatal("changed = false")
		}
		if _, _, pw, _ := grafanaDBSettings(out); pw != "new-pass" {
			t.Fatalf("database password = %q after rewrite", pw)
		}
		if !strings.Contains(out, "[smtp]\npassword = keep-me") {
			t.Errorf("another section's password was touched:\n%s", out)
		}
		for _, keep := range []string{"host = 10.100.0.242:5432", "user = containarium", "ssl_mode = disable", "[auth.anonymous]\nenabled = false"} {
			if !strings.Contains(out, keep) {
				t.Errorf("line %q lost on rewrite:\n%s", keep, out)
			}
		}
	})
	t.Run("already equal is a no-op", func(t *testing.T) {
		in := grafanaIniWithPassword("same")
		out, changed := withGrafanaDBPassword(in, "same")
		if changed || out != in {
			t.Fatalf("converged ini was rewritten (changed=%v)", changed)
		}
	})
	t.Run("no [database] section is left alone", func(t *testing.T) {
		in := "[server]\nhttp_port = 3000\n"
		out, changed := withGrafanaDBPassword(in, "x")
		if changed || out != in {
			t.Fatalf("an ini with nothing to rewrite was modified (changed=%v)", changed)
		}
	})
	t.Run("a password Grafana would read as a comment is quoted", func(t *testing.T) {
		out, changed := withGrafanaDBPassword(grafanaIniWithPassword("old"), "ab#cd;ef")
		if !changed {
			t.Fatal("changed = false")
		}
		if _, _, pw, _ := grafanaDBSettings(out); pw != "ab#cd;ef" {
			t.Fatalf("round-trip = %q, want ab#cd;ef\n%s", pw, out)
		}
		if !strings.Contains(out, `"""ab#cd;ef"""`) {
			t.Errorf("value containing # or ; must be triple-quoted:\n%s", out)
		}
	})
}

// The template must carry the password it is given, quoted when needed — it
// is the effective one, never a hard-coded default (#2091).
func TestRenderGrafanaIni_UsesGivenPassword(t *testing.T) {
	ini := renderGrafanaIni("10.100.0.242", "containarium", "from-the-secret-file")
	if _, _, pw, ok := grafanaDBSettings(ini); !ok || pw != "from-the-secret-file" {
		t.Fatalf("rendered password = %q ok=%v\n%s", pw, ok, ini)
	}
	// Scoped to the [database] section on purpose: [security] admin_password
	// is the other half of #2091 and is decided separately.
	if _, _, pw, _ := grafanaDBSettings(ini); pw == DefaultPostgresPassword {
		t.Errorf("rendered [database] password is still the compiled-in default")
	}

	hard := renderGrafanaIni("10.100.0.242", "containarium", "a#b")
	if _, _, pw, _ := grafanaDBSettings(hard); pw != "a#b" {
		t.Fatalf("a password containing # did not survive the template: %q\n%s", pw, hard)
	}
}

// fakeGrafanaPG wires a grafana box and a scripted connection test.
type fakeGrafanaPG struct {
	*fakeGrafanaBox
	pingErr   error
	pingCalls []pgPingArgs
}

func newFakeGrafanaPG(ini string, readErr, pingErr error) (*fakeGrafanaPG, *CoreServices) {
	f := &fakeGrafanaPG{fakeGrafanaBox: newFakeGrafanaBox(ini, readErr), pingErr: pingErr}
	cs := NewCoreServices(f, CoreServicesConfig{PostgresPassword: "new-effective"})
	cs.pgPing = func(_ context.Context, a pgPingArgs) error {
		f.pingCalls = append(f.pingCalls, a)
		return f.pingErr
	}
	return f, cs
}

func TestBackfillGrafanaDBPassword(t *testing.T) {
	t.Run("stale grafana password, effective one connects → rewritten and restarted", func(t *testing.T) {
		f, cs := newFakeGrafanaPG(grafanaIniWithPassword("old-pass"), nil, nil)

		cs.backfillGrafanaDBPassword()

		if len(f.pingCalls) != 1 {
			t.Fatalf("connection tests = %d, want 1", len(f.pingCalls))
		}
		if a := f.pingCalls[0]; a.Host != "10.100.0.242:5432" || a.User != "containarium" || a.Password != "new-effective" || a.Database != "grafana" {
			t.Fatalf("connection test used %+v, want the ini's host/user, the grafana database and the effective password", a)
		}
		if len(f.written) != 1 {
			t.Fatalf("writes = %d, want 1", len(f.written))
		}
		if _, _, pw, _ := grafanaDBSettings(f.written[0]); pw != "new-effective" {
			t.Fatalf("written ini password = %q", pw)
		}
		if !sawRestart(f.execs) {
			t.Fatalf("grafana was not restarted; execs = %v", f.execs)
		}
	})

	t.Run("effective password does NOT connect → host left exactly as it is", func(t *testing.T) {
		// A host rotated by hand: Grafana already holds the working password
		// and the daemon's env still resolves to something else. Overwriting
		// would take Grafana's database offline.
		f, cs := newFakeGrafanaPG(grafanaIniWithPassword("hand-rotated"), nil, errors.New("password authentication failed"))

		cs.backfillGrafanaDBPassword()

		if len(f.written) != 0 || len(f.execs) != 0 {
			t.Fatalf("must not touch Grafana when the new password does not work; writes=%d execs=%v", len(f.written), f.execs)
		}
	})

	t.Run("already the effective password → no connection test, no write", func(t *testing.T) {
		f, cs := newFakeGrafanaPG(grafanaIniWithPassword("new-effective"), nil, nil)

		cs.backfillGrafanaDBPassword()

		if len(f.pingCalls) != 0 || len(f.written) != 0 || len(f.execs) != 0 {
			t.Fatalf("converged host must be left alone; pings=%d writes=%d execs=%v", len(f.pingCalls), len(f.written), f.execs)
		}
	})

	t.Run("unreadable ini → nothing happens", func(t *testing.T) {
		f, cs := newFakeGrafanaPG("", errors.New("container not running"), nil)

		cs.backfillGrafanaDBPassword()

		if len(f.pingCalls) != 0 || len(f.written) != 0 || len(f.execs) != 0 {
			t.Fatalf("pings=%d writes=%d execs=%v", len(f.pingCalls), len(f.written), f.execs)
		}
	})

	t.Run("ini without a database password → nothing happens", func(t *testing.T) {
		f, cs := newFakeGrafanaPG("[server]\nhttp_port = 3000\n", nil, nil)

		cs.backfillGrafanaDBPassword()

		if len(f.pingCalls) != 0 || len(f.written) != 0 {
			t.Fatalf("pings=%d writes=%d", len(f.pingCalls), len(f.written))
		}
	})
}

// The existing-host path: auto-detection makes the daemon skip
// EnsureVictoriaMetrics, so the backfills must also run from
// hardenDetectedGrafana or they would miss exactly the hosts that need them.
func TestHardenDetectedGrafana_AlsoBackfillsDBPassword(t *testing.T) {
	f := newFakeGrafanaBox(grafanaIniWithPassword("old-pass"), nil)
	cs := NewCoreServices(f, CoreServicesConfig{PostgresPassword: "new-effective"})
	cs.pgPing = func(context.Context, pgPingArgs) error { return nil }

	hardenDetectedGrafana(cs, f)

	if len(f.written) == 0 {
		t.Fatal("hardenDetectedGrafana did not backfill the database password")
	}
	last := f.written[len(f.written)-1]
	if _, _, pw, _ := grafanaDBSettings(last); pw != "new-effective" {
		t.Fatalf("database password after hardenDetectedGrafana = %q", pw)
	}
}

// NewCoreServices must resolve the operator's password the same way the
// daemon's own connection does, so CREATE USER, the readiness probe and
// Grafana all agree with it (#2091). Before this, no caller set
// CoreServicesConfig.PostgresPassword and a first install always created the
// role with the compiled-in default.
func TestNewCoreServices_ResolvesEffectivePassword(t *testing.T) {
	t.Run("password file wins", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "pg.password")
		if err := os.WriteFile(p, []byte("from-file\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("CONTAINARIUM_POSTGRES_PASSWORD_FILE", p)
		t.Setenv("CONTAINARIUM_POSTGRES_PASSWORD", "from-env")

		cs := NewCoreServices(incustest.NewMockBackend(), CoreServicesConfig{})
		if cs.config.PostgresPassword != "from-file" {
			t.Fatalf("password = %q, want from-file", cs.config.PostgresPassword)
		}
	})
	t.Run("env var", func(t *testing.T) {
		t.Setenv("CONTAINARIUM_POSTGRES_PASSWORD_FILE", "")
		t.Setenv("CONTAINARIUM_POSTGRES_PASSWORD", "from-env")

		cs := NewCoreServices(incustest.NewMockBackend(), CoreServicesConfig{})
		if cs.config.PostgresPassword != "from-env" {
			t.Fatalf("password = %q, want from-env", cs.config.PostgresPassword)
		}
	})
	t.Run("an explicit config value is not overridden", func(t *testing.T) {
		t.Setenv("CONTAINARIUM_POSTGRES_PASSWORD", "from-env")

		cs := NewCoreServices(incustest.NewMockBackend(), CoreServicesConfig{PostgresPassword: "explicit"})
		if cs.config.PostgresPassword != "explicit" {
			t.Fatalf("password = %q, want explicit", cs.config.PostgresPassword)
		}
	})
	t.Run("nothing configured → compiled-in default, without a log line per construction", func(t *testing.T) {
		t.Setenv("CONTAINARIUM_POSTGRES_PASSWORD_FILE", "")
		t.Setenv("CONTAINARIUM_POSTGRES_PASSWORD", "")
		var buf bytes.Buffer
		log.SetOutput(&buf)
		t.Cleanup(func() { log.SetOutput(os.Stderr) })

		cs := NewCoreServices(incustest.NewMockBackend(), CoreServicesConfig{})
		if cs.config.PostgresPassword != DefaultPostgresPassword {
			t.Fatalf("password = %q, want the default", cs.config.PostgresPassword)
		}
		// The daemon resolves once and warns once; NewCoreServices is built
		// several times per start and must not repeat that warning.
		if strings.Contains(buf.String(), "WARNING") {
			t.Errorf("NewCoreServices logged a warning:\n%s", buf.String())
		}
	})
	t.Run("an unusable password file falls back and says so", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "pg.password")
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil { // world-readable: refused
			t.Fatal(err)
		}
		t.Setenv("CONTAINARIUM_POSTGRES_PASSWORD_FILE", p)
		var buf bytes.Buffer
		log.SetOutput(&buf)
		t.Cleanup(func() { log.SetOutput(os.Stderr) })

		cs := NewCoreServices(incustest.NewMockBackend(), CoreServicesConfig{})
		if cs.config.PostgresPassword != DefaultPostgresPassword {
			t.Fatalf("password = %q", cs.config.PostgresPassword)
		}
		if !strings.Contains(buf.String(), "insecure permissions") {
			t.Errorf("a refused password file must be reported, got:\n%s", buf.String())
		}
	})
}
