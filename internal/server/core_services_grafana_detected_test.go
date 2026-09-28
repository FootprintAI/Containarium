package server

import (
	"strings"
	"testing"
)

// #2103: the daemon auto-detects an existing metrics container and then
// skips EnsureVictoriaMetrics entirely, so the #2079 backfill inside it
// never ran on any existing host. The detected path must run the same
// backfill — with or without a CoreServices already constructed.
func TestHardenDetectedGrafana(t *testing.T) {
	t.Run("no CoreServices yet: builds one and still closes anonymous access", func(t *testing.T) {
		f := newFakeGrafanaBox(grafanaIniAnonOn, nil)

		cs := hardenDetectedGrafana(nil, f)

		if cs == nil {
			t.Fatal("must return a usable CoreServices for the callers after it")
		}
		if len(f.written) != 1 || !sawRestart(f.execs) {
			t.Fatalf("backfill did not run: writes=%d execs=%v", len(f.written), f.execs)
		}
		if enabled, ok := grafanaAnonymousEnabled(f.written[0]); !ok || enabled {
			t.Fatalf("written ini still allows anonymous:\n%s", f.written[0])
		}
	})
	t.Run("existing CoreServices is reused, not replaced", func(t *testing.T) {
		f := newFakeGrafanaBox(grafanaIniAnonOn, nil)
		existing := NewCoreServices(f, CoreServicesConfig{NetworkCIDR: "10.100.0.0/24"})

		cs := hardenDetectedGrafana(existing, f)

		if cs != existing {
			t.Fatal("must not construct a second CoreServices when one exists")
		}
		if len(f.written) != 1 {
			t.Fatalf("backfill did not run through the existing CoreServices: writes=%d", len(f.written))
		}
	})
	t.Run("already hardened host: no write, no restart", func(t *testing.T) {
		f := newFakeGrafanaBox(strings.Replace(grafanaIniAnonOn, "enabled = true", "enabled = false", 1), nil)

		hardenDetectedGrafana(nil, f)

		if len(f.written) != 0 || len(f.execs) != 0 {
			t.Fatalf("converged host must be left alone: writes=%d execs=%v", len(f.written), f.execs)
		}
	})
	t.Run("no incus client: nothing happens, no panic", func(t *testing.T) {
		if cs := hardenDetectedGrafana(nil, nil); cs != nil {
			t.Fatal("no backend → no CoreServices")
		}
	})
}
