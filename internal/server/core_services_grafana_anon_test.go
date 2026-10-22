package server

import (
	"errors"
	"strings"
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/incus/incustest"
)

const grafanaIniAnonOn = `[database]
type = postgres
host = 10.100.0.242:5432

[security]
allow_embedding = true
admin_user = admin

[auth.anonymous]
enabled = true
org_role = Viewer

[users]
default_theme = light
`

// The template the daemon writes on first provisioning must not enable
// anonymous access — that is the finding this fixes (#2079): with the
// dashboard port reachable from every tenant, anonymous Viewer meant any
// tenant could read platform dashboards with no credential at all.
func TestGrafanaIni_AnonymousDisabled(t *testing.T) {
	ini := renderGrafanaIni("10.100.0.242", "containarium", "secret", "adminpw")

	got, ok := grafanaAnonymousEnabled(ini)
	if !ok {
		t.Fatalf("rendered grafana.ini has no [auth.anonymous] section:\n%s", ini)
	}
	if got {
		t.Fatalf("rendered grafana.ini enables anonymous access:\n%s", ini)
	}
	if !strings.Contains(ini, "host = 10.100.0.242:5432") || !strings.Contains(ini, "password = secret") {
		t.Errorf("template lost its database settings:\n%s", ini)
	}
}

func TestDisableGrafanaAnonymous(t *testing.T) {
	tests := []struct {
		name        string
		in          string
		wantChanged bool
		wantEnabled bool // state after
	}{
		{"enabled → disabled", grafanaIniAnonOn, true, false},
		{"already disabled is untouched", strings.Replace(grafanaIniAnonOn, "enabled = true", "enabled = false", 1), false, false},
		{"section absent is untouched (grafana default is disabled)", "[server]\nhttp_port = 3000\n", false, false},
		{"tolerates spacing and case", strings.Replace(grafanaIniAnonOn, "enabled = true", "Enabled=TRUE", 1), true, false},
		{"an 'enabled' key in another section is not the anonymous one",
			"[auth.basic]\nenabled = true\n\n[auth.anonymous]\nenabled = false\n", false, false},
		{"rewrites the anonymous key, not an earlier section's 'enabled'",
			"[auth.basic]\nenabled = true\n\n[auth.anonymous]\nenabled = true\n", true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, changed := disableGrafanaAnonymous(tc.in)
			if changed != tc.wantChanged {
				t.Fatalf("changed = %v, want %v\n--- out ---\n%s", changed, tc.wantChanged, out)
			}
			if !changed && out != tc.in {
				t.Fatalf("unchanged input was rewritten:\n%s", out)
			}
			if enabled, ok := grafanaAnonymousEnabled(out); ok && enabled != tc.wantEnabled {
				t.Fatalf("anonymous enabled = %v after, want %v\n%s", enabled, tc.wantEnabled, out)
			}
			// Nothing outside [auth.anonymous] may change.
			if changed {
				for _, line := range []string{"[database]", "host = 10.100.0.242:5432", "admin_user = admin", "default_theme = light", "[auth.basic]\nenabled = true"} {
					if strings.Contains(tc.in, line) && !strings.Contains(out, line) {
						t.Errorf("line %q lost on rewrite:\n%s", line, out)
					}
				}
			}
		})
	}
}

// fakeGrafanaBox is a MockBackend that serves one grafana.ini and records
// what the backfill writes and runs.
type fakeGrafanaBox struct {
	*incustest.MockBackend
	ini     string
	readErr error

	written []string
	execs   [][]string
}

func newFakeGrafanaBox(ini string, readErr error) *fakeGrafanaBox {
	f := &fakeGrafanaBox{MockBackend: &incustest.MockBackend{}, ini: ini, readErr: readErr}
	f.ReadFileFunc = func(_, path string) ([]byte, error) {
		if f.readErr != nil {
			return nil, f.readErr
		}
		if path != "/etc/grafana/grafana.ini" {
			return nil, errors.New("unexpected path " + path)
		}
		return []byte(f.ini), nil
	}
	f.WriteFileFunc = func(_, path string, content []byte, _ string) error {
		if path != "/etc/grafana/grafana.ini" {
			return errors.New("unexpected write to " + path)
		}
		f.written = append(f.written, string(content))
		return nil
	}
	f.ExecFunc = func(_ string, cmd []string) error {
		f.execs = append(f.execs, cmd)
		return nil
	}
	return f
}

func TestBackfillGrafanaAnonymous(t *testing.T) {
	t.Run("live ini with anonymous on is rewritten and grafana restarted", func(t *testing.T) {
		f := newFakeGrafanaBox(grafanaIniAnonOn, nil)
		cs := NewCoreServices(f, CoreServicesConfig{})

		cs.backfillGrafanaAnonymous()

		if len(f.written) != 1 {
			t.Fatalf("writes = %d, want 1", len(f.written))
		}
		if enabled, ok := grafanaAnonymousEnabled(f.written[0]); !ok || enabled {
			t.Fatalf("written ini still allows anonymous:\n%s", f.written[0])
		}
		if !sawRestart(f.execs) {
			t.Fatalf("grafana was not restarted after the ini change; execs = %v", f.execs)
		}
	})
	t.Run("already disabled → no write, no restart", func(t *testing.T) {
		f := newFakeGrafanaBox(strings.Replace(grafanaIniAnonOn, "enabled = true", "enabled = false", 1), nil)
		cs := NewCoreServices(f, CoreServicesConfig{})

		cs.backfillGrafanaAnonymous()

		if len(f.written) != 0 || len(f.execs) != 0 {
			t.Fatalf("converged host must be left alone; writes=%d execs=%v", len(f.written), f.execs)
		}
	})
	t.Run("unreadable ini → nothing written, nothing run", func(t *testing.T) {
		f := newFakeGrafanaBox("", errors.New("container not running"))
		cs := NewCoreServices(f, CoreServicesConfig{})

		cs.backfillGrafanaAnonymous()

		if len(f.written) != 0 || len(f.execs) != 0 {
			t.Fatalf("must not write on a failed read; writes=%d execs=%v", len(f.written), f.execs)
		}
	})
}

func sawRestart(execs [][]string) bool {
	for _, cmd := range execs {
		if len(cmd) >= 3 && cmd[0] == "systemctl" && cmd[1] == "restart" && cmd[2] == "grafana-server" {
			return true
		}
	}
	return false
}

// Compile-time: the fake must still satisfy Backend through the embedded mock.
var _ incus.Backend = (*fakeGrafanaBox)(nil)
