package server

import (
	"errors"
	"strings"
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus/incustest"
)

const clamdConfPackaged = `# Debian clamd.conf
LocalSocket /var/run/clamav/clamd.ctl
LocalSocketGroup clamav
LocalSocketMode 666
# User clamav
User clamav
ScanMail true
ExcludePath ^/mnt/scan-.*/sys
`

func TestClamdRunAsRoot(t *testing.T) {
	tests := []struct {
		name        string
		in          string
		wantChanged bool
		wantUser    string // the effective (first non-comment) User value after
	}{
		{"packaged conf: clamav → root", clamdConfPackaged, true, "root"},
		{"already root is untouched", strings.Replace(clamdConfPackaged, "\nUser clamav", "\nUser root", 1), false, "root"},
		{"tolerates extra spacing", strings.Replace(clamdConfPackaged, "\nUser clamav", "\n  User   clamav  ", 1), true, "root"},
		{"no User line → appended", "LocalSocket /var/run/clamav/clamd.ctl", true, "root"},
		{"a commented User line is not the directive", "# User clamav\nScanMail true\n", true, "root"},
		{"a key that merely starts with User is left alone", "UserHome /x\nUser clamav\n", true, "root"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, changed := clamdRunAsRoot(tc.in)
			if changed != tc.wantChanged {
				t.Fatalf("changed = %v, want %v\n%s", changed, tc.wantChanged, out)
			}
			if !changed && out != tc.in {
				t.Fatalf("unchanged input was rewritten:\n%s", out)
			}
			if got := clamdEffectiveUser(out); got != tc.wantUser {
				t.Fatalf("effective User = %q, want %q\n%s", got, tc.wantUser, out)
			}
			// Idempotent: a second pass over the result changes nothing.
			if again, changed2 := clamdRunAsRoot(out); changed2 || again != out {
				t.Fatalf("not idempotent; second pass changed=%v:\n%s", changed2, again)
			}
			// Nothing else may be lost on a rewrite.
			for _, line := range []string{"LocalSocketGroup clamav", "ScanMail true", "ExcludePath ^/mnt/scan-.*/sys", "UserHome /x"} {
				if strings.Contains(tc.in, line) && !strings.Contains(out, line) {
					t.Errorf("line %q lost:\n%s", line, out)
				}
			}
		})
	}
}

// clamdEffectiveUser is the value of the first non-comment `User` directive.
func clamdEffectiveUser(conf string) string {
	for _, raw := range strings.Split(conf, "\n") {
		if f := strings.Fields(raw); len(f) == 2 && f[0] == "User" {
			return f[1]
		}
	}
	return ""
}

type fakeClamdBox struct {
	*incustest.MockBackend
	conf     string
	readErr  error
	writeErr error
	execErr  error

	written []string
	execs   [][]string
}

func newFakeClamdBox(conf string) *fakeClamdBox {
	f := &fakeClamdBox{MockBackend: &incustest.MockBackend{}, conf: conf}
	f.ReadFileFunc = func(c, path string) ([]byte, error) {
		if f.readErr != nil {
			return nil, f.readErr
		}
		if c != CoreSecurityContainer || path != "/etc/clamav/clamd.conf" {
			return nil, errors.New("unexpected read " + c + ":" + path)
		}
		return []byte(f.conf), nil
	}
	f.WriteFileFunc = func(c, path string, content []byte, _ string) error {
		if f.writeErr != nil {
			return f.writeErr
		}
		if c != CoreSecurityContainer || path != "/etc/clamav/clamd.conf" {
			return errors.New("unexpected write " + c + ":" + path)
		}
		f.written = append(f.written, string(content))
		return nil
	}
	f.ExecFunc = func(_ string, cmd []string) error {
		f.execs = append(f.execs, cmd)
		return f.execErr
	}
	return f
}

func sawClamdRestart(execs [][]string) bool {
	for _, cmd := range execs {
		if len(cmd) == 3 && cmd[0] == "systemctl" && cmd[1] == "restart" && cmd[2] == "clamav-daemon" {
			return true
		}
	}
	return false
}

func TestBackfillClamdUser(t *testing.T) {
	t.Run("clamav conf is rewritten and clamd restarted", func(t *testing.T) {
		f := newFakeClamdBox(clamdConfPackaged)
		NewCoreServices(f, CoreServicesConfig{}).backfillClamdUser()
		if len(f.written) != 1 || clamdEffectiveUser(f.written[0]) != "root" {
			t.Fatalf("writes = %v", f.written)
		}
		if !sawClamdRestart(f.execs) {
			t.Fatalf("clamd not restarted; execs = %v", f.execs)
		}
	})
	t.Run("already root → no write, no restart", func(t *testing.T) {
		f := newFakeClamdBox("User root\n")
		NewCoreServices(f, CoreServicesConfig{}).backfillClamdUser()
		if len(f.written) != 0 || len(f.execs) != 0 {
			t.Fatalf("converged host was touched: writes=%v execs=%v", f.written, f.execs)
		}
	})
	t.Run("unreadable conf → nothing happens", func(t *testing.T) {
		f := newFakeClamdBox("")
		f.readErr = errors.New("container stopped")
		NewCoreServices(f, CoreServicesConfig{}).backfillClamdUser()
		if len(f.written) != 0 || len(f.execs) != 0 {
			t.Fatalf("writes=%v execs=%v", f.written, f.execs)
		}
	})
	t.Run("write failure → no restart", func(t *testing.T) {
		f := newFakeClamdBox(clamdConfPackaged)
		f.writeErr = errors.New("read-only fs")
		NewCoreServices(f, CoreServicesConfig{}).backfillClamdUser()
		if len(f.execs) != 0 {
			t.Fatalf("restarted despite failed write: %v", f.execs)
		}
	})
	t.Run("restart failure is logged, not fatal", func(t *testing.T) {
		f := newFakeClamdBox(clamdConfPackaged)
		f.execErr = errors.New("unit not found")
		NewCoreServices(f, CoreServicesConfig{}).backfillClamdUser() // must not panic
		if len(f.written) != 1 {
			t.Fatalf("writes = %v", f.written)
		}
	})
}

func TestConfigureClamdUser_FirstProvision(t *testing.T) {
	f := newFakeClamdBox(clamdConfPackaged)
	if err := NewCoreServices(f, CoreServicesConfig{}).configureClamdUser(); err != nil {
		t.Fatal(err)
	}
	if len(f.written) != 1 || clamdEffectiveUser(f.written[0]) != "root" {
		t.Fatalf("writes = %v", f.written)
	}
	if len(f.execs) != 0 {
		t.Fatalf("first provision must not restart clamd (it is not started yet): %v", f.execs)
	}
}
