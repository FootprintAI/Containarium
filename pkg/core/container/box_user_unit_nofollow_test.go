package container

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"testing"
)

// The in-box script runs as root with the account's home under the account's
// control. A symlink on any path below that home must be refused, and nothing
// may be written through it (#3670).

func writeFakeExe(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

// runUserUnitScript runs enableUserUnitScript with getent and ls replaced by
// stubs that report the given home and unit, so no real account is needed.
func runUserUnitScript(t *testing.T, home, unit, username string) error {
	t.Helper()
	bin := t.TempDir()
	writeFakeExe(t, bin, "getent", "#!/bin/bash\necho \"$1:x:1000:1000::$FAKE_HOME:/bin/sh\"\n")
	writeFakeExe(t, bin, "ls", "#!/bin/bash\necho \"$FAKE_UNIT\"\n")
	cmd := exec.Command("bash", "-c", enableUserUnitScript, "bash", username)
	cmd.Env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FAKE_HOME="+home,
		"FAKE_UNIT="+unit,
	)
	return cmd.Run()
}

func currentUsername(t *testing.T) string {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Skipf("no current user: %v", err)
	}
	return u.Username
}

func TestEnableUserUnitScriptWritesLinkForRealHome(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	home := t.TempDir()
	unit := filepath.Join(t.TempDir(), "podman-restart.service")
	if err := os.WriteFile(unit, []byte("unit"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runUserUnitScript(t, home, unit, currentUsername(t)); err != nil {
		t.Fatalf("script failed on a real home: %v", err)
	}
	link := filepath.Join(home, ".config/systemd/user/default.target.wants/podman-restart.service")
	got, err := os.Readlink(link)
	if err != nil {
		t.Fatalf("link not created: %v", err)
	}
	if got != unit {
		t.Errorf("link points to %q, want %q", got, unit)
	}
}

// Each case plants a symlink at one level of the path. The script must fail,
// and the directory the link points at must stay empty.
func TestEnableUserUnitScriptRefusesSymlinkedPaths(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	username := currentUsername(t)
	cases := []struct {
		name  string
		dirs  []string // real directories to create under home first
		plant string   // path under home that becomes a symlink to outside
	}{
		{"config", nil, ".config"},
		{"user", []string{".config/systemd"}, ".config/systemd/user"},
		{"wants", []string{".config/systemd/user"}, ".config/systemd/user/default.target.wants"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			outside := t.TempDir()
			for _, d := range tc.dirs {
				if err := os.MkdirAll(filepath.Join(home, d), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(outside, filepath.Join(home, tc.plant)); err != nil {
				t.Fatal(err)
			}
			unit := filepath.Join(t.TempDir(), "podman-restart.service")
			if err := os.WriteFile(unit, []byte("unit"), 0o644); err != nil {
				t.Fatal(err)
			}

			if err := runUserUnitScript(t, home, unit, username); err == nil {
				t.Fatal("script followed a symlink on the home path; want refusal")
			}
			entries, err := os.ReadDir(outside)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Errorf("something was written through the symlink: %d entries", len(entries))
			}
		})
	}
}
