package engine

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestClaudeProjectSlug pins the "/" -> "-" convention #2193's accepted
// default commits to (unverified against a live Claude Code install — see
// session_discovery.go's doc comment).
func TestClaudeProjectSlug(t *testing.T) {
	tests := []struct{ cwd, want string }{
		{"/home/alice", "-home-alice"},
		{"/home/alice/myproject", "-home-alice-myproject"},
		{"/", "-"},
	}
	for _, tc := range tests {
		if got := ClaudeProjectSlug(tc.cwd); got != tc.want {
			t.Errorf("ClaudeProjectSlug(%q) = %q, want %q", tc.cwd, got, tc.want)
		}
	}
}

// TestSessionDiscoveryBackgroundCommand_UnknownEngine pins that an engine
// with no discoverable session id (there are none today, but a future engine
// added to Name without updating sessionSearchDir must fail closed, not
// silently poll a made-up path).
func TestSessionDiscoveryBackgroundCommand_UnknownEngine(t *testing.T) {
	if _, ok := SessionDiscoveryBackgroundCommand(Name("made-up"), "/home/alice", "/home/alice", "/tmp/x.session"); ok {
		t.Error("an unknown engine should report ok=false, not a command")
	}
}

// TestSessionDiscoveryBackgroundCommand_FindsNewestFile is an end-to-end
// proof against a REAL shell (not a string match on the generated command):
// seed a fake session directory with an older and a newer file, run the
// generated command, and confirm the sidecar ends up holding the NEWER
// file's id. This is the part of #2193 flagged as unverified against a real
// engine install — this test pins the mechanism (newest-file-wins, sidecar
// written atomically) independently of whether the real path turns out to
// match once someone can test it live.
func TestSessionDiscoveryBackgroundCommand_FindsNewestFile(t *testing.T) {
	for _, tc := range []struct {
		name   string
		engine Name
		seed   func(home, cwd string) (sessionDir string, wantID string)
	}{
		{
			name:   "claude",
			engine: NameClaude,
			seed: func(home, cwd string) (string, string) {
				dir := filepath.Join(home, ".claude", "projects", ClaudeProjectSlug(cwd))
				mustMkdirAll(t, dir)
				writeAt(t, filepath.Join(dir, "older.jsonl"), time.Now().Add(-time.Hour))
				writeAt(t, filepath.Join(dir, "newer-session-id.jsonl"), time.Now())
				return dir, "newer-session-id"
			},
		},
		{
			name:   "pi",
			engine: NamePi,
			seed: func(home, cwd string) (string, string) {
				dir := filepath.Join(home, ".pi", "agent", "sessions")
				mustMkdirAll(t, dir)
				writeAt(t, filepath.Join(dir, "older-session"), time.Now().Add(-time.Hour))
				writeAt(t, filepath.Join(dir, "newer-session"), time.Now())
				return dir, "newer-session"
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			cwd := filepath.Join(home, "myproject")
			_, wantID := tc.seed(home, cwd)

			sidecar := filepath.Join(t.TempDir(), "run.session")
			cmd, ok := SessionDiscoveryBackgroundCommand(tc.engine, home, cwd, sidecar)
			if !ok {
				t.Fatalf("SessionDiscoveryBackgroundCommand(%s) ok=false", tc.engine)
			}
			// #nosec G204 -- cmd is built entirely by the function under test
			// from test-controlled inputs; this is the test for it.
			if out, err := exec.Command("/bin/sh", "-c", cmd).CombinedOutput(); err != nil {
				t.Fatalf("running the discovery command failed: %v\n%s", err, out)
			}

			got := waitForSidecar(t, sidecar, 3*time.Second)
			if got != wantID {
				t.Errorf("sidecar = %q, want %q", got, wantID)
			}
		})
	}
}

// TestSessionDiscoveryBackgroundCommand_GivesUpWithoutATraceWhenNothingAppears
// confirms absence is silent and non-fatal: no sidecar, no hang, no error —
// exactly the "absent for engines that don't expose one" contract the issue
// allows, applied here to "nothing showed up in time" too.
func TestSessionDiscoveryBackgroundCommand_GivesUpWithoutATraceWhenNothingAppears(t *testing.T) {
	home := t.TempDir()
	sidecar := filepath.Join(t.TempDir(), "run.session")
	cmd, ok := SessionDiscoveryBackgroundCommand(NamePi, home, home, sidecar)
	if !ok {
		t.Fatal("ok=false")
	}
	// #nosec G204 -- see above.
	if out, err := exec.Command("/bin/sh", "-c", cmd).CombinedOutput(); err != nil {
		t.Fatalf("command failed: %v\n%s", err, out)
	}
	// Give the backgrounded loop its full budget plus margin, then confirm
	// it gave up cleanly rather than writing something wrong.
	time.Sleep(time.Duration(sessionDiscoveryAttempts)*time.Duration(sessionDiscoveryIntervalMS)*time.Millisecond + 500*time.Millisecond)
	if _, err := os.Stat(sidecar); err == nil {
		t.Error("sidecar should not exist when no session file ever appeared")
	}
}

func mustMkdirAll(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
}

func writeAt(t *testing.T, path string, mtime time.Time) {
	t.Helper()
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

// waitForSidecar polls for the sidecar file (the discovery command backgrounds
// itself and returns immediately) and returns its content once it appears.
func waitForSidecar(t *testing.T, path string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(path); err == nil {
			return strings.TrimSpace(string(data))
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("sidecar %s never appeared within %s", path, timeout)
	return ""
}
