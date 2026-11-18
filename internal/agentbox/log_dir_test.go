//go:build !windows

package agentbox

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// The run directory is per box user (#3682): <LogRoot>/<user>, never the
// shared root itself.
func TestUserLogDir_IsPerUserUnderTheRoot(t *testing.T) {
	if LogRoot != "/tmp/agent-box" {
		t.Errorf("LogRoot = %q, want /tmp/agent-box", LogRoot)
	}
	if got := UserLogDir("alice"); got != "/tmp/agent-box/alice" {
		t.Errorf("UserLogDir(alice) = %q, want /tmp/agent-box/alice", got)
	}
	if UserLogDir("alice") == UserLogDir("bob") {
		t.Error("two box users share one run directory")
	}
}

// With no override, agent-box writes into the directory of the user it runs as.
func TestDefaultProcessLogDir_IsTheCurrentUsersDirectory(t *testing.T) {
	t.Setenv("AGENTBOX_LOG_DIR", "")
	u, err := user.Current()
	if err != nil {
		t.Skipf("no current user: %v", err)
	}
	if got, want := defaultProcessLogDir(), UserLogDir(u.Username); got != want {
		t.Errorf("defaultProcessLogDir() = %q, want %q", got, want)
	}
}

func dirStat(t *testing.T, p string) (os.FileMode, uint32) {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("no unix ownership on this platform")
	}
	return fi.Mode(), st.Uid
}

// The directory is created mode 0700 and owned by the box user; the root it
// lives in is created sticky and world-writable, like /tmp, so every box user
// can make its own directory there and none can remove another's.
func TestEnsureLogDir_Creates0700OwnedByTheUser(t *testing.T) {
	root := filepath.Join(t.TempDir(), "agent-box")
	dir := filepath.Join(root, "alice")
	if err := EnsureLogDir(dir); err != nil {
		t.Fatalf("EnsureLogDir: %v", err)
	}
	mode, uid := dirStat(t, dir)
	if !mode.IsDir() || mode.Perm() != 0o700 {
		t.Errorf("run directory mode = %v, want drwx------", mode)
	}
	if int(uid) != os.Getuid() {
		t.Errorf("run directory owner = %d, want %d", uid, os.Getuid())
	}
	rmode, _ := dirStat(t, root)
	if rmode.Perm() != 0o777 || rmode&os.ModeSticky == 0 {
		t.Errorf("root mode = %v, want sticky 0777", rmode)
	}
}

// A directory the user already owns but left readable to others is closed.
func TestEnsureLogDir_TightensAWiderMode(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "alice")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := EnsureLogDir(dir); err != nil {
		t.Fatalf("EnsureLogDir: %v", err)
	}
	if mode, _ := dirStat(t, dir); mode.Perm() != 0o700 {
		t.Errorf("mode = %v, want 0700", mode)
	}
}

// A symlink planted at the run directory's path is refused, never followed.
func TestEnsureLogDir_RefusesASymlink(t *testing.T) {
	target := t.TempDir()
	if err := os.Chmod(target, 0o755); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "alice")
	if err := os.Symlink(target, dir); err != nil {
		t.Fatal(err)
	}
	err := EnsureLogDir(dir)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("EnsureLogDir over a symlink = %v, want a symlink refusal", err)
	}
	if mode, _ := dirStat(t, target); mode.Perm() != 0o755 {
		t.Errorf("the symlink's target was changed to %v", mode)
	}
}

// A symlink planted at the root is refused too: the per-user directory would
// otherwise be created wherever it points.
func TestEnsureLogDir_RefusesASymlinkedRoot(t *testing.T) {
	target := t.TempDir()
	root := filepath.Join(t.TempDir(), "agent-box")
	if err := os.Symlink(target, root); err != nil {
		t.Fatal(err)
	}
	err := EnsureLogDir(filepath.Join(root, "alice"))
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("EnsureLogDir under a symlinked root = %v, want a symlink refusal", err)
	}
	if ents, _ := os.ReadDir(target); len(ents) != 0 {
		t.Errorf("a directory was created through the symlinked root: %v", ents)
	}
}

// A directory owned by anyone but the box user is refused: its owner could
// read every log written there.
func TestEnsureLogDir_RefusesAForeignOwner(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "alice")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	err := ensureLogDir(dir, os.Getuid()+1)
	if err == nil || !strings.Contains(err.Error(), "owned by") {
		t.Fatalf("ensureLogDir on another user's directory = %v, want an owner refusal", err)
	}
}

// A regular file at the path is refused, not replaced.
func TestEnsureLogDir_RefusesANonDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "alice")
	if err := os.WriteFile(dir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EnsureLogDir(dir); err == nil {
		t.Fatal("EnsureLogDir over a regular file succeeded")
	}
}

// process_start refuses to write a run's log through a planted symlink.
func TestSpawn_RefusesASymlinkedLogDir(t *testing.T) {
	target := t.TempDir()
	dir := filepath.Join(t.TempDir(), "alice")
	if err := os.Symlink(target, dir); err != nil {
		t.Fatal(err)
	}
	old := processLogDir
	processLogDir = dir
	defer func() { processLogDir = old; waitForReapersForTest() }()

	if mp, err := spawnBackgroundProcess("planted", "true", "", CaptureCombined, "", ""); err == nil {
		t.Fatalf("spawn through a symlinked log directory succeeded: %+v", mp)
	}
	if ents, _ := os.ReadDir(target); len(ents) != 0 {
		t.Errorf("the run wrote through the symlink: %v", ents)
	}
}

// process_start creates the run directory 0700.
func TestSpawn_CreatesThePrivateLogDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "agent-box", "alice")
	old := processLogDir
	processLogDir = dir
	defer func() { processLogDir = old; waitForReapersForTest() }()

	if _, err := spawnBackgroundProcess("private", "true", "", CaptureCombined, "", ""); err != nil {
		t.Fatal(err)
	}
	if mode, _ := dirStat(t, dir); mode.Perm() != 0o700 {
		t.Errorf("run directory mode = %v, want 0700", mode)
	}
}
