package server

import (
	"fmt"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/agentbox"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// The daemon's run directory is per box user (#3682): the owner's runs in
// <root>/<owner>, the unprivileged run user's in <root>/<run user>, and the
// shared root itself is never read or written as a run directory.
func TestBoxRunDir_IsPerUser(t *testing.T) {
	s := &ContainerServer{}
	if got := s.boxRunDir("alice"); got != "/tmp/agent-box/alice" {
		t.Errorf("boxRunDir(alice) = %q, want /tmp/agent-box/alice", got)
	}
	want := []string{"/tmp/agent-box/alice", "/tmp/agent-box/" + boxRunUnprivilegedUser}
	if got := s.boxRunDirs("alice"); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("boxRunDirs(alice) = %v, want %v", got, want)
	}
	for _, d := range s.boxRunDirs("alice") {
		if d == agentbox.LogRoot {
			t.Errorf("the shared root %s is still a run directory", d)
		}
	}
}

// Every daemon reader lists the box user's own directories, not the shared root.
func TestListBoxRuns_ReadsThePerUserDirectories(t *testing.T) {
	var mu sync.Mutex
	var scripts []string
	s := &ContainerServer{boxRunExec: func(box, script string) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		scripts = append(scripts, script)
		return "", nil
	}}
	if _, err := s.ListBoxRuns(tenantCtx("alice"), &pb.ListBoxRunsRequest{Username: "alice"}); err != nil {
		t.Fatal(err)
	}
	if len(scripts) != 1 {
		t.Fatalf("scripts = %d, want 1", len(scripts))
	}
	for _, want := range []string{"'/tmp/agent-box/alice'", "'/tmp/agent-box/" + boxRunUnprivilegedUser + "'"} {
		if !strings.Contains(scripts[0], want) {
			t.Errorf("list script does not read %s:\n%s", want, scripts[0])
		}
	}
	if strings.Contains(scripts[0], "'/tmp/agent-box'") {
		t.Errorf("list script still reads the shared root:\n%s", scripts[0])
	}
}

// One list read covers several directories, and each run is reported under the
// directory it is in.
func TestBoxRunListScript_ReadsEveryDirectory(t *testing.T) {
	owner, runUser := t.TempDir(), t.TempDir()
	t0 := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	code := 0
	writeRecord(t, owner, recordSpec{name: "mine", pid: 1, boot: "b", started: t0, exitCode: &code})
	writeRecord(t, runUser, recordSpec{name: "theirs", pid: 1, boot: "b", started: t0.Add(time.Minute), exitCode: &code})
	out, err := osexec.Command("sh", "-c", boxRunListScript(owner, runUser)).Output()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range parseBoxRunList(string(out), owner) {
		got[r.GetRunName()] = r.GetLogPath()
	}
	want := map[string]string{"mine": owner + "/mine.log", "theirs": runUser + "/theirs.log"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("runs = %v, want %v", got, want)
	}
}

// A record file whose name carries a newline cannot forge a "D" line and move
// the records after it into another directory.
func TestBoxRunListScript_ANewlineNameCannotForgeADirectory(t *testing.T) {
	dir := t.TempDir()
	t0 := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	code := 0
	writeRecord(t, dir, recordSpec{name: "real", pid: 1, boot: "b", started: t0, exitCode: &code})
	// Listed before real.json, so an unguarded forgery would move real into
	// "elsewhere".
	writeFile(t, filepath.Join(dir, "a\nD elsewhere\nzz.json"), "{}")
	out, err := osexec.Command("sh", "-c", boxRunListScript(dir)).Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "D elsewhere") {
		t.Fatalf("a file name forged a directory line:\n%s", out)
	}
	runs := parseBoxRunList(string(out), dir)
	if len(runs) != 1 || runs[0].GetLogPath() != dir+"/real.log" {
		t.Errorf("runs = %v, want only real in %s", runs, dir)
	}
}

// A finished run in another user's directory is rotated aside as root: the new
// run's user cannot write there.
func TestBoxRunRotateAsRoot(t *testing.T) {
	for _, tc := range []struct {
		level, dir, collisionDir string
		want                     bool
	}{
		{"", "/tmp/agent-box/alice", "/tmp/agent-box/alice", false},
		{"", "/tmp/agent-box/alice", "/tmp/agent-box/" + boxRunUnprivilegedUser, true},
		{"read_only", "/tmp/agent-box/" + boxRunUnprivilegedUser, "/tmp/agent-box/alice", true},
		{"read_only", "/tmp/agent-box/" + boxRunUnprivilegedUser, "/tmp/agent-box/" + boxRunUnprivilegedUser, true},
	} {
		if got := boxRunRotateAsRoot(tc.level, tc.dir, tc.collisionDir); got != tc.want {
			t.Errorf("boxRunRotateAsRoot(%q, %q, %q) = %v, want %v", tc.level, tc.dir, tc.collisionDir, got, tc.want)
		}
	}
}

// The root-run preparation for an unprivileged run makes the run directory's
// root sticky and world-writable, creates no run directory itself, and refuses
// a symlinked root.
func TestBoxRunDirScript_PreparesOnlyTheRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "agent-box")
	dir := filepath.Join(root, boxRunUnprivilegedUser)
	if out, err := osexec.Command("sh", "-c", boxRunDirScript(dir)).CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if rmode, _ := statDir(t, root); rmode.Perm() != 0o777 || rmode&os.ModeSticky == 0 {
		t.Errorf("root mode = %v, want sticky 0777", rmode)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Errorf("root created the run user's directory itself: %v", err)
	}

	target := t.TempDir()
	linked := filepath.Join(t.TempDir(), "agent-box")
	if err := os.Symlink(target, linked); err != nil {
		t.Fatal(err)
	}
	if out, err := osexec.Command("sh", "-c", boxRunDirScript(filepath.Join(linked, "u"))).CombinedOutput(); err == nil || !strings.Contains(string(out), "symlink") {
		t.Errorf("a symlinked root was not refused: err=%v out=%q", err, out)
	}
}

func runEnsure(t *testing.T, dir, prelude string) (string, error) {
	t.Helper()
	out, err := osexec.Command("sh", "-c", prelude+"set -e\n"+boxRunEnsureDirScript(dir)).CombinedOutput()
	return string(out), err
}

func statDir(t *testing.T, p string) (os.FileMode, uint32) {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode(), fi.Sys().(*syscall.Stat_t).Uid
}

// The run's own shell creates its directory 0700, owned by the user it runs as,
// and the root sticky and world-writable when it has to create it.
func TestBoxRunEnsureDirScript_Creates0700(t *testing.T) {
	root := filepath.Join(t.TempDir(), "agent-box")
	dir := filepath.Join(root, "alice")
	if out, err := runEnsure(t, dir, ""); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mode, uid := statDir(t, dir)
	if !mode.IsDir() || mode.Perm() != 0o700 || int(uid) != os.Getuid() {
		t.Errorf("run directory = %v owned by %d, want drwx------ owned by %d", mode, uid, os.Getuid())
	}
	if rmode, _ := statDir(t, root); rmode.Perm() != 0o777 || rmode&os.ModeSticky == 0 {
		t.Errorf("root mode = %v, want sticky 0777", rmode)
	}

	// An existing directory left open to others is closed again.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := runEnsure(t, dir, ""); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if mode, _ := statDir(t, dir); mode.Perm() != 0o700 {
		t.Errorf("mode = %v, want 0700", mode)
	}
}

// A symlink planted at the run directory is refused, and its target untouched.
func TestBoxRunEnsureDirScript_RefusesASymlink(t *testing.T) {
	target := t.TempDir()
	if err := os.Chmod(target, 0o755); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "alice")
	if err := os.Symlink(target, dir); err != nil {
		t.Fatal(err)
	}
	out, err := runEnsure(t, dir, "")
	if err == nil || !strings.Contains(out, "symlink") {
		t.Fatalf("ensure over a symlink: err=%v out=%q, want a symlink refusal", err, out)
	}
	if mode, _ := statDir(t, target); mode.Perm() != 0o755 {
		t.Errorf("the symlink's target was changed to %v", mode)
	}
}

// A symlinked root is refused before anything is created through it.
func TestBoxRunEnsureDirScript_RefusesASymlinkedRoot(t *testing.T) {
	target := t.TempDir()
	root := filepath.Join(t.TempDir(), "agent-box")
	if err := os.Symlink(target, root); err != nil {
		t.Fatal(err)
	}
	out, err := runEnsure(t, filepath.Join(root, "alice"), "")
	if err == nil || !strings.Contains(out, "symlink") {
		t.Fatalf("ensure under a symlinked root: err=%v out=%q, want a symlink refusal", err, out)
	}
	if ents, _ := os.ReadDir(target); len(ents) != 0 {
		t.Errorf("created through the symlinked root: %v", ents)
	}
}

// A directory owned by another user is refused. The test cannot chown, so the
// script's own `id -u` is made to answer as a different user.
func TestBoxRunEnsureDirScript_RefusesAForeignOwner(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "alice")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	prelude := fmt.Sprintf("id() { case \"$1\" in -u) echo %d;; *) echo someone-else;; esac; }\n", os.Getuid()+1)
	out, err := runEnsure(t, dir, prelude)
	if err == nil || !strings.Contains(out, "owned by") {
		t.Fatalf("ensure on a foreign directory: err=%v out=%q, want an owner refusal", err, out)
	}
}

// The run's launch refuses a planted symlink at its run directory instead of
// writing its log through it.
func TestBoxRunSpawnPrepareScript_RefusesASymlinkedDir(t *testing.T) {
	target := t.TempDir()
	dir := filepath.Join(t.TempDir(), "alice")
	if err := os.Symlink(target, dir); err != nil {
		t.Fatal(err)
	}
	script := boxRunSpawnPrepareScript(boxRunSpawn{dir: dir, name: "code", command: "true", home: t.TempDir()})
	if out, err := osexec.Command("sh", "-c", script).CombinedOutput(); err == nil {
		t.Fatalf("prepare through a symlinked run directory succeeded:\n%s", out)
	}
	if ents, _ := os.ReadDir(target); len(ents) != 0 {
		t.Errorf("the prepare wrote through the symlink: %v", ents)
	}
}

// The notify service reads each user's journal from that user's directory.
func TestNotifyServer_ReadsThePerUserDirectory(t *testing.T) {
	s := NewNotifyServer(nil, nil, nil, "", nil)
	if got := s.runDir("alice"); got != "/tmp/agent-box/alice" {
		t.Errorf("runDir(alice) = %q, want /tmp/agent-box/alice", got)
	}
	if got := notifyJournalScript(s.runDir("alice")); !strings.Contains(got, "'/tmp/agent-box/alice'") {
		t.Errorf("journal script does not read alice's directory:\n%s", got)
	}
}
