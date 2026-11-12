package hosting

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"syscall"
	"testing"
)

// The Caddy home is chowned with -h so that a symlink planted in the tree is
// never followed. Host and container both use CaddyHomeChownArgs (#3669).
func TestCaddyHomeChownArgsAreNoFollow(t *testing.T) {
	want := []string{"chown", "-R", "-h", "caddy:caddy", "/var/lib/caddy"}
	if got := CaddyHomeChownArgs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("CaddyHomeChownArgs() = %v, want %v", got, want)
	}
}

// Root-only: a symlink planted in the tree must not carry the chown to its
// target. The target is root-owned before the run and must stay root-owned.
func TestCaddyHomeChownDoesNotFollowPlantedSymlink(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to observe an ownership change")
	}
	tree := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(outside, "target")
	if err := os.WriteFile(target, []byte("root"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(tree, "planted")); err != nil {
		t.Fatal(err)
	}

	args := caddyHomeChownArgs(tree, "65534:65534")
	if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
		t.Fatalf("chown: %v\n%s", err, out)
	}

	fi, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if uid := fi.Sys().(*syscall.Stat_t).Uid; uid != 0 {
		t.Errorf("symlink target owner = %s, want 0 (chown must not follow the link)", strconv.Itoa(int(uid)))
	}
}
