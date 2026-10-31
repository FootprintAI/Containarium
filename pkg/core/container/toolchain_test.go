package container

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus/incustest"
)

func TestManagedToolchainsLazyAttach(t *testing.T) {
	root := t.TempDir()
	attached, checked := false, false
	b := &incustest.MockBackend{
		EnsureToolchainVolumeFunc: func(name, source string) error {
			attached = name == "alice-container" && source == root
			return nil
		},
		ExecFunc: func(name string, args []string) error {
			checked = attached && strings.Contains(args[2], "/proc/mounts") && strings.Contains(args[2], "/usr/local/bin")
			return nil
		},
	}
	m := NewWithBackend(b)
	m.toolchainRoot = root
	if err := m.EnsureManagedToolchains("alice"); err == nil || attached {
		t.Fatalf("missing release: attached=%v err=%v", attached, err)
	}
	if err := os.MkdirAll(filepath.Join(root, "current"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "current/manifest.json"), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := m.EnsureManagedToolchains("alice"); err != nil || !checked {
		t.Fatalf("lazy attach: checked=%v err=%v", checked, err)
	}
	b.EnsureToolchainVolumeFunc = func(string, string) error { return errors.New("attach failed") }
	checked = false
	if err := m.EnsureManagedToolchains("alice"); err == nil || checked {
		t.Fatalf("attach failure must stop setup: %v", err)
	}
}

func TestManagedToolchainsClassifiesManifestStatFailures(t *testing.T) {
	root := t.TempDir()
	m := NewWithBackend(&incustest.MockBackend{})
	m.toolchainRoot = root
	if err := m.EnsureManagedToolchains("alice"); !errors.Is(err, ErrManagedToolchainHostMissing) {
		t.Fatalf("missing manifest error = %v, want ErrManagedToolchainHostMissing", err)
	}

	if err := os.Mkdir(filepath.Join(root, "current"), 0755); err != nil {
		t.Fatal(err)
	}
	// A directory at manifest.json is present but malformed, so it must not
	// be confused with an absent release.
	if err := os.Mkdir(filepath.Join(root, "current", "manifest.json"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := m.EnsureManagedToolchains("alice"); err == nil || errors.Is(err, ErrManagedToolchainHostMissing) {
		t.Fatalf("non-regular manifest error = %v, want generic error", err)
	}
}

func TestManagedToolchainsStatErrorIsNotMissingRelease(t *testing.T) {
	root := t.TempDir()
	if err := os.Symlink(filepath.Join(root, "current"), filepath.Join(root, "current")); err != nil {
		t.Skipf("cannot create symlink for stat error case: %v", err)
	}
	m := NewWithBackend(&incustest.MockBackend{})
	m.toolchainRoot = root
	err := m.EnsureManagedToolchains("alice")
	if err == nil || errors.Is(err, ErrManagedToolchainHostMissing) {
		t.Fatalf("stat error = %v, want generic error", err)
	}
}

func TestManagedToolchainsDanglingManifestSymlinkIsNotMissingRelease(t *testing.T) {
	root := t.TempDir()
	current := filepath.Join(root, "current")
	if err := os.Mkdir(current, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "missing-target"), filepath.Join(current, "manifest.json")); err != nil {
		t.Skipf("cannot create symlink for dangling manifest case: %v", err)
	}
	m := NewWithBackend(&incustest.MockBackend{})
	m.toolchainRoot = root
	err := m.EnsureManagedToolchains("alice")
	if err == nil || errors.Is(err, ErrManagedToolchainHostMissing) {
		t.Fatalf("dangling manifest error = %v, want generic error", err)
	}
}

func TestManagedToolchainsAttachedAtCreate(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "current"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "current/manifest.json"), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	b := &stagesBackend{}
	m := NewWithBackend(b)
	m.toolchainRoot = root
	t.Setenv("HOME", t.TempDir())
	if _, err := m.Create(stagesOpts()); err != nil {
		t.Fatal(err)
	}
	if b.createdConfig.ManagedToolchainRoot != root {
		t.Fatalf("created without managed volume: %+v", b.createdConfig)
	}
}

type conflictingToolchainBackend struct{ *stagesBackend }

func (b *conflictingToolchainBackend) Exec(_ string, args []string) error {
	if len(args) == 3 && strings.Contains(args[2], "/proc/mounts") {
		return errors.New("managed tool conflicts with pnpm")
	}
	return nil
}

// The nodejs stack installs its own pnpm. Mounting a host release must not
// make that box impossible to create at NONE/FULL_SUDO; BUILD_TOOLS validates
// the links again and refuses the run until the operator resolves the conflict.
func TestManagedToolchainConflictDoesNotFailCreate(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "current"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "current/manifest.json"), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	b := &conflictingToolchainBackend{stagesBackend: &stagesBackend{}}
	m := NewWithBackend(b)
	m.toolchainRoot = root
	t.Setenv("HOME", t.TempDir())
	if _, err := m.Create(stagesOpts()); err != nil {
		t.Fatalf("optional tools must not break box creation: %v", err)
	}
}
