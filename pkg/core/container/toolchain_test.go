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
