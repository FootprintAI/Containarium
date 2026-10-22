package container

import (
	"errors"
	"strings"
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// installStackBackend records every Exec. Detection probes (powershell,
// redhat-release) fail so the box reads as Debian family.
type installStackBackend struct {
	incus.Backend
	execs [][]string
	// installErr, when set, fails the package-install Exec (apt-get install).
	installErr error
	config     map[string]string // SetConfig writes, by key
}

func (b *installStackBackend) SetConfig(_, key, value string) error {
	if b.config == nil {
		b.config = map[string]string{}
	}
	b.config[key] = value
	return nil
}

func (b *installStackBackend) GetContainer(name string) (*incus.ContainerInfo, error) {
	return &incus.ContainerInfo{Name: name, State: "Running"}, nil
}

func (b *installStackBackend) Exec(_ string, cmd []string) error {
	b.execs = append(b.execs, cmd)
	if b.installErr != nil && len(cmd) > 1 && cmd[0] == "apt-get" && cmd[1] == "install" {
		return b.installErr
	}
	if cmd[0] == "powershell" || (cmd[0] == "test" && len(cmd) > 2 && strings.Contains(cmd[2], "redhat-release")) {
		return errors.New("not this family")
	}
	return nil
}

func (b *installStackBackend) ran(prefix ...string) bool {
	for _, c := range b.execs {
		if len(c) >= len(prefix) && strings.Join(c[:len(prefix)], " ") == strings.Join(prefix, " ") {
			return true
		}
	}
	return false
}

// #2617: the startup base-script reconcile ran a package-index update in
// every running container although the script installs nothing. A base
// script with no packages must skip it; a dev stack still updates first.
func TestInstallStack_PackageIndexUpdate(t *testing.T) {
	t.Run("base script with no packages does not update the index", func(t *testing.T) {
		b := &installStackBackend{}
		if err := NewWithBackend(b).InstallStack("alice", "ntp"); err != nil {
			t.Fatalf("InstallStack: %v", err)
		}
		if b.ran("apt-get", "update") {
			t.Error("apt-get update ran for a base script that installs no packages")
		}
		if !b.ran("bash", "-c", "timedatectl set-timezone Asia/Taipei") {
			t.Errorf("the script's own pre-install step did not run: %v", b.execs)
		}
	})
	t.Run("dev stack still updates the index before installing", func(t *testing.T) {
		b := &installStackBackend{}
		if err := NewWithBackend(b).InstallStack("alice", "nodejs"); err != nil {
			t.Fatalf("InstallStack: %v", err)
		}
		if !b.ran("apt-get", "update") {
			t.Error("a stack with packages must update the index first")
		}
		if !b.ran("apt-get", "install", "-y") {
			t.Errorf("packages were not installed: %v", b.execs)
		}
	})
}

// #2859: a successful dev-stack install records the stack so list/get report
// it. The model is single-valued (Container.stack is one string, "the stack
// installed"), so a second stack REPLACES the first. Base scripts (the startup
// timezone reconcile runs one in every box) are not stacks and never touch it;
// a failed install leaves it alone.
func TestInstallStack_RecordsStoredStack(t *testing.T) {
	t.Run("success records the stack", func(t *testing.T) {
		b := &installStackBackend{}
		if err := NewWithBackend(b).InstallStack("alice", "nodejs"); err != nil {
			t.Fatalf("InstallStack: %v", err)
		}
		if got := b.config[incus.StackKey]; got != "nodejs" {
			t.Errorf("%s = %q, want nodejs", incus.StackKey, got)
		}
	})
	t.Run("a second stack replaces the first", func(t *testing.T) {
		b := &installStackBackend{}
		m := NewWithBackend(b)
		for _, id := range []string{"nodejs", "python"} {
			if err := m.InstallStack("alice", id); err != nil {
				t.Fatalf("InstallStack(%s): %v", id, err)
			}
		}
		if got := b.config[incus.StackKey]; got != "python" {
			t.Errorf("%s = %q, want python (latest)", incus.StackKey, got)
		}
	})
	t.Run("a base script does not touch it", func(t *testing.T) {
		b := &installStackBackend{}
		if err := NewWithBackend(b).InstallStack("alice", "ntp"); err != nil {
			t.Fatalf("InstallStack: %v", err)
		}
		if v, ok := b.config[incus.StackKey]; ok {
			t.Errorf("%s was written (%q) by a base script", incus.StackKey, v)
		}
	})
	t.Run("a failed install does not record", func(t *testing.T) {
		b := &installStackBackend{installErr: errors.New("boom")}
		if err := NewWithBackend(b).InstallStack("alice", "nodejs"); err == nil {
			t.Fatal("InstallStack should fail when the package install fails")
		}
		if v, ok := b.config[incus.StackKey]; ok {
			t.Errorf("%s was written (%q) despite the failure", incus.StackKey, v)
		}
	})
}
