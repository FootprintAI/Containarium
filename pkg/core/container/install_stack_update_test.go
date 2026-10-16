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
}

func (b *installStackBackend) GetContainer(name string) (*incus.ContainerInfo, error) {
	return &incus.ContainerInfo{Name: name, State: "Running"}, nil
}

func (b *installStackBackend) Exec(_ string, cmd []string) error {
	b.execs = append(b.execs, cmd)
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
