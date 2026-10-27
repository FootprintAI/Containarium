package container

import (
	"strings"
	"testing"
	"time"

	incusapi "github.com/lxc/incus/v7/shared/api"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// vmStagesBackend extends the stages fake with the one extra call the
// non-baked (VM) path makes: installPackages probes cloud-init through
// ExecWithExitCode. Exit 0 = present, so the (shortened) cloud-init wait
// path runs too.
type vmStagesBackend struct {
	*stagesBackend
}

func (b *vmStagesBackend) ExecWithExitCode(string, []string) (string, string, int, error) {
	return "", "", 0, nil
}

// TestCreate_IsolationVM_CreatesLinuxVM drives Create end to end against
// the stages fake and asserts what reaches Incus for a Linux VM request:
// instance type VM, the /cloud image variant, nesting and privileged
// podman forced off, and the baked-image fast path (a container image)
// not taken.
func TestCreate_IsolationVM_CreatesLinuxVM(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	b := &vmStagesBackend{stagesBackend: &stagesBackend{}}
	m := NewWithBackend(b)
	m.cloudInitWait = time.Millisecond

	opts := stagesOpts()
	opts.OSType = pb.OSType_OS_TYPE_UBUNTU_2404
	opts.Isolation = pb.IsolationType_ISOLATION_TYPE_VM
	opts.EnablePodman = true
	opts.EnablePodmanPrivileged = true

	if _, err := m.Create(opts); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got := b.createdConfig
	if got.InstanceType != incusapi.InstanceTypeVM {
		t.Errorf("InstanceType = %q, want %q", got.InstanceType, incusapi.InstanceTypeVM)
	}
	if got.Image != "images:ubuntu/24.04/cloud" {
		t.Errorf("Image = %q, want the /cloud VM variant", got.Image)
	}
	if got.EnableNesting || got.EnablePodmanPrivileged {
		t.Errorf("nesting=%v privileged=%v: both must be off for a VM", got.EnableNesting, got.EnablePodmanPrivileged)
	}
	if got.Image == BakedImageAliasFor("images:ubuntu/24.04") {
		t.Errorf("Image = %q: the baked-image (container) fast path must not apply to a VM", got.Image)
	}
}

// TestCreate_IsolationUnspecified_KeepsContainer is the regression guard:
// a request that says nothing about isolation still produces a container
// from the plain image, exactly as before #2196.
func TestCreate_IsolationUnspecified_KeepsContainer(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	b := &stagesBackend{}
	m := NewWithBackend(b)

	if _, err := m.Create(stagesOpts()); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if b.createdConfig.InstanceType != "" && b.createdConfig.InstanceType != incusapi.InstanceTypeContainer {
		t.Errorf("InstanceType = %q, want container/default", b.createdConfig.InstanceType)
	}
	if strings.Contains(b.createdConfig.Image, "/cloud") {
		t.Errorf("Image = %q: container create must not pick the VM image variant", b.createdConfig.Image)
	}
}

// TestCreate_WindowsContainer_Rejected: Windows can only be a VM, and the
// refusal happens before anything is created.
func TestCreate_WindowsContainer_Rejected(t *testing.T) {
	b := &stagesBackend{}
	m := NewWithBackend(b)

	opts := stagesOpts()
	opts.OSType = pb.OSType_OS_TYPE_WINDOWS_2022
	opts.Isolation = pb.IsolationType_ISOLATION_TYPE_CONTAINER

	if _, err := m.Create(opts); err == nil {
		t.Fatal("Create: want an error for windows+container, got nil")
	}
	if b.createdConfig.Name != "" {
		t.Errorf("CreateContainer was called (%q) despite the invalid combination", b.createdConfig.Name)
	}
}
