package container

import (
	"errors"
	"fmt"
	"os"

	"github.com/footprintai/containarium/pkg/core/toolchain"
)

// ErrManagedToolchainHostMissing means the operator has not installed the
// managed toolchain release on this host. Callers may use errors.Is to
// distinguish this refusal from attach or setup failures.
var ErrManagedToolchainHostMissing = errors.New("host managed toolchain missing")

func (m *Manager) managedToolchainRoot() string {
	if m.toolchainRoot != "" {
		return m.toolchainRoot
	}
	return toolchain.HostRoot
}

// EnsureManagedToolchains lazily equips an existing box. No software is
// downloaded by a run: the operator must first install a host release.
func (m *Manager) EnsureManagedToolchains(username string) error {
	root := m.managedToolchainRoot()
	if err := toolchain.CheckRelease(root); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: missing managed toolchain mount %s: install the host toolchain release first", ErrManagedToolchainHostMissing, toolchain.HostRoot)
		}
		return err
	}
	name := username + "-container"
	if err := m.incus.EnsureToolchainVolume(name, root); err != nil {
		return err
	}
	return m.incus.Exec(name, []string{"sh", "-c", toolchain.SetupScript()})
}
