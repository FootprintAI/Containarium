package container

import (
	"fmt"

	"github.com/footprintai/containarium/pkg/core/toolchain"
)

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
	if !toolchain.Available(root) {
		return fmt.Errorf("missing managed toolchain mount %s: install the host toolchain release first", toolchain.HostRoot)
	}
	name := username + "-container"
	if err := m.incus.EnsureToolchainVolume(name, root); err != nil {
		return err
	}
	return m.incus.Exec(name, []string{"sh", "-c", toolchain.SetupScript()})
}
