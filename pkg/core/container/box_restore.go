package container

import (
	"fmt"
	"io"

	"github.com/footprintai/containarium/pkg/core/backup"
	"github.com/footprintai/containarium/pkg/core/incus"
)

// Whole-box restore (#3357): the container layer's half of
// backup.BoxRestoreOps. Names are Incus instance names.

// BoxState reports whether the instance exists and whether it is stopped.
// Anything but Stopped (Running, Frozen, a transition) is active: a restore
// never replaces it.
func (m *Manager) BoxState(containerName string) (backup.BoxState, error) {
	info, err := m.incus.GetContainer(containerName)
	if err != nil {
		if incus.IsNotFound(err) {
			return backup.BoxAbsent, nil
		}
		return backup.BoxAbsent, fmt.Errorf("state of %s: %w", containerName, err)
	}
	if info == nil {
		return backup.BoxAbsent, nil
	}
	if info.State == "Stopped" {
		return backup.BoxStopped, nil
	}
	return backup.BoxActive, nil
}

// ImportBox creates a new, stopped instance from an Incus backup tarball
// through the export/import seam. No pool is named, so Incus places the box
// on the pool its archived config records (falling back to the default
// profile's pool when that one does not exist): a restore keeps the box
// where it was, including a tenant's own pool.
func (m *Manager) ImportBox(containerName string, archive io.Reader) error {
	return m.incus.ImportInstance(containerName, "", archive, incus.ImportOptions{})
}

// RenameBox renames a stopped instance.
func (m *Manager) RenameBox(from, to string) error {
	return m.incus.RenameInstance(from, to)
}

// DeleteBox deletes a stopped instance.
func (m *Manager) DeleteBox(containerName string) error {
	return m.incus.DeleteContainer(containerName)
}
