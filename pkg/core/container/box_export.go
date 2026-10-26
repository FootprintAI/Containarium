package container

import (
	"fmt"
	"io"
)

// Whole-box backup (#2801): the container layer's half of backup.BoxOps.

// ExportInstance streams the instance as an Incus backup tarball through
// the backend's export seam. The caller closes the reader.
func (m *Manager) ExportInstance(containerName string) (io.ReadCloser, error) {
	return m.incus.ExportInstance(containerName)
}

// BoxDiskUsage reports the bytes the instance's root disk uses, from its
// metrics. Zero means the backend did not report it.
func (m *Manager) BoxDiskUsage(containerName string) (int64, error) {
	metrics, err := m.incus.GetContainerMetrics(containerName)
	if err != nil {
		return 0, fmt.Errorf("metrics for %s: %w", containerName, err)
	}
	if metrics == nil {
		return 0, nil
	}
	return metrics.DiskUsageBytes, nil
}
