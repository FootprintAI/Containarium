package container

import (
	"errors"
	"io"
	"testing"

	"github.com/footprintai/containarium/pkg/core/backup"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/incus/incustest"
)

// The manager is the backup core's BoxOps (#2801): it exports through the
// Incus seam and sizes the box from its metrics.
var _ backup.BoxOps = (*Manager)(nil)

func TestManager_BoxOps(t *testing.T) {
	backend := incustest.NewMockBackend()
	backend.Containers["alice-container"] = &incus.ContainerInfo{Name: "alice-container", State: "Running"}
	backend.Archives = map[string][]byte{"alice-container": []byte("tarball")}
	backend.GetContainerMetricsFunc = func(name string) (*incus.ContainerMetrics, error) {
		if name != "alice-container" {
			return nil, errors.New("unexpected " + name)
		}
		return &incus.ContainerMetrics{Name: name, DiskUsageBytes: 4096}, nil
	}
	m := NewWithBackend(backend)

	rc, err := m.ExportInstance("alice-container")
	if err != nil {
		t.Fatalf("ExportInstance: %v", err)
	}
	b, _ := io.ReadAll(rc)
	_ = rc.Close()
	if string(b) != "tarball" {
		t.Errorf("export = %q", b)
	}
	if _, err := m.ExportInstance("ghost-container"); err == nil {
		t.Error("export of a missing box succeeded")
	}

	if n, err := m.BoxDiskUsage("alice-container"); err != nil || n != 4096 {
		t.Errorf("BoxDiskUsage = %d, %v; want 4096", n, err)
	}
	backend.GetContainerMetricsFunc = func(string) (*incus.ContainerMetrics, error) { return nil, nil }
	if n, err := m.BoxDiskUsage("alice-container"); err != nil || n != 0 {
		t.Errorf("no metrics: BoxDiskUsage = %d, %v; want 0 (unknown), nil", n, err)
	}
	backend.GetContainerMetricsFunc = func(string) (*incus.ContainerMetrics, error) { return nil, errors.New("state down") }
	if _, err := m.BoxDiskUsage("alice-container"); err == nil {
		t.Error("a metrics error was swallowed")
	}
}
