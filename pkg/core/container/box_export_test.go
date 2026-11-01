package container

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/lxc/incus/v7/shared/api"

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

// The manager is also the backup core's BoxRestoreOps (#3357): it reads a
// box's state, imports through the Incus seam onto the pool the archive
// names, renames and deletes.
var _ backup.BoxRestoreOps = (*Manager)(nil)

func TestManager_BoxRestoreOps(t *testing.T) {
	backend := incustest.NewMockBackend()
	backend.Containers["up-container"] = &incus.ContainerInfo{Name: "up-container", State: "Running"}
	backend.Containers["frozen-container"] = &incus.ContainerInfo{Name: "frozen-container", State: "Frozen"}
	backend.Containers["down-container"] = &incus.ContainerInfo{Name: "down-container", State: "Stopped"}
	m := NewWithBackend(backend)

	for name, want := range map[string]backup.BoxState{
		"up-container": backup.BoxActive, "frozen-container": backup.BoxActive,
		"down-container": backup.BoxStopped, "ghost-container": backup.BoxAbsent,
	} {
		if got, err := m.BoxState(name); err != nil || got != want {
			t.Errorf("BoxState(%s) = %v, %v; want %v", name, got, err, want)
		}
	}
	backend.GetContainerFunc = func(string) (*incus.ContainerInfo, error) {
		return nil, fmt.Errorf("failed to get container: %w", api.StatusErrorf(http.StatusNotFound, "Instance not found"))
	}
	if got, err := m.BoxState("ghost-container"); err != nil || got != backup.BoxAbsent {
		t.Errorf("not-found error: BoxState = %v, %v; want absent", got, err)
	}
	backend.GetContainerFunc = func(string) (*incus.ContainerInfo, error) { return nil, errors.New("socket down") }
	if _, err := m.BoxState("x"); err == nil {
		t.Error("a lookup failure read as a state")
	}
	backend.GetContainerFunc = nil

	pool := "unset"
	backend.ImportInstanceFunc = func(name, p string, r io.Reader, opts incus.ImportOptions) error {
		pool = p
		b, _ := io.ReadAll(r)
		backend.Archives = map[string][]byte{name: b}
		backend.Containers[name] = &incus.ContainerInfo{Name: name, State: "Stopped"}
		return nil
	}
	if err := m.ImportBox("containarium-restore-1", strings.NewReader("tarball")); err != nil {
		t.Fatalf("ImportBox: %v", err)
	}
	if pool != "" || string(backend.Archives["containarium-restore-1"]) != "tarball" {
		t.Errorf("import onto pool %q with %q; want the archive's own pool (empty) and the tarball", pool, backend.Archives["containarium-restore-1"])
	}
	if err := m.RenameBox("containarium-restore-1", "new-container"); err != nil {
		t.Fatalf("RenameBox: %v", err)
	}
	if _, ok := backend.Containers["new-container"]; !ok {
		t.Error("rename did not reach the backend")
	}
	if err := m.DeleteBox("new-container"); err != nil {
		t.Fatalf("DeleteBox: %v", err)
	}
	if _, ok := backend.Containers["new-container"]; ok {
		t.Error("delete did not reach the backend")
	}
}
