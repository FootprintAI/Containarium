package server

import (
	"testing"

	"github.com/footprintai/containarium/internal/cloud"
)

func TestBuildContainerConfig(t *testing.T) {
	cfg := buildContainerConfig(cloud.ContainerSpec{
		LocalName: "cld-abc", Image: "ubuntu:24.04",
		RAMMB: 2048, DiskGB: 40, GPUCount: 1,
	})
	if cfg.Name != "cld-abc" || cfg.Image != "ubuntu:24.04" {
		t.Errorf("name/image wrong: %+v", cfg)
	}
	if cfg.Memory != "2048MB" {
		t.Errorf("memory = %q, want 2048MB", cfg.Memory)
	}
	if cfg.Disk == nil || cfg.Disk.Size != "40GB" || cfg.Disk.Path != "/" || cfg.Disk.Pool != "default" {
		t.Errorf("disk wrong: %+v", cfg.Disk)
	}
	if cfg.GPU == nil {
		t.Error("GPUCount>0 should request GPU passthrough")
	}
}

func TestBuildContainerConfig_MinimalOmitsDevices(t *testing.T) {
	cfg := buildContainerConfig(cloud.ContainerSpec{LocalName: "cld-x", Image: "alpine"})
	if cfg.Memory != "" {
		t.Errorf("no RAM → memory unset, got %q", cfg.Memory)
	}
	if cfg.Disk != nil {
		t.Errorf("no disk → Disk nil, got %+v", cfg.Disk)
	}
	if cfg.GPU != nil {
		t.Errorf("no GPU → GPU nil, got %+v", cfg.GPU)
	}
}
