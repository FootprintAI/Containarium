package cluster

import (
	"testing"

	"github.com/lxc/incus/v6/shared/api"
)

// The Incus config a cluster node is created from. Pure, so the parts
// Incus validates before it will create anything are testable without a
// real host — which is where #1435 hid: a root disk carrying only a
// size is rejected with `Disk entry is missing the required "source" or
// "path" property`, so no node of either isolation class was ever
// created.
func TestNodeContainerConfig(t *testing.T) {
	spec := NodeSpec{Name: "t-k8s-c-small-1", CPU: "2", Memory: "4GB", Disk: "40GB"}

	tests := []struct {
		name         string
		spec         NodeSpec
		isolation    Isolation
		wantType     api.InstanceType
		wantNesting  bool
		wantDisk     bool
		wantDiskSize string
	}{
		{
			name:         "vm node",
			spec:         spec,
			isolation:    IsolationVM,
			wantType:     api.InstanceTypeVM,
			wantDisk:     true,
			wantDiskSize: "40GB",
		},
		{
			name:         "container node carries the container profile",
			spec:         spec,
			isolation:    IsolationContainer,
			wantType:     api.InstanceTypeContainer,
			wantNesting:  true,
			wantDisk:     true,
			wantDiskSize: "40GB",
		},
		{
			name:      "no disk size means no root device, not an empty one",
			spec:      NodeSpec{Name: "t-k8s-c-small-1", CPU: "2", Memory: "4GB"},
			isolation: IsolationVM,
			wantType:  api.InstanceTypeVM,
			wantDisk:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := nodeContainerConfig(tt.spec, tt.isolation, "poolname")

			if cfg.Name != tt.spec.Name {
				t.Fatalf("Name = %q, want %q", cfg.Name, tt.spec.Name)
			}
			if cfg.InstanceType != tt.wantType {
				t.Fatalf("InstanceType = %q, want %q", cfg.InstanceType, tt.wantType)
			}
			if got := cfg.ExtraConfig["security.nesting"] == "true"; got != tt.wantNesting {
				t.Fatalf("security.nesting = %v, want %v", got, tt.wantNesting)
			}
			if !tt.wantDisk {
				if cfg.Disk != nil {
					t.Fatalf("Disk = %+v, want none", cfg.Disk)
				}
				return
			}
			if cfg.Disk == nil {
				t.Fatal("Disk is nil, want a root device")
			}
			// The three properties Incus validates. A device with only a
			// size is refused, and the refusal happens at instance
			// creation — minutes into a provisioning loop, not here.
			if cfg.Disk.Path != "/" {
				t.Fatalf("Disk.Path = %q, want %q — Incus rejects a root disk with no path", cfg.Disk.Path, "/")
			}
			if cfg.Disk.Pool != "poolname" {
				t.Fatalf("Disk.Pool = %q, want the host's resolved pool", cfg.Disk.Pool)
			}
			if cfg.Disk.Size != tt.wantDiskSize {
				t.Fatalf("Disk.Size = %q, want %q", cfg.Disk.Size, tt.wantDiskSize)
			}
		})
	}
}
