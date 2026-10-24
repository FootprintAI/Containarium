package cmd

import (
	"strings"
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// `containarium info` prints one line per storage pool and flags the ones
// past a threshold (#2823).
func TestRenderStoragePools(t *testing.T) {
	if got := renderStoragePools(nil); got != "" {
		t.Fatalf("no pools: want empty, got %q", got)
	}
	out := renderStoragePools([]incus.StoragePoolCapacity{
		{StoragePoolUsage: incus.StoragePoolUsage{Name: "p1", Driver: "zfs", UsedBytes: 96 << 30, TotalBytes: 100 << 30}, Level: incus.StoragePoolLevelCritical},
		{StoragePoolUsage: incus.StoragePoolUsage{Name: "p2", Driver: "dir", UsedBytes: 10 << 30, TotalBytes: 100 << 30}, Level: incus.StoragePoolLevelOK},
	})
	for _, needle := range []string{
		"Storage Pools:",
		"p1",
		"96.0% of 100.0 GiB (zfs)",
		"CRITICAL",
		"p2",
		"10.0% of 100.0 GiB (dir)",
	} {
		if !strings.Contains(out, needle) {
			t.Errorf("output lacks %q:\n%s", needle, out)
		}
	}
	if strings.Count(out, "WARNING")+strings.Count(out, "CRITICAL") != 1 {
		t.Errorf("only the critical pool should be flagged:\n%s", out)
	}
}
