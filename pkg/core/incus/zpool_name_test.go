package incus

import "testing"

// #2853: `zpool list` takes a pool name, never a dataset or a device path, and
// Incus's `source` can be any of the three.
func TestZpoolNameFor(t *testing.T) {
	cases := []struct {
		name   string
		driver string
		config map[string]string
		want   string
	}{
		{"whole pool by zfs.pool_name", "zfs", map[string]string{"zfs.pool_name": "tank", "source": "tank"}, "tank"},
		{"dataset keeps only the pool", "zfs", map[string]string{"zfs.pool_name": "tank/incus", "source": "tank/incus"}, "tank"},
		{"loop-file source: the pool name comes from zfs.pool_name", "zfs", map[string]string{"zfs.pool_name": "default", "source": "/var/lib/incus/disks/default.img"}, "default"},
		{"no zfs.pool_name: a plain source is the pool", "zfs", map[string]string{"source": "tank"}, "tank"},
		{"no zfs.pool_name and a path source: unknown", "zfs", map[string]string{"source": "/dev/sdb"}, ""},
		{"empty config", "zfs", map[string]string{}, ""},
		{"nil config", "zfs", nil, ""},
		{"not zfs", "dir", map[string]string{"source": "/var/lib/incus/storage-pools/default"}, ""},
		{"btrfs", "btrfs", map[string]string{"source": "tank"}, ""},
		{"whitespace trimmed", "zfs", map[string]string{"zfs.pool_name": " tank/incus "}, "tank"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ZpoolNameFor(tc.driver, tc.config); got != tc.want {
				t.Errorf("ZpoolNameFor(%q, %v) = %q, want %q", tc.driver, tc.config, got, tc.want)
			}
		})
	}
}
