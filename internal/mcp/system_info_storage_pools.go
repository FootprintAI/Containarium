package mcp

import (
	"fmt"
	"strings"
)

// formatStoragePools renders SystemInfo.storage_pools for get_system_info
// (#2823): one line per pool with its fill and level. Empty when the daemon
// reported none.
func formatStoragePools(pools []StoragePoolCapacity) string {
	if len(pools) == 0 {
		return ""
	}
	out := "\nStorage pools:\n"
	for _, p := range pools {
		level := strings.ToLower(strings.TrimPrefix(p.Level, "STORAGE_POOL_CAPACITY_LEVEL_"))
		if level == "" || level == "unspecified" {
			level = "unknown"
		}
		if p.TotalBytes <= 0 {
			out += fmt.Sprintf("  %s: size not reported\n", p.Pool)
			continue
		}
		out += fmt.Sprintf("  %s: %.1f%% full (%s)\n", p.Pool, float64(p.UsedBytes)*100/float64(p.TotalBytes), level)
	}
	return out
}
