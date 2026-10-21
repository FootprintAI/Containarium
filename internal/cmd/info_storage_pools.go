package cmd

import (
	"fmt"
	"strings"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// renderStoragePools is the "Storage Pools" block of `containarium info`
// (#2823): each pool's fill against its size, flagged WARNING (>= 85%) or
// CRITICAL (>= 95%). Empty when the daemon reported no pools (local mode, an
// older daemon, or a monitor that has not read yet).
func renderStoragePools(pools []incus.StoragePoolCapacity) string {
	if len(pools) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("Storage Pools:\n")
	for _, p := range pools {
		line := fmt.Sprintf("  %-18s ", p.Name+":")
		if p.TotalBytes > 0 {
			line += fmt.Sprintf("%.1f%% of %.1f GiB", float64(p.UsedBytes)*100/float64(p.TotalBytes), float64(p.TotalBytes)/(1<<30))
		} else {
			line += "size not reported"
		}
		if p.Driver != "" {
			line += " (" + p.Driver + ")"
		}
		switch p.Level {
		case incus.StoragePoolLevelWarning:
			line += "  WARNING"
		case incus.StoragePoolLevelCritical:
			line += "  CRITICAL: containers on this pool may soon stop writing"
		}
		sb.WriteString(line + "\n")
	}
	sb.WriteString("\n")
	return sb.String()
}
