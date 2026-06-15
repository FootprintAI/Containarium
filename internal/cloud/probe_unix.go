//go:build !windows

package cloud

import (
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/footprintai/containarium/internal/safecast"
)

// diskDataDir is where the daemon's Incus storage lives — the disk the host's
// container workloads consume. statfs here reflects the capacity that
// actually matters for scheduling. Falls back to "/" when absent.
const diskDataDir = "/var/lib/incus"

// diskGB returns (total, available) disk in GB for the daemon's data dir via
// statfs. Best-effort: (0, 0) when neither the data dir nor "/" can be
// stat-ed. Computed in uint64 so it's correct whether the platform's Bsize is
// signed (Linux int64) or unsigned (darwin uint32).
func diskGB() (total, avail int32) {
	path := diskDataDir
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		if err := syscall.Statfs("/", &st); err != nil {
			return 0, 0
		}
	}
	bsize := safecast.U64FromI64(int64(st.Bsize))
	const bytesPerGB = 1024 * 1024 * 1024
	total = safecast.I32(safecast.I64FromU64(uint64(st.Blocks) * bsize / bytesPerGB))
	avail = safecast.I32(safecast.I64FromU64(uint64(st.Bavail) * bsize / bytesPerGB))
	return total, avail
}

// gpuInfo returns (count, spec): the number of NVIDIA GPUs (counted from
// /dev/nvidia[0-9]* device nodes) and a lowercased model string from
// nvidia-smi. Best-effort and cheap (no LXC spin-up): (0, "") on a host with
// no NVIDIA GPUs or no nvidia-smi. The heavyweight nvidia.runtime validation
// stays a separate one-shot admin check, not this per-cycle probe.
func gpuInfo() (count int32, spec string) {
	nodes, _ := filepath.Glob("/dev/nvidia[0-9]*")
	if len(nodes) == 0 {
		return 0, ""
	}
	count = safecast.I32(len(nodes))
	// Model name from nvidia-smi (first GPU). Optional — a host can have the
	// device nodes but a broken driver; we still report the count.
	out, err := exec.Command("nvidia-smi", "--query-gpu=name", "--format=csv,noheader").Output() // #nosec G204 -- fixed args, no user input
	if err == nil {
		if line := strings.TrimSpace(firstLine(string(out))); line != "" {
			spec = strings.ToLower(line)
		}
	}
	return count, spec
}

// firstLine returns the first line of s (without the newline).
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
