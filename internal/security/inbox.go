package security

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// The in-box ClamAV scan runner (#2631, #2658).
//
// The scan executes INSIDE the tenant's own box, as an unprivileged user with
// only the capability to read files, so the platform never mounts or streams a
// tenant's files and a scanner bug parsing malware never runs as box root (and,
// in a privileged box, never as host root). What leaves the box is a verdict
// record: status, signature names with counts, duration, scanner version. File
// paths are not kept (a path under a home directory is customer data).

// MinBoxMemoryBytes is the memory a box needs to run ClamAV: a one-shot
// clamscan loads about 1.5 GB of signatures. It equals the default box size
// ("4GB", decimal), so a default box is supported. Incus reads GB as 10^9 and
// GiB as 2^30, so both "4GB" and "4GiB" pass.
const MinBoxMemoryBytes int64 = 4_000_000_000

// DefaultInBoxScanTimeout bounds one scan.
const DefaultInBoxScanTimeout = 30 * time.Minute

// Why a scan produced no verdict. Stored in the report's findings text for
// every status other than clean/infected.
const (
	reasonNotRunning    = "box is not running"
	reasonNoClamscan    = "clamscan is not installed in the box (run: containarium security clamav install)"
	reasonNoSignatures  = "no ClamAV signatures in the box (run freshclam, or: containarium security clamav install)"
	reasonScanError     = "scan error (clamscan exit 2)"
	reasonOOM           = "scan was killed, most likely out of memory (box limit)"
	reasonTimeout       = "scan timed out"
	reasonUnexpectedRC  = "unexpected clamscan exit code"
	reasonTooSmallFmt   = "box memory limit %s is below the %d GB ClamAV needs"
	reasonExecFailedFmt = "could not run the scan in the box: %v"
)

// boxAPI is the slice of the Incus client the runner needs.
// *incus.Client satisfies it.
type boxAPI interface {
	GetContainer(name string) (*incus.ContainerInfo, error)
	ExecWithExitCode(containerName string, command []string) (stdout, stderr string, exitCode int, err error)
}

// parseMemoryBytes parses an Incus limits.memory value. ok is false for an
// empty value, a percentage, or anything it does not understand — the caller
// then does not block the scan on size.
func parseMemoryBytes(v string) (bytes int64, ok bool) {
	v = strings.TrimSpace(v)
	if v == "" || strings.HasSuffix(v, "%") {
		return 0, false
	}
	units := []struct {
		suffix string
		mult   int64
	}{
		{"TiB", 1 << 40}, {"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10},
		{"TB", 1_000_000_000_000}, {"GB", 1_000_000_000}, {"MB", 1_000_000}, {"kB", 1_000}, {"KB", 1_000},
		{"B", 1},
	}
	mult := int64(1)
	num := v
	for _, u := range units {
		if strings.HasSuffix(v, u.suffix) {
			mult, num = u.mult, strings.TrimSpace(strings.TrimSuffix(v, u.suffix))
			break
		}
	}
	f, err := strconv.ParseFloat(num, 64)
	if err != nil || f < 0 {
		return 0, false
	}
	return int64(f * float64(mult)), true
}

// boxTooSmall reports whether a box's memory limit is below MinBoxMemoryBytes.
// An unknown or unparsable limit is not "too small".
func boxTooSmall(limit string) bool {
	b, ok := parseMemoryBytes(limit)
	return ok && b < MinBoxMemoryBytes
}

// summarizeFindings turns clamscan's "<path>: <Signature> FOUND" lines into the
// stored form: total count and one "Signature (n)" entry per distinct
// signature. The path is dropped on purpose.
func summarizeFindings(stdout string) (count int, summary string) {
	sigs := map[string]int{}
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasSuffix(line, " FOUND") {
			continue
		}
		line = strings.TrimSuffix(line, " FOUND")
		// Signature names contain no spaces; a path may, so take the last field.
		sig := line
		if i := strings.LastIndex(line, " "); i >= 0 {
			sig = line[i+1:]
		}
		if sig == "" {
			continue
		}
		sigs[sig]++
		count++
	}
	names := make([]string, 0, len(sigs))
	for n := range sigs {
		names = append(names, n)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, n := range names {
		parts = append(parts, fmt.Sprintf("%s (%d)", n, sigs[n]))
	}
	return count, strings.Join(parts, "\n")
}

// classifyInBoxRun maps a clamscan run (wrapped in `timeout`) to a status and,
// for anything other than clean/infected, the reason. An error is never clean
// (#2496): only exit 0 with no findings is clean.
func classifyInBoxRun(exitCode int, stdout string) (status string, findingsCount int, detail string) {
	count, summary := summarizeFindings(stdout)
	switch exitCode {
	case 0:
		if count > 0 { // defensive: findings with exit 0 are never clean
			return ScanStatusInfected, count, summary
		}
		return ScanStatusClean, 0, ""
	case 1:
		if count == 0 { // exit 1 without a FOUND line: do not guess
			return ScanStatusIncomplete, 0, reasonScanError
		}
		return ScanStatusInfected, count, summary
	case 2:
		if count > 0 { // an infection is real even if another path errored
			return ScanStatusInfected, count, summary + "\n" + reasonScanError
		}
		return ScanStatusIncomplete, 0, reasonScanError
	case 124: // coreutils timeout
		return ScanStatusIncomplete, 0, reasonTimeout
	case 137, 143: // SIGKILL / SIGTERM, typically the box's OOM killer
		return ScanStatusIncomplete, 0, reasonOOM
	default:
		return ScanStatusIncomplete, 0, fmt.Sprintf("%s: %d", reasonUnexpectedRC, exitCode)
	}
}

// inBoxScanCommand is the argv run inside the box. `timeout` bounds it;
// `setpriv` drops to the unprivileged nobody user keeping only
// CAP_DAC_READ_SEARCH (read bypass, no write), so clamscan can read root-only
// files without being root.
func inBoxScanCommand(timeout time.Duration) []string {
	secs := int(timeout / time.Second)
	if secs < 1 {
		secs = 1
	}
	return []string{
		"timeout", strconv.Itoa(secs),
		"setpriv", "--reuid=65534", "--regid=65534", "--clear-groups",
		"--inh-caps=+dac_read_search", "--ambient-caps=+dac_read_search",
		"clamscan", "-r", "-i", "--no-summary", "--stdout",
		"--exclude-dir=^/proc", "--exclude-dir=^/sys", "--exclude-dir=^/dev", "--exclude-dir=^/run",
		"/",
	}
}

// preflight returns a non-empty status (with reason) when the scan must not be
// attempted. All of these produce a report; none is ever clean.
func (s *Scanner) preflight(box boxAPI, name string) (status, reason string) {
	info, err := box.GetContainer(name)
	if err != nil {
		return ScanStatusIncomplete, fmt.Sprintf(reasonExecFailedFmt, err)
	}
	if info.State != "Running" {
		return ScanStatusIncomplete, reasonNotRunning
	}
	if boxTooSmall(info.Memory) {
		return ScanStatusUnsupportedSize,
			fmt.Sprintf(reasonTooSmallFmt, info.Memory, MinBoxMemoryBytes/1_000_000_000)
	}
	if _, _, code, err := box.ExecWithExitCode(name, []string{"sh", "-c", "command -v clamscan"}); err != nil {
		return ScanStatusIncomplete, fmt.Sprintf(reasonExecFailedFmt, err)
	} else if code != 0 {
		return ScanStatusNotInstalled, reasonNoClamscan
	}
	if _, _, code, err := box.ExecWithExitCode(name, []string{"sh", "-c", "ls /var/lib/clamav/main.c?d /var/lib/clamav/daily.c?d >/dev/null 2>&1"}); err != nil {
		return ScanStatusIncomplete, fmt.Sprintf(reasonExecFailedFmt, err)
	} else if code != 0 {
		return ScanStatusNotInstalled, reasonNoSignatures
	}
	return "", ""
}

// scannerVersion reads `clamscan --version` (e.g. "ClamAV 1.0.7/27123/..."),
// best effort; it is kept as the only detail of a clean report.
func scannerVersion(box boxAPI, name string) string {
	out, _, code, err := box.ExecWithExitCode(name, []string{"clamscan", "--version"})
	if err != nil || code != 0 {
		return ""
	}
	return strings.TrimSpace(strings.SplitN(out, "\n", 2)[0])
}
