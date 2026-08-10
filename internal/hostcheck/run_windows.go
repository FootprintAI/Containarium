//go:build windows

package hostcheck

// Run is a no-op stub on Windows: the capability checks (Linux caps, useradd,
// daemon paths) don't apply, and the daemon doesn't run on Windows. The base
// `containarium` Windows binary still imports this package transitively
// (internal/cloud → hostcheck), so it must compile — it just reports no checks.
func Run() []Check { return nil }

// RunPosture is a no-op stub on Windows for the same reason as Run: the
// host security-posture checks (#1103) read Linux-specific state — efivars,
// /proc/mounts, sshd_config, APT — and the daemon doesn't run on Windows.
func RunPosture() []Check { return nil }
