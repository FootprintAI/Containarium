//go:build windows

package hostcheck

// Run is a no-op stub on Windows: the capability checks (Linux caps, useradd,
// daemon paths) don't apply, and the daemon doesn't run on Windows. The base
// `containarium` Windows binary still imports this package transitively
// (internal/cloud → hostcheck), so it must compile — it just reports no checks.
func Run() []Check { return nil }
