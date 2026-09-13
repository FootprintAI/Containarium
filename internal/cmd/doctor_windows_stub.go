//go:build windows && !containarium_client

package cmd

import "github.com/footprintai/containarium/internal/hostcheck"

// printPosture is a no-op on Windows: doctor.go (where the real
// implementation lives) is excluded there because the daemon itself doesn't
// run on Windows and hostcheck.RunPosture's own Windows stub always returns
// nil anyway. This stub exists only so cross-platform callers like `cloud
// enroll` (internal/cmd/cloud.go, no !windows tag — it's a valid client-side
// command on Windows) still link.
func printPosture(_ []hostcheck.Check) {}
