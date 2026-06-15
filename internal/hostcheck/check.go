// Package hostcheck is the host capability self-check from the daemon deploy
// contract (prd/oss/daemon-deploy-contract.md) — the checks behind the
// "capability trap": running uid/caps, writability of the daemon's paths, and
// a live useradd/userdel probe.
//
// Extracted from internal/cmd so BOTH the `containarium doctor` / `pool join`
// CLIs AND the daemon's cloud-actuation status probe (internal/cloud) can run
// the same checks without an import cycle. The check logic is //go:build
// !windows (it pokes Linux caps + useradd); a windows stub keeps the package
// importable from the cross-platform internal/cloud.
package hostcheck

// Check is one capability-self-check result. Required=true means a failure
// blocks the host from running the daemon's per-tenant user management.
type Check struct {
	Name     string
	OK       bool
	Required bool
	Detail   string
}

// AllRequiredPass reports whether every required check in cs passed. Used by
// the status probe to derive the cloud-facing self_check_ok flag.
func AllRequiredPass(cs []Check) bool {
	for _, c := range cs {
		if c.Required && !c.OK {
			return false
		}
	}
	return true
}
