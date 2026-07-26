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

// CheckKind separates the two question types so a functional pass is never
// mistaken for a security pass. A string rather than an int enum because it
// crosses to the cloud inside a check name (see WireName) until the proto
// gains a typed field.
//
// Declared here rather than beside the posture checks because this file has
// no build constraint: the Windows stub build must still see the type.
type CheckKind string

const (
	// KindCapability — "can the daemon operate here" (run.go).
	KindCapability CheckKind = "capability"
	// KindPosture — "is this host hardened" (posture.go).
	KindPosture CheckKind = "posture"
)

// Check is one self-check result. Required=true means a failure blocks the
// host from running the daemon's per-tenant user management.
type Check struct {
	Name     string
	OK       bool
	Required bool
	Detail   string
	// Kind separates "can the daemon operate here" (KindCapability) from
	// "is this host hardened" (KindPosture, #1103). The zero value reads as
	// capability so every pre-existing construction site keeps its meaning
	// without being touched.
	Kind CheckKind
}

// WireName is the check's name as reported to the control plane. Posture
// checks are prefixed so the two groups stay distinguishable across a wire
// format that currently carries only {name, ok, detail} — without it a
// hardening warning would be indistinguishable from a capability failure in
// the cloud's stored self-check, which is exactly the conflation #1103 is
// about. Replace with a typed proto field when the contract gains one.
func (c Check) WireName() string {
	if c.Kind == KindPosture {
		return "posture: " + c.Name
	}
	return c.Name
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
