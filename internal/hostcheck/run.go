//go:build !windows

package hostcheck

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// RequiredCaps are the effective capabilities the daemon needs to manage
// per-tenant Linux users (useradd, chown ~, etc.). Bit numbers per
// <linux/capability.h>.
var RequiredCaps = []struct {
	Name string
	Bit  uint
}{
	{"CAP_CHOWN", 0},
	{"CAP_DAC_OVERRIDE", 1},
	{"CAP_FOWNER", 3},
	{"CAP_SETGID", 6},
	{"CAP_SETUID", 7},
}

// DaemonWritablePaths must be writable for the daemon (the unit's
// ReadWritePaths) plus /var/log — useradd touches /var/log/lastlog, the
// "second, independent trap" the deploy contract calls out.
var DaemonWritablePaths = []string{
	"/var/lib/incus", "/etc/containarium", "/etc", "/home",
	"/var/lock", "/run/lock", "/opt/containarium", "/var/log",
}

// Run executes every host capability check and returns the results. Pure of
// CLI concerns so the `doctor` / `pool join` CLIs, the daemon startup
// self-check, and the cloud status probe all share one implementation.
func Run() []Check {
	var checks []Check

	// 1. Running as (effective) root.
	euid := os.Geteuid()
	checks = append(checks, Check{
		Name: "running as root", OK: euid == 0, Required: true,
		Detail: fmt.Sprintf("euid=%d (need 0)", euid),
	})

	// 2. Effective capabilities. Diagnostic — the useradd probe (4) is the
	// definitive test; a host can lack the readable mask yet still work, or
	// have it yet be broken by other sandboxing.
	checks = append(checks, capCheck())

	// 3. Writable paths.
	for _, p := range DaemonWritablePaths {
		checks = append(checks, writableCheck(p))
	}

	// 4. The definitive capability-trap test: create + delete a throwaway user.
	checks = append(checks, useraddProbe())

	// 5. incus present (the unit Requires=incus.service).
	_, err := exec.LookPath("incus")
	checks = append(checks, Check{
		Name: "incus binary present", OK: err == nil, Required: true,
		Detail: "incus not found on PATH",
	})

	return checks
}

// capCheck reads CapEff from /proc/self/status and verifies the required caps.
func capCheck() Check {
	c := Check{Name: "effective capabilities", Required: true}
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		c.Detail = fmt.Sprintf("cannot read /proc/self/status: %v", err)
		return c
	}
	var capEff uint64
	found := false
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			hexStr := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
			v, perr := strconv.ParseUint(hexStr, 16, 64)
			if perr != nil {
				c.Detail = fmt.Sprintf("parse CapEff %q: %v", hexStr, perr)
				return c
			}
			capEff = v
			found = true
			break
		}
	}
	if !found {
		c.Detail = "CapEff not found in /proc/self/status"
		return c
	}
	if missing := MissingCaps(capEff); len(missing) > 0 {
		c.Detail = "missing: " + strings.Join(missing, ", ")
		return c
	}
	c.OK = true
	return c
}

// MissingCaps returns the required capabilities NOT set in the effective
// capability mask. Pure — unit-tested.
func MissingCaps(capEff uint64) []string {
	var missing []string
	for _, rc := range RequiredCaps {
		if capEff&(1<<rc.Bit) == 0 {
			missing = append(missing, rc.Name)
		}
	}
	return missing
}

// writableCheck confirms dir exists and is writable by creating+removing a
// temp file (tests writability under the CURRENT caps/sandbox, not just mode).
func writableCheck(dir string) Check {
	c := Check{Name: "writable: " + dir, Required: true}
	info, err := os.Stat(dir)
	if err != nil {
		c.Detail = fmt.Sprintf("missing: %v", err)
		return c
	}
	if !info.IsDir() {
		c.Detail = "not a directory"
		return c
	}
	f, err := os.CreateTemp(dir, ".containarium-doctor-*")
	if err != nil {
		c.Detail = fmt.Sprintf("not writable: %v", err)
		return c
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	c.OK = true
	return c
}

// useraddProbe creates then deletes a throwaway user — the definitive
// capability-trap test (the daemon does this per tenant).
func useraddProbe() Check {
	c := Check{Name: "useradd/userdel probe", Required: true}
	if _, err := exec.LookPath("useradd"); err != nil {
		c.Detail = "useradd not found on PATH"
		return c
	}
	probe := fmt.Sprintf("__ctn_preflight_%d", os.Getpid())
	// -M: no home dir (keeps the probe minimal). Always attempt cleanup.
	out, err := exec.Command("useradd", "-M", "-s", "/usr/sbin/nologin", probe).CombinedOutput() // #nosec G204 -- fixed args + a pid-derived probe name, not user input
	defer func() { _ = exec.Command("userdel", probe).Run() }()                                  // #nosec G204 -- same
	if err != nil {
		c.Detail = fmt.Sprintf("useradd failed (the capability trap): %v: %s", err, strings.TrimSpace(string(out)))
		return c
	}
	c.OK = true
	return c
}
