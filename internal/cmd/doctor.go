//go:build !windows

package cmd

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// doctor — the host capability self-check from the daemon deploy contract
// (prd/oss/daemon-deploy-contract.md). It catches the "capability trap": a
// systemd unit that looks fine (User=root) but whose NoNewPrivileges /
// missing AmbientCapabilities / missing ReadWritePaths silently break
// `useradd` — so the daemon starts "successfully" and only fails on the
// FIRST container create, hours later. The definitive check is a live
// useradd/userdel probe.
//
// Run it under the SAME constraints as the daemon (i.e. via the systemd
// unit, or as the daemon) for an accurate result — a plain root shell has
// full caps and will pass even if the daemon unit is mis-configured.

// requiredCaps are the effective capabilities the daemon needs to manage
// per-tenant Linux users (useradd, chown ~, etc.). Bit numbers per
// <linux/capability.h>.
var requiredCaps = []struct {
	name string
	bit  uint
}{
	{"CAP_CHOWN", 0},
	{"CAP_DAC_OVERRIDE", 1},
	{"CAP_FOWNER", 3},
	{"CAP_SETGID", 6},
	{"CAP_SETUID", 7},
}

// daemonWritablePaths must be writable for the daemon (the unit's
// ReadWritePaths) plus /var/log — useradd touches /var/log/lastlog, the
// "second, independent trap" the deploy contract calls out.
var daemonWritablePaths = []string{
	"/var/lib/incus", "/etc/containarium", "/etc", "/home",
	"/var/lock", "/run/lock", "/opt/containarium", "/var/log",
}

type doctorCheck struct {
	name     string
	ok       bool
	required bool
	detail   string
}

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Run the host capability self-check (the deploy-contract preflight)",
	Long: `Verify this host can actually run the Containarium daemon's user-management
operations — the checks behind the "capability trap": running uid/caps,
writability of the daemon's paths, and a LIVE useradd/userdel probe.

Run under the same constraints as the daemon (via its systemd unit) for an
accurate result; a plain root shell has full capabilities and will pass even
when the daemon unit is mis-configured. Exits non-zero if any required check
fails.`,
	RunE: runDoctor,
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}

// hostDoctorChecks runs every host capability check and returns the results.
// Pure of CLI concerns so `pool join` (and, later, daemon startup) can run
// the same checks.
func hostDoctorChecks() []doctorCheck {
	var checks []doctorCheck

	// 1. Running as (effective) root.
	euid := os.Geteuid()
	checks = append(checks, doctorCheck{
		name: "running as root", ok: euid == 0, required: true,
		detail: fmt.Sprintf("euid=%d (need 0)", euid),
	})

	// 2. Effective capabilities. Diagnostic — the useradd probe (4) is the
	// definitive test; a host can lack the readable mask yet still work, or
	// have it yet be broken by other sandboxing.
	checks = append(checks, capCheck())

	// 3. Writable paths.
	for _, p := range daemonWritablePaths {
		checks = append(checks, writableCheck(p))
	}

	// 4. The definitive capability-trap test: create + delete a throwaway user.
	checks = append(checks, useraddProbe())

	// 5. incus present (the unit Requires=incus.service).
	_, err := exec.LookPath("incus")
	checks = append(checks, doctorCheck{
		name: "incus binary present", ok: err == nil, required: true,
		detail: "incus not found on PATH",
	})

	return checks
}

// capCheck reads CapEff from /proc/self/status and verifies the required caps.
func capCheck() doctorCheck {
	c := doctorCheck{name: "effective capabilities", required: true}
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		c.detail = fmt.Sprintf("cannot read /proc/self/status: %v", err)
		return c
	}
	var capEff uint64
	found := false
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			hexStr := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
			v, perr := strconv.ParseUint(hexStr, 16, 64)
			if perr != nil {
				c.detail = fmt.Sprintf("parse CapEff %q: %v", hexStr, perr)
				return c
			}
			capEff = v
			found = true
			break
		}
	}
	if !found {
		c.detail = "CapEff not found in /proc/self/status"
		return c
	}
	if missing := missingCaps(capEff); len(missing) > 0 {
		c.detail = "missing: " + strings.Join(missing, ", ")
		return c
	}
	c.ok = true
	return c
}

// missingCaps returns the required capabilities NOT set in the effective
// capability mask. Pure — unit-tested.
func missingCaps(capEff uint64) []string {
	var missing []string
	for _, rc := range requiredCaps {
		if capEff&(1<<rc.bit) == 0 {
			missing = append(missing, rc.name)
		}
	}
	return missing
}

// writableCheck confirms dir exists and is writable by creating+removing a
// temp file (tests writability under the CURRENT caps/sandbox, not just mode).
func writableCheck(dir string) doctorCheck {
	c := doctorCheck{name: "writable: " + dir, required: true}
	info, err := os.Stat(dir)
	if err != nil {
		c.detail = fmt.Sprintf("missing: %v", err)
		return c
	}
	if !info.IsDir() {
		c.detail = "not a directory"
		return c
	}
	f, err := os.CreateTemp(dir, ".containarium-doctor-*")
	if err != nil {
		c.detail = fmt.Sprintf("not writable: %v", err)
		return c
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	c.ok = true
	return c
}

// useraddProbe creates then deletes a throwaway user — the definitive
// capability-trap test (the daemon does this per tenant).
func useraddProbe() doctorCheck {
	c := doctorCheck{name: "useradd/userdel probe", required: true}
	if _, err := exec.LookPath("useradd"); err != nil {
		c.detail = "useradd not found on PATH"
		return c
	}
	probe := fmt.Sprintf("__ctn_preflight_%d", os.Getpid())
	// -M: no home dir (keeps the probe minimal). Always attempt cleanup.
	out, err := exec.Command("useradd", "-M", "-s", "/usr/sbin/nologin", probe).CombinedOutput() // #nosec G204 -- fixed args + a pid-derived probe name, not user input
	defer func() { _ = exec.Command("userdel", probe).Run() }()                                  // #nosec G204 -- same
	if err != nil {
		c.detail = fmt.Sprintf("useradd failed (the capability trap): %v: %s", err, strings.TrimSpace(string(out)))
		return c
	}
	c.ok = true
	return c
}

func runDoctor(cmd *cobra.Command, args []string) error {
	checks := hostDoctorChecks()
	failed := printDoctor(checks)
	if failed > 0 {
		return fmt.Errorf("doctor: %d required check(s) failed — this host cannot run the daemon's user management until fixed (see prd daemon-deploy-contract)", failed)
	}
	return nil
}

// logStartupSelfCheck runs the host capability self-check at daemon boot and
// logs a loud, NON-FATAL warning if any required check fails — so a
// capability-trap misconfig surfaces at startup, not on the first container
// create (prd daemon-deploy-contract #69). Non-fatal by design: the daemon
// keeps running so an operator can fix the unit and recover without a restart
// loop. Returns the number of failed required checks.
func logStartupSelfCheck() int {
	var bad []doctorCheck
	for _, c := range hostDoctorChecks() {
		if !c.ok && c.required {
			bad = append(bad, c)
		}
	}
	if len(bad) == 0 {
		return 0
	}
	log.Printf("=============== CONTAINARIUM CAPABILITY SELF-CHECK FAILED ===============")
	log.Printf("%d required check(s) failed — per-tenant user/container creation WILL", len(bad))
	log.Printf("break until fixed (this is the 'capability trap': a unit that looks fine")
	log.Printf("but whose caps/ReadWritePaths silently break useradd):")
	for _, c := range bad {
		log.Printf("  ✗ %s — %s", c.name, c.detail)
	}
	log.Printf("See prd daemon-deploy-contract; run 'containarium doctor'. Continuing (non-fatal).")
	log.Printf("========================================================================")
	return len(bad)
}

// printDoctor renders the checks and returns the count of failed REQUIRED
// checks. Shared by `doctor` and `pool join`.
func printDoctor(checks []doctorCheck) int {
	failed := 0
	for _, c := range checks {
		mark := "✓"
		if !c.ok {
			if c.required {
				mark = "✗"
				failed++
			} else {
				mark = "!"
			}
		}
		line := fmt.Sprintf("  %s %s", mark, c.name)
		if !c.ok && c.detail != "" {
			line += " — " + c.detail
		}
		fmt.Println(line)
	}
	return failed
}
