//go:build !windows

package cmd

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"

	"github.com/footprintai/containarium/internal/hostcheck"
)

// doctor — the host capability self-check from the daemon deploy contract
// (prd/oss/daemon-deploy-contract.md). It catches the "capability trap": a
// systemd unit that looks fine (User=root) but whose NoNewPrivileges /
// missing AmbientCapabilities / missing ReadWritePaths silently break
// `useradd` — so the daemon starts "successfully" and only fails on the
// FIRST container create, hours later. The definitive check is a live
// useradd/userdel probe.
//
// The check logic lives in internal/hostcheck so the daemon's cloud status
// probe can run the same checks (#528); this file is the CLI shell.
//
// Run it under the SAME constraints as the daemon (i.e. via the systemd
// unit, or as the daemon) for an accurate result — a plain root shell has
// full caps and will pass even if the daemon unit is mis-configured.

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

// hostDoctorChecks runs every host capability check. Thin alias over
// hostcheck.Run so existing callers (`pool join`) stay unchanged.
func hostDoctorChecks() []hostcheck.Check { return hostcheck.Run() }

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
	var bad []hostcheck.Check
	for _, c := range hostDoctorChecks() {
		if !c.OK && c.Required {
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
		log.Printf("  ✗ %s — %s", c.Name, c.Detail)
	}
	log.Printf("See prd daemon-deploy-contract; run 'containarium doctor'. Continuing (non-fatal).")
	log.Printf("========================================================================")
	return len(bad)
}

// printDoctor renders the checks and returns the count of failed REQUIRED
// checks. Shared by `doctor` and `pool join`.
func printDoctor(checks []hostcheck.Check) int {
	failed := 0
	for _, c := range checks {
		mark := "✓"
		if !c.OK {
			if c.Required {
				mark = "✗"
				failed++
			} else {
				mark = "!"
			}
		}
		line := fmt.Sprintf("  %s %s", mark, c.Name)
		if !c.OK && c.Detail != "" {
			line += " — " + c.Detail
		}
		fmt.Println(line)
	}
	return failed
}
