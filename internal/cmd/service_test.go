//go:build !windows

package cmd

import (
	"slices"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/hostcheck"
)

// TestSystemdServiceDoesNotHardRequireIncus guards the boot-resilience contract.
//
// With Requires=incus.service, a transient incus failure at boot fails
// containarium.service's *start job*. Restart=on-failure does not retry job
// failures, so the daemon stays dead even after incus recovers seconds later --
// observed on a pool member, where it means silently dropping out of the pool
// until a human notices. After= alone gives the ordering; Wants= keeps a bad
// incus start from being terminal, and Restart=on-failure handles "not ready yet".
func TestSystemdServiceDoesNotHardRequireIncus(t *testing.T) {
	var after, requires, wants []string
	for _, line := range strings.Split(systemdServiceTemplate, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "#"):
			continue
		case strings.HasPrefix(line, "After="):
			after = strings.Fields(strings.TrimPrefix(line, "After="))
		case strings.HasPrefix(line, "Requires="):
			requires = strings.Fields(strings.TrimPrefix(line, "Requires="))
		case strings.HasPrefix(line, "Wants="):
			wants = strings.Fields(strings.TrimPrefix(line, "Wants="))
		}
	}
	if slices.Contains(requires, "incus.service") {
		t.Error("systemdServiceTemplate has Requires=incus.service; use Wants= so a " +
			"transient incus failure does not permanently kill the daemon's start job")
	}
	if !slices.Contains(wants, "incus.service") {
		t.Errorf("systemdServiceTemplate should declare Wants=incus.service, got Wants=%v", wants)
	}
	if !slices.Contains(after, "incus.service") {
		t.Errorf("systemdServiceTemplate must keep After=incus.service for ordering, got After=%v", after)
	}
}

// TestSystemdServiceReadWritePathsCoverDoctorContract guards against the unit's
// ProtectSystem=strict sandbox drifting away from the paths the daemon's own
// doctor self-check requires writable. A path the doctor requires but the unit
// denies makes a freshly-installed host boot DEGRADED (this is exactly what
// happened when /var/log — which useradd touches via /var/log/lastlog — was
// missing from ReadWritePaths). The generated unit's ReadWritePaths must be a
// superset of hostcheck.DaemonWritablePaths.
func TestSystemdServiceReadWritePathsCoverDoctorContract(t *testing.T) {
	var rwLine string
	for _, line := range strings.Split(systemdServiceTemplate, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "ReadWritePaths=") {
			rwLine = strings.TrimSpace(line)
			break
		}
	}
	if rwLine == "" {
		t.Fatal("systemdServiceTemplate has no ReadWritePaths= line")
	}
	granted := make(map[string]bool)
	for _, p := range strings.Fields(strings.TrimPrefix(rwLine, "ReadWritePaths=")) {
		granted[p] = true
	}
	for _, required := range hostcheck.DaemonWritablePaths {
		if !granted[required] {
			t.Errorf("ReadWritePaths is missing %q (required by hostcheck.DaemonWritablePaths); "+
				"the host would boot DEGRADED. ReadWritePaths=%v", required, rwLine)
		}
	}
}
