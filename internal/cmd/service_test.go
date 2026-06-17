//go:build !windows

package cmd

import (
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/hostcheck"
)

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
