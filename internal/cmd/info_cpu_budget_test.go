package cmd

import (
	"strings"
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// TestRenderCPUBudget: `containarium info` prints the tenant / core /
// physical breakdown and, when the gate is advisory and the host is past
// its ceiling, says so with the ratio (#2284 acceptance criteria 1 and 3).
func TestRenderCPUBudget(t *testing.T) {
	t.Run("nil budget prints nothing", func(t *testing.T) {
		if got := renderCPUBudget(nil); got != "" {
			t.Fatalf("want empty, got %q", got)
		}
	})

	t.Run("advisory over ceiling warns", func(t *testing.T) {
		out := renderCPUBudget(&incus.CPUBudget{
			PhysicalCPUs: 8, TenantCommittedCores: 199, CoreCommittedCores: 8,
			OvercommitFactor: 4, AdmissionMode: incus.CPUAdmissionAdvisory,
		})
		for _, needle := range []string{
			"CPU Budget:",
			"Physical CPUs:     8",
			"Tenant committed:  199.00 cores (24.88×)",
			"Core committed:    8.00 cores",
			"Admission gate:    advisory, factor 4.00× (ceiling 32.00 cores)",
			"WARNING:",
			"not enforcing",
		} {
			if !strings.Contains(out, needle) {
				t.Errorf("output lacks %q:\n%s", needle, out)
			}
		}
	})

	t.Run("disabled gate has no ceiling and no warning", func(t *testing.T) {
		out := renderCPUBudget(&incus.CPUBudget{PhysicalCPUs: 8, TenantCommittedCores: 12, CoreCommittedCores: 3, AdmissionMode: incus.CPUAdmissionDisabled})
		if strings.Contains(out, "WARNING") || strings.Contains(out, "ceiling") {
			t.Errorf("disabled gate must not warn or print a ceiling:\n%s", out)
		}
		if !strings.Contains(out, "Admission gate:    disabled") {
			t.Errorf("gate posture missing:\n%s", out)
		}
	})

	t.Run("unknown mode says not reported", func(t *testing.T) {
		out := renderCPUBudget(&incus.CPUBudget{PhysicalCPUs: 8, TenantCommittedCores: 12})
		if !strings.Contains(out, "Admission gate:    not reported") {
			t.Errorf("unknown mode must read as not reported:\n%s", out)
		}
	})
}
