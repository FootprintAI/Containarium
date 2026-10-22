package incus

import (
	"strings"
	"testing"
)

// TestCoreCommittedCores pins the other half of committedTenantCores: the
// cores committed by core-role (platform) containers, which the admission
// gate and SystemInfo.committed_cpu_cores deliberately leave out (#2284).
func TestCoreCommittedCores(t *testing.T) {
	containers := []ContainerInfo{
		{Name: "alice-container", Tenant: "alice", CPU: "8"},
		{Name: "postgres", Role: RolePostgres, CPU: "2"},
		{Name: "caddy", Role: RoleCaddy, CPU: "1"},
		{Name: "controlplane", Role: RoleControlPlane, CPU: "4"},
		{Name: "bob-container", Tenant: "bob", CPU: "0-3"}, // CPU-set notation, tenant
		{Name: "legacy-core", Role: RoleSecurity, CPU: ""}, // unbounded → counts 0
	}
	if got := CoreCommittedCores(containers); got != 7 {
		t.Fatalf("CoreCommittedCores = %v, want 7 (2+1+4; tenants and unbounded excluded)", got)
	}
	if got := CoreCommittedCores(nil); got != 0 {
		t.Fatalf("CoreCommittedCores(nil) = %v, want 0", got)
	}
}

func TestCPUBudget_DerivedNumbers(t *testing.T) {
	b := CPUBudget{PhysicalCPUs: 8, TenantCommittedCores: 199, CoreCommittedCores: 8, OvercommitFactor: 4, AdmissionMode: CPUAdmissionAdvisory}
	if got := b.Ceiling(); got != 32 {
		t.Errorf("Ceiling = %v, want 32", got)
	}
	if got := b.TenantRatio(); got != 199.0/8 {
		t.Errorf("TenantRatio = %v, want %v", got, 199.0/8)
	}
	if got := b.TotalCommittedCores(); got != 207 {
		t.Errorf("TotalCommittedCores = %v, want 207", got)
	}
	// The operator recipe: a factor at or below (physical − core) / physical
	// leaves the platform's own cores un-overcommitted.
	if got := b.HeadroomFactor(); got != 0 {
		t.Errorf("HeadroomFactor with core == physical = %v, want 0", got)
	}
	b.CoreCommittedCores = 2
	if got := b.HeadroomFactor(); got != 0.75 {
		t.Errorf("HeadroomFactor = %v, want 0.75", got)
	}

	// Unknown capacity never divides by zero and never claims a ceiling.
	z := CPUBudget{TenantCommittedCores: 10, OvercommitFactor: 4, AdmissionMode: CPUAdmissionAdvisory}
	if z.Ceiling() != 0 || z.TenantRatio() != 0 || z.HeadroomFactor() != 0 {
		t.Errorf("zero physical must yield zero ceiling/ratio/headroom, got %v %v %v", z.Ceiling(), z.TenantRatio(), z.HeadroomFactor())
	}
	// A disabled gate has no ceiling even with a stale factor.
	d := CPUBudget{PhysicalCPUs: 8, OvercommitFactor: 4, AdmissionMode: CPUAdmissionDisabled}
	if d.Ceiling() != 0 {
		t.Errorf("disabled gate Ceiling = %v, want 0", d.Ceiling())
	}
}

// TestCPUBudget_AdvisoryWarning: the gate fails silently in advisory mode
// today — the warning fires exactly when the gate is advisory AND the host is
// already past the ceiling it would enforce (#2284 gap 2/4).
func TestCPUBudget_AdvisoryWarning(t *testing.T) {
	cases := map[string]struct {
		b    CPUBudget
		want bool
	}{
		"advisory over ceiling": {CPUBudget{PhysicalCPUs: 8, TenantCommittedCores: 199, CoreCommittedCores: 8, OvercommitFactor: 4, AdmissionMode: CPUAdmissionAdvisory}, true},
		"advisory at ceiling":   {CPUBudget{PhysicalCPUs: 8, TenantCommittedCores: 32, OvercommitFactor: 4, AdmissionMode: CPUAdmissionAdvisory}, false},
		"advisory under":        {CPUBudget{PhysicalCPUs: 8, TenantCommittedCores: 12, OvercommitFactor: 4, AdmissionMode: CPUAdmissionAdvisory}, false},
		"enforcing over":        {CPUBudget{PhysicalCPUs: 8, TenantCommittedCores: 199, OvercommitFactor: 4, AdmissionMode: CPUAdmissionEnforcing}, false},
		"disabled over":         {CPUBudget{PhysicalCPUs: 8, TenantCommittedCores: 199, OvercommitFactor: 0, AdmissionMode: CPUAdmissionDisabled}, false},
		"unknown mode":          {CPUBudget{PhysicalCPUs: 8, TenantCommittedCores: 199, OvercommitFactor: 4, AdmissionMode: CPUAdmissionUnknown}, false},
		"advisory unknown cpus": {CPUBudget{PhysicalCPUs: 0, TenantCommittedCores: 199, OvercommitFactor: 4, AdmissionMode: CPUAdmissionAdvisory}, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			msg, warn := tc.b.AdvisoryWarning()
			if warn != tc.want {
				t.Fatalf("warn = %v, want %v (msg %q)", warn, tc.want, msg)
			}
			if !warn {
				if msg != "" {
					t.Fatalf("no warning must mean empty message, got %q", msg)
				}
				return
			}
			for _, needle := range []string{"ADVISORY", "199.00", "32.00", "24.88×", "8 logical CPUs", "not enforcing", "8.00 core"} {
				if !strings.Contains(msg, needle) {
					t.Errorf("warning lacks %q:\n%s", needle, msg)
				}
			}
		})
	}
}

func TestCPUAdmissionMode_String(t *testing.T) {
	want := map[CPUAdmissionMode]string{
		CPUAdmissionUnknown:   "unknown",
		CPUAdmissionDisabled:  "disabled",
		CPUAdmissionAdvisory:  "advisory",
		CPUAdmissionEnforcing: "enforcing",
		CPUAdmissionMode(99):  "unknown",
	}
	for m, s := range want {
		if m.String() != s {
			t.Errorf("%d.String() = %q, want %q", int(m), m.String(), s)
		}
	}
}
