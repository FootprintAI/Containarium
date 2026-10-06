package server

import (
	"strings"
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func coreBox(name string, role incus.Role, cpu string) incus.ContainerInfo {
	return incus.ContainerInfo{Name: name, Role: role, CPU: cpu}
}

// TestCPUBudget_SplitsTenantAndCore: the host budget reports the platform's
// own core-role CPU next to tenant CPU instead of silently dropping it
// (#2284 gap 1). The tenant half must stay byte-identical to what
// committed_cpu_cores already reports.
func TestCPUBudget_SplitsTenantAndCore(t *testing.T) {
	containers := []incus.ContainerInfo{
		tenant("a", "8"), tenant("b", "4"),
		coreBox("postgres", incus.RolePostgres, "2"),
		coreBox("caddy", incus.RoleCaddy, "1"),
		coreBox("cp", incus.RoleControlPlane, "4"),
	}
	s := seedServer(t, 8, containers)
	s.SetCPUOvercommitPolicy(4, false)

	b := s.cpuBudget(containers, 8)
	if b.TenantCommittedCores != 12 {
		t.Errorf("TenantCommittedCores = %v, want 12", b.TenantCommittedCores)
	}
	if b.TenantCommittedCores != committedTenantCores(containers, nil) {
		t.Errorf("tenant half must equal committed_cpu_cores: %v vs %v", b.TenantCommittedCores, committedTenantCores(containers, nil))
	}
	if b.CoreCommittedCores != 7 {
		t.Errorf("CoreCommittedCores = %v, want 7", b.CoreCommittedCores)
	}
	if b.PhysicalCPUs != 8 || b.OvercommitFactor != 4 || b.AdmissionMode != incus.CPUAdmissionAdvisory {
		t.Errorf("posture not carried: %+v", b)
	}
}

func TestCPUAdmissionMode_FollowsPolicy(t *testing.T) {
	s := seedServer(t, 8, nil)
	if got := s.cpuAdmissionMode(); got != incus.CPUAdmissionDisabled {
		t.Errorf("default = %v, want disabled", got)
	}
	s.SetCPUOvercommitPolicy(2, false)
	if got := s.cpuAdmissionMode(); got != incus.CPUAdmissionAdvisory {
		t.Errorf("factor>0 enforce=false = %v, want advisory", got)
	}
	s.SetCPUOvercommitPolicy(2, true)
	if got := s.cpuAdmissionMode(); got != incus.CPUAdmissionEnforcing {
		t.Errorf("factor>0 enforce=true = %v, want enforcing", got)
	}
	// enforce without a factor is still "off" — the gate never runs.
	s.SetCPUOvercommitPolicy(0, true)
	if got := s.cpuAdmissionMode(); got != incus.CPUAdmissionDisabled {
		t.Errorf("factor=0 enforce=true = %v, want disabled", got)
	}
}

func TestCPUAdmissionModeToProto(t *testing.T) {
	want := map[incus.CPUAdmissionMode]pb.CPUAdmissionMode{
		incus.CPUAdmissionDisabled:  pb.CPUAdmissionMode_CPU_ADMISSION_MODE_DISABLED,
		incus.CPUAdmissionAdvisory:  pb.CPUAdmissionMode_CPU_ADMISSION_MODE_ADVISORY,
		incus.CPUAdmissionEnforcing: pb.CPUAdmissionMode_CPU_ADMISSION_MODE_ENFORCING,
		incus.CPUAdmissionUnknown:   pb.CPUAdmissionMode_CPU_ADMISSION_MODE_UNSPECIFIED,
	}
	for m, p := range want {
		if got := cpuAdmissionModeToProto(m); got != p {
			t.Errorf("%v → %v, want %v", m, got, p)
		}
	}
}

// TestCPUBudgetPostureLine: the daemon's boot-time posture line (#2284 gap
// 4). Advisory + over ceiling → a WARNING naming the ratio; anything else →
// a plain posture line, never a warning.
func TestCPUBudgetPostureLine(t *testing.T) {
	over := []incus.ContainerInfo{tenant("a", "100"), tenant("b", "99"), coreBox("postgres", incus.RolePostgres, "8")}
	s := seedServer(t, 8, over)
	s.SetCPUOvercommitPolicy(4, false)
	line, warn := s.cpuBudgetPostureLine()
	if !warn {
		t.Fatalf("advisory over ceiling must warn, got %q", line)
	}
	for _, needle := range []string{"WARNING", "199.00", "32.00", "24.88×"} {
		if !strings.Contains(line, needle) {
			t.Errorf("posture line lacks %q: %s", needle, line)
		}
	}

	s.SetCPUOvercommitPolicy(4, true)
	line, warn = s.cpuBudgetPostureLine()
	if warn || !strings.Contains(line, "enforcing") {
		t.Errorf("enforcing must not warn; got warn=%v line=%q", warn, line)
	}

	under := seedServer(t, 8, []incus.ContainerInfo{tenant("a", "4")})
	under.SetCPUOvercommitPolicy(4, false)
	line, warn = under.cpuBudgetPostureLine()
	if warn || !strings.Contains(line, "advisory") || !strings.Contains(line, "4.00") {
		t.Errorf("under ceiling must report posture without warning; got warn=%v line=%q", warn, line)
	}

	// Unknown host capacity: no numbers to judge, so no warning — fail open,
	// same as the gate itself.
	unknown := seedServer(t, 0, over)
	unknown.SetCPUOvercommitPolicy(4, false)
	if _, warn = unknown.cpuBudgetPostureLine(); warn {
		t.Error("unknown core count must not warn")
	}
}
