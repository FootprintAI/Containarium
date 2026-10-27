//go:build !windows

package cloud

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/footprintai/containarium/internal/policyreadiness"
)

// #2483: the status probe carries policy-store readiness as advisory
// checks: reported unmet while a store is unavailable, met once it is
// installed, and never folded into SelfCheckOK.
func TestProbe_ReportsPolicyStoreReadiness(t *testing.T) {
	h := health.NewServer()
	for _, svc := range policyreadiness.Services() {
		h.SetServingStatus(svc, healthpb.HealthCheckResponse_NOT_SERVING)
	}
	probe := DefaultStatusProbe{Readiness: policyreadiness.ServerCheck(h)}
	baseline, err := DefaultStatusProbe{}.Probe(context.Background())
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	readiness := func(st HostStatus) map[string]HostCheck {
		out := map[string]HostCheck{}
		for _, c := range st.Checks {
			if strings.HasPrefix(c.Name, "readiness: ") {
				out[c.Name] = c
			}
		}
		return out
	}

	st, err := probe.Probe(context.Background())
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	got := readiness(st)
	if len(got) != len(policyreadiness.Services()) {
		t.Fatalf("readiness checks = %v, want one per policy service", got)
	}
	for name, c := range got {
		if c.OK || !strings.Contains(c.Detail, "unavailable") {
			t.Errorf("%s = %+v, want unmet and saying unavailable", name, c)
		}
	}
	if st.SelfCheckOK != baseline.SelfCheckOK {
		t.Errorf("SelfCheckOK = %v with readiness unmet, want %v (advisory only)", st.SelfCheckOK, baseline.SelfCheckOK)
	}

	for _, svc := range policyreadiness.Services() {
		h.SetServingStatus(svc, healthpb.HealthCheckResponse_SERVING)
	}
	st, err = probe.Probe(context.Background())
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	for name, c := range readiness(st) {
		if !c.OK {
			t.Errorf("%s = %+v after recovery, want met", name, c)
		}
	}
}

// With no readiness source wired, the probe reports no readiness checks.
func TestProbe_NoReadinessSourceAddsNoChecks(t *testing.T) {
	st, err := DefaultStatusProbe{}.Probe(context.Background())
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	for _, c := range st.Checks {
		if strings.HasPrefix(c.Name, "readiness: ") {
			t.Errorf("unexpected readiness check %+v", c)
		}
	}
}
