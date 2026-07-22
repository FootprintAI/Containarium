package server

import (
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/incus/incustest"
)

// TestAdmitCPURequest pins the pure policy: fits iff committed+request stays
// within physical×factor, and unknown capacity (physical<=0) always fits so
// the caller can fail open.
func TestAdmitCPURequest(t *testing.T) {
	cases := []struct {
		name                                 string
		physical, committed, request, factor float64
		wantFits                             bool
		wantRatio                            float64
	}{
		{"empty host under 1x", 8, 0, 4, 1, true, 0.5},
		{"exactly at ceiling fits", 8, 4, 4, 1, true, 1},
		{"one core over ceiling", 8, 5, 4, 1, false, 9.0 / 8},
		{"overcommit within 4x", 8, 20, 8, 4, true, 3.5},
		{"overcommit past 4x", 8, 25, 8, 4, false, 33.0 / 8},
		{"unknown capacity always fits", 0, 999, 8, 1, true, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ratio, fits := admitCPURequest(c.physical, c.committed, c.request, c.factor)
			if fits != c.wantFits {
				t.Fatalf("fits = %v, want %v", fits, c.wantFits)
			}
			if diff := ratio - c.wantRatio; diff > 1e-9 || diff < -1e-9 {
				t.Fatalf("ratio = %v, want %v", ratio, c.wantRatio)
			}
		})
	}
}

// seedServer builds a ContainerServer over a mock backend pre-loaded with the
// given committed containers, plus a fixed physical-core count.
func seedServer(t *testing.T, physicalCores float64, seed []incus.ContainerInfo) *ContainerServer {
	t.Helper()
	mock := incustest.NewMockBackend()
	for i := range seed {
		c := seed[i]
		mock.Containers[c.Name] = &c
	}
	mgr := container.NewWithBackend(mock)
	s := &ContainerServer{manager: mgr}
	s.hostCoresFn = func() (float64, error) { return physicalCores, nil }
	return s
}

func tenant(name, cpu string) incus.ContainerInfo {
	return incus.ContainerInfo{Name: name + "-container", Tenant: name, CPU: cpu}
}

// TestAdmitCPUCapacity_Disabled: with no factor set (the default), the gate is
// a pure no-op even on a wildly overcommitted host — existing fleets keep
// working until an operator opts in.
func TestAdmitCPUCapacity_Disabled(t *testing.T) {
	s := seedServer(t, 8, []incus.ContainerInfo{
		tenant("a", "8"), tenant("b", "8"), tenant("c", "8"),
	})
	// factor stays 0
	if err := s.admitCPUCapacity("newbie", "8"); err != nil {
		t.Fatalf("disabled gate must never reject, got %v", err)
	}
}

// TestAdmitCPUCapacity_Enforce: an enabled+enforcing gate rejects a create
// that would push committed cores past physical×factor, with ResourceExhausted.
func TestAdmitCPUCapacity_Enforce(t *testing.T) {
	// 8-core host, 2x ceiling = 16 committed cores allowed.
	s := seedServer(t, 8, []incus.ContainerInfo{
		tenant("a", "8"), tenant("b", "4"), // 12 committed
	})
	s.SetCPUOvercommitPolicy(2, true)

	// 12 + 4 = 16 == ceiling → fits.
	if err := s.admitCPUCapacity("fits", "4"); err != nil {
		t.Fatalf("at-ceiling create should fit, got %v", err)
	}
	// 12 + 8 = 20 > 16 → reject.
	err := s.admitCPUCapacity("toobig", "8")
	if err == nil {
		t.Fatal("over-ceiling create should be rejected")
	}
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("want ResourceExhausted, got %v (%v)", status.Code(err), err)
	}
}

// TestAdmitCPUCapacity_Advisory: an enabled but non-enforcing gate never
// rejects, even over the ceiling (it only logs).
func TestAdmitCPUCapacity_Advisory(t *testing.T) {
	s := seedServer(t, 8, []incus.ContainerInfo{tenant("a", "8"), tenant("b", "8")})
	s.SetCPUOvercommitPolicy(2, false) // enabled, advisory
	if err := s.admitCPUCapacity("toobig", "8"); err != nil {
		t.Fatalf("advisory gate must not reject, got %v", err)
	}
}

// TestAdmitCPUCapacity_ExcludesCoreAndSelf: infra (core-role) containers and
// the tenant being recreated must not count toward committed cores.
func TestAdmitCPUCapacity_ExcludesCoreAndSelf(t *testing.T) {
	core := incus.ContainerInfo{Name: "postgres", CPU: "8", Role: incus.RolePostgres}
	self := tenant("me", "8")
	other := tenant("other", "4")
	s := seedServer(t, 8, []incus.ContainerInfo{core, self, other})
	s.SetCPUOvercommitPolicy(1, true) // 8-core ceiling, strict

	// Committed should count ONLY `other` (4), excluding the 8-core core box
	// and my own existing 8-core box. So recreating "me" at 4 cores → 4+4=8 == ceiling → fits.
	// If core/self weren't excluded, committed would be 8+4(+8 self) and this would reject.
	if err := s.admitCPUCapacity("me", "4"); err != nil {
		t.Fatalf("core+self exclusion should let this fit, got %v", err)
	}
}

// TestAdmitCPUCapacity_FailOpenOnUnknownCores: if the host core count can't be
// read, the gate allows the create rather than blocking it.
func TestAdmitCPUCapacity_FailOpenOnUnknownCores(t *testing.T) {
	s := seedServer(t, 0, []incus.ContainerInfo{tenant("a", "8"), tenant("b", "8")})
	s.hostCoresFn = func() (float64, error) { return 0, errors.New("incus unreachable") }
	s.SetCPUOvercommitPolicy(1, true)
	if err := s.admitCPUCapacity("newbie", "8"); err != nil {
		t.Fatalf("must fail open when host cores unknown, got %v", err)
	}
}
