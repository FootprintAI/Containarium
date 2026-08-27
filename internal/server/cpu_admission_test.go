package server

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/incus/incustest"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// resizeCtx builds an authenticated context for a tenant resizing their own
// box, matching what ResizeContainer's auth.RequireScope/AuthorizeTenant
// gates require.
func resizeCtx(username string) context.Context {
	return auth.ContextWithTestSubjectScopes(context.Background(),
		username, []string{"user"}, []string{auth.ScopeContainersWrite})
}

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

// TestCommittedTenantCores_TotalExcludesOnlyCoreRole is the SystemInfo report
// case (#1580, no username to exclude): every tenant container counts,
// core-role infra does not.
func TestCommittedTenantCores_TotalExcludesOnlyCoreRole(t *testing.T) {
	containers := []incus.ContainerInfo{
		{Name: "postgres", CPU: "4", Role: incus.RolePostgres},
		tenant("alice", "2"),
		tenant("bob", "1.5"),
	}
	got := committedTenantCores(containers, nil)
	if want := 3.5; got != want {
		t.Errorf("committedTenantCores(total) = %v, want %v (2 + 1.5, core-role excluded)", got, want)
	}
}

// TestCommittedTenantCores_SkipExcludesMatchedContainers verifies the skip
// predicate composes correctly with the core-role exclusion — this is the
// exact shape committedCoresExcluding uses, pinned here so the shared helper
// can't silently regress admission behavior while being reused for reporting.
func TestCommittedTenantCores_SkipExcludesMatchedContainers(t *testing.T) {
	containers := []incus.ContainerInfo{
		{Name: "postgres", CPU: "8", Role: incus.RolePostgres},
		tenant("me", "8"),
		tenant("other", "4"),
	}
	got := committedTenantCores(containers, func(c *incus.ContainerInfo) bool {
		return c.Tenant == "me"
	})
	if want := 4.0; got != want {
		t.Errorf("committedTenantCores(skip me) = %v, want %v (core-role and \"me\" excluded, only \"other\" counts)", got, want)
	}
}

// TestCommittedTenantCores_EmptyIsZero: no containers at all sums to zero,
// not an error or a panic.
func TestCommittedTenantCores_EmptyIsZero(t *testing.T) {
	if got := committedTenantCores(nil, nil); got != 0 {
		t.Errorf("committedTenantCores(nil) = %v, want 0", got)
	}
}

// TestCommittedCoresExcluding_UnchangedAfterRefactor pins that
// committedCoresExcluding's own observable behavior (used for admission) is
// unchanged now that its summation is shared with the SystemInfo report via
// committedTenantCores — the existing TestAdmitCPUCapacity_ExcludesCoreAndSelf
// exercises this indirectly through admitCPUCapacity; this test calls the
// method directly so a regression here fails with a smaller, more direct
// signal.
func TestCommittedCoresExcluding_UnchangedAfterRefactor(t *testing.T) {
	s := seedServer(t, 8, []incus.ContainerInfo{
		{Name: "postgres", CPU: "8", Role: incus.RolePostgres},
		tenant("me", "8"),
		tenant("other", "4"),
	})
	got, err := s.committedCoresExcluding("me")
	if err != nil {
		t.Fatalf("committedCoresExcluding: %v", err)
	}
	if want := 4.0; got != want {
		t.Errorf("committedCoresExcluding(\"me\") = %v, want %v", got, want)
	}
}

// Known gap, not covered by any test below: committedCoresExcluding (which
// admitCPUResize calls into via admitCPUCapacity) excludes every container
// whose Tenant matches the given username, not only the specific container
// being resized. A tenant that owns more than one container would have all
// of them excluded from the committed sum during a resize of just one,
// understating true commitment. This is pre-existing — CreateContainer's
// admission already has the identical exposure via the same helper — not
// introduced by routing resize through it, and it is out of scope for
// #1579 to fix (would mean threading a container identity, not just a
// tenant string, through the shared helper for every caller). Flagged here
// so this test suite is not read as proving the check airtight for every
// tenant shape; see docs/architecture/cpu-reservation-and-overcommit-visibility.md
// section A for the full discussion.

// TestAdmitCPUResize_DecreaseNeverBlocked: a resize that doesn't increase CPU
// (lower value, or exactly the current value) must never be blocked, even on
// a host that is already over its ceiling — a legacy, pre-gate fleet must
// still be able to shrink a box. #1579.
func TestAdmitCPUResize_DecreaseNeverBlocked(t *testing.T) {
	// 8-core host, other tenants already committing 10 (over the 8-core
	// ceiling before this tenant's own 4 cores are even added) — a
	// pre-existing overcommit scenario the gate must not retroactively punish.
	s := seedServer(t, 8, []incus.ContainerInfo{tenant("other", "10")})
	s.SetCPUOvercommitPolicy(1, true)

	if err := s.admitCPUResize("me", "4", "2"); err != nil {
		t.Fatalf("a decrease must never be blocked, got %v", err)
	}
	if err := s.admitCPUResize("me", "4", "4"); err != nil {
		t.Fatalf("an unchanged value must never be blocked, got %v", err)
	}
}

// TestAdmitCPUResize_IncreaseUsesFullNewValueNotDelta pins the exact bug an
// earlier draft of #1579 nearly shipped: checking committed_excl + delta
// double-subtracts the tenant's own current allocation (committed_excl
// already has it removed once) and wrongly admits a resize that would push
// the host over its ceiling. The worked counterexample from the issue: an
// 8-core host at factor 1 (ceiling 8), other tenants committing 4, this
// tenant currently at 4 (host exactly at the ceiling). Resizing to 8 must be
// REJECTED — true post-resize total is 4+8=12 > 8. The (wrong) delta formula
// computes 4+(8-4)=8 <= 8 and would wrongly admit it.
func TestAdmitCPUResize_IncreaseUsesFullNewValueNotDelta(t *testing.T) {
	s := seedServer(t, 8, []incus.ContainerInfo{tenant("other", "4"), tenant("me", "4")})
	s.SetCPUOvercommitPolicy(1, true)

	err := s.admitCPUResize("me", "4", "8")
	if err == nil {
		t.Fatal("resize to 8 must be rejected (4 other + 8 new = 12 > 8-core ceiling); the delta formula would wrongly admit this")
	}
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("want ResourceExhausted, got %v (%v)", status.Code(err), err)
	}
}

// TestAdmitCPUResize_IncreaseWithinCeilingAdmitted is the fitting mirror of
// the above: a resize that stays within the ceiling once the tenant's own
// current allocation is properly accounted for is admitted.
func TestAdmitCPUResize_IncreaseWithinCeilingAdmitted(t *testing.T) {
	s := seedServer(t, 8, []incus.ContainerInfo{tenant("other", "4"), tenant("me", "2")})
	s.SetCPUOvercommitPolicy(1, true)

	// committed_excl("me") = 4 (other only, "me" itself is excluded); 4 + 4 == 8-core ceiling.
	if err := s.admitCPUResize("me", "2", "4"); err != nil {
		t.Fatalf("resize to 4 should fit (4 other + 4 new = 8 == ceiling), got %v", err)
	}
}

// TestAdmitCPUResize_DisabledGateNeverBlocks: with the gate off (the
// default), a resize increase is never blocked, matching create's behavior.
func TestAdmitCPUResize_DisabledGateNeverBlocks(t *testing.T) {
	s := seedServer(t, 8, []incus.ContainerInfo{tenant("other", "8")})
	// factor stays 0 (disabled)
	if err := s.admitCPUResize("me", "2", "16"); err != nil {
		t.Fatalf("disabled gate must never reject a resize, got %v", err)
	}
}

// TestResizeContainer_AdmissionRejectsOverCeiling drives ResizeContainer
// end to end (not just the pure admitCPUResize helper) for a local box: an
// enforcing gate must reject a CPU increase that would push the host over
// its ceiling, and the underlying CPU limit must be left untouched.
func TestResizeContainer_AdmissionRejectsOverCeiling(t *testing.T) {
	s := seedServer(t, 8, []incus.ContainerInfo{tenant("other", "4"), tenant("me", "4")})
	s.SetCPUOvercommitPolicy(1, true) // 8-core ceiling, strict

	_, err := s.ResizeContainer(resizeCtx("me"), &pb.ResizeContainerRequest{Username: "me", Cpu: "8"})
	if err == nil {
		t.Fatal("resize to 8 should be rejected (4 other + 8 new = 12 > 8-core ceiling)")
	}
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("want ResourceExhausted, got %v (%v)", status.Code(err), err)
	}
}

// TestResizeContainer_AdmissionAllowsWithinCeiling is the fitting mirror,
// also end to end: a resize that stays within the ceiling succeeds.
func TestResizeContainer_AdmissionAllowsWithinCeiling(t *testing.T) {
	s := seedServer(t, 8, []incus.ContainerInfo{tenant("other", "4"), tenant("me", "2")})
	s.SetCPUOvercommitPolicy(1, true)

	if _, err := s.ResizeContainer(resizeCtx("me"), &pb.ResizeContainerRequest{Username: "me", Cpu: "4"}); err != nil {
		t.Fatalf("resize to 4 should fit (4 other + 4 new = 8 == ceiling), got %v", err)
	}
}

// TestResizeContainer_AdmissionSkippedForDecrease: end to end, a resize that
// lowers CPU is never blocked by admission, even on an already-overcommitted
// host (the legacy-fleet scenario admitCPUResize's pure test already covers;
// this proves the same holds through the full ResizeContainer path).
func TestResizeContainer_AdmissionSkippedForDecrease(t *testing.T) {
	s := seedServer(t, 8, []incus.ContainerInfo{tenant("other", "10"), tenant("me", "4")})
	s.SetCPUOvercommitPolicy(1, true)

	if _, err := s.ResizeContainer(resizeCtx("me"), &pb.ResizeContainerRequest{Username: "me", Cpu: "2"}); err != nil {
		t.Fatalf("a decrease must never be blocked, got %v", err)
	}
}
