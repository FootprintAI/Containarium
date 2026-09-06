package server

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
	if _, err := s.admitCPUCapacity("newbie", "8"); err != nil {
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
	if _, err := s.admitCPUCapacity("fits", "4"); err != nil {
		t.Fatalf("at-ceiling create should fit, got %v", err)
	}
	// 12 + 8 = 20 > 16 → reject.
	_, err := s.admitCPUCapacity("toobig", "8")
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
	if _, err := s.admitCPUCapacity("toobig", "8"); err != nil {
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
	if _, err := s.admitCPUCapacity("me", "4"); err != nil {
		t.Fatalf("core+self exclusion should let this fit, got %v", err)
	}
}

// TestAdmitCPUCapacity_FailOpenOnUnknownCores: if the host core count can't be
// read, the gate allows the create rather than blocking it.
func TestAdmitCPUCapacity_FailOpenOnUnknownCores(t *testing.T) {
	s := seedServer(t, 0, []incus.ContainerInfo{tenant("a", "8"), tenant("b", "8")})
	s.hostCoresFn = func() (float64, error) { return 0, errors.New("incus unreachable") }
	s.SetCPUOvercommitPolicy(1, true)
	if _, err := s.admitCPUCapacity("newbie", "8"); err != nil {
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

	if _, err := s.admitCPUResize("me", "4", "2"); err != nil {
		t.Fatalf("a decrease must never be blocked, got %v", err)
	}
	if _, err := s.admitCPUResize("me", "4", "4"); err != nil {
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

	_, err := s.admitCPUResize("me", "4", "8")
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
	if _, err := s.admitCPUResize("me", "2", "4"); err != nil {
		t.Fatalf("resize to 4 should fit (4 other + 4 new = 8 == ceiling), got %v", err)
	}
}

// TestAdmitCPUResize_DisabledGateNeverBlocks: with the gate off (the
// default), a resize increase is never blocked, matching create's behavior.
func TestAdmitCPUResize_DisabledGateNeverBlocks(t *testing.T) {
	s := seedServer(t, 8, []incus.ContainerInfo{tenant("other", "8")})
	// factor stays 0 (disabled)
	if _, err := s.admitCPUResize("me", "2", "16"); err != nil {
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

// #1588 — the check-then-act race. These exercise admitCPUCapacity's
// reservation mechanism directly, reproducing the issue's own worked
// example: an 8-core host at factor 1 (ceiling 8), two tenants each already
// committed at 2 cores, both concurrently resizing to 6. Each admission
// check alone sees 2+6=8<=8 and would admit — the true post-resize total,
// 6+6=12, exceeds the ceiling. Before this fix, both calls would return nil
// because neither held anything across the other's (unmodeled, in this
// direct-call test) mutation; the fix's reservation makes the SECOND call
// see the FIRST one's outstanding cores even though nothing was actually
// mutated yet.
func TestAdmitCPUCapacity_ConcurrentAdmitsRaceIsClosed(t *testing.T) {
	s := seedServer(t, 8, []incus.ContainerInfo{tenant("a", "2"), tenant("b", "2")})
	s.SetCPUOvercommitPolicy(1, true) // 8-core ceiling, strict

	releaseA, err := s.admitCPUCapacity("a", "6")
	if err != nil {
		t.Fatalf("first admit (a: 2->6) should fit alone (2 other + 6 = 8 == ceiling), got %v", err)
	}
	defer releaseA()

	// Without the fix, this would also admit: committedCoresExcluding("b")
	// still reads the REAL (unchanged) container list, seeing "a" at its
	// OLD 2 cores, not the 6 it was just admitted for — 2(b's real
	// other-tenant total, "a" unchanged)+6(requested)=8<=8 would wrongly
	// fit. With the fix, b's check adds a's outstanding 6-core reservation
	// on top: 2(real)+6(a's reservation)+6(requested)=14>8 — rejected.
	_, err = s.admitCPUCapacity("b", "6")
	if err == nil {
		t.Fatal("second concurrent admit (b: 2->6) should be REJECTED once a's reservation is counted — this is the #1588 race")
	}
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("want ResourceExhausted, got %v (%v)", status.Code(err), err)
	}
}

// Releasing a reservation makes room for a subsequent admit that would
// otherwise be rejected — proving release() actually does something, not
// just that the reservation exists.
func TestAdmitCPUCapacity_ReleaseFreesTheReservation(t *testing.T) {
	s := seedServer(t, 8, []incus.ContainerInfo{tenant("a", "2"), tenant("b", "2")})
	s.SetCPUOvercommitPolicy(1, true)

	releaseA, err := s.admitCPUCapacity("a", "6")
	if err != nil {
		t.Fatalf("first admit should fit, got %v", err)
	}
	if _, err := s.admitCPUCapacity("b", "6"); err == nil {
		t.Fatal("second admit should be rejected while a's reservation is outstanding")
	}

	releaseA()

	if _, err := s.admitCPUCapacity("b", "6"); err != nil {
		t.Fatalf("after releasing a's reservation, b's admit should fit (2 other + 6 = 8 == ceiling), got %v", err)
	}
}

// A reservation nobody ever releases still stops counting once it expires —
// the safety net for a caller whose completion this package can't observe
// (the k8s Box-CR reconciliation path). Uses nowFn rather than a real
// 10-minute wait.
func TestAdmitCPUCapacity_ReservationExpiresAfterTTL(t *testing.T) {
	s := seedServer(t, 8, []incus.ContainerInfo{tenant("a", "2"), tenant("b", "2")})
	s.SetCPUOvercommitPolicy(1, true)

	current := time.Now()
	s.nowFn = func() time.Time { return current }

	if _, err := s.admitCPUCapacity("a", "6"); err != nil {
		t.Fatalf("first admit should fit, got %v", err)
	}
	if _, err := s.admitCPUCapacity("b", "6"); err == nil {
		t.Fatal("second admit should be rejected while a's reservation is live")
	}

	// Never released — advance the clock past the TTL instead.
	current = current.Add(cpuReservationTTL + time.Second)

	if _, err := s.admitCPUCapacity("b", "6"); err != nil {
		t.Fatalf("after a's reservation expires, b's admit should fit, got %v", err)
	}
}

// A tenant's own outstanding reservation must not count against its own
// next admit — the same "don't double-count the tenant being (re)sized"
// rule committedCoresExcluding already applies to the real committed total,
// extended to the reservation table.
func TestAdmitCPUCapacity_OwnReservationExcludedFromOwnNextAdmit(t *testing.T) {
	s := seedServer(t, 8, []incus.ContainerInfo{tenant("other", "2")})
	s.SetCPUOvercommitPolicy(1, true)

	if _, err := s.admitCPUCapacity("me", "6"); err != nil {
		t.Fatalf("first admit for me should fit (2 other + 6 = 8 == ceiling), got %v", err)
	}
	// A second admit for the SAME tenant (e.g. a retried request) must be
	// judged against the real committed total plus OTHER tenants'
	// reservations, not doubled up with its own prior reservation.
	if _, err := s.admitCPUCapacity("me", "6"); err != nil {
		t.Fatalf("second admit for the same tenant should still fit (its own prior reservation must not stack against itself), got %v", err)
	}
}

// TestAdmitCPUCapacity_ConcurrentGoroutinesNeverExceedCeiling drives the fix
// with real concurrent goroutines (run with -race) rather than sequential
// calls simulating concurrency — the shape of bug the issue actually
// describes. 8-core host, 1x ceiling: ten different tenants each request 2
// cores at once. 8 cores / 2 per admit divides evenly, so regardless of
// goroutine scheduling order exactly 4 must be admitted and 6 rejected —
// any other count means the ceiling was violated or admission was
// needlessly conservative.
func TestAdmitCPUCapacity_ConcurrentGoroutinesNeverExceedCeiling(t *testing.T) {
	s := seedServer(t, 8, nil)
	s.SetCPUOvercommitPolicy(1, true)

	const tenants = 10
	var wg sync.WaitGroup
	var admitted int64
	for i := 0; i < tenants; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := s.admitCPUCapacity(fmt.Sprintf("tenant-%d", i), "2")
			if err == nil {
				atomic.AddInt64(&admitted, 1)
			}
		}(i)
	}
	wg.Wait()

	if admitted != 4 {
		t.Fatalf("admitted %d of %d concurrent 2-core requests on an 8-core/1x host, want exactly 4 (8/2) — "+
			"a higher count means the ceiling was violated (the #1588 race), a lower count means admission "+
			"was wrongly conservative", admitted, tenants)
	}
}
