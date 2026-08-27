package server

import (
	"fmt"
	"log"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// CPU capacity admission (#1029 direction 2).
//
// A whole-core `limits.cpu` only bounds WHICH cores a container can see, not
// how much CPU time it may consume; #1034 made every request also carry a hard
// CFS quota, but that still lets an operator pack far more committed cores onto
// a host than it physically has ("~14× overcommit" was observed live on an
// 8-core host holding many `limits.cpu=8` tenants). CPU is compressible, so
// *some* overcommit is fine and even desirable — but unbounded overcommit is
// how one busy tenant starves every co-located one.
//
// This gate refuses (or, in advisory mode, merely warns about) a create that
// would push a host's committed cores past `physicalCores × factor`. It is:
//
//   - Off by default. `factor <= 0` disables it entirely — no list, no read,
//     no behavior change. Existing already-overcommitted fleets keep working
//     until an operator opts in.
//   - Rollout-friendly. `factor > 0` with enforce=false logs what it *would*
//     reject without blocking, so an operator can watch a real fleet for a
//     while (mirroring how eBPF enforcement was rolled out observe-first)
//     before flipping enforce=true.
//   - Fail-open. If the host's core count or container list can't be read, the
//     create proceeds — a capacity check must never be the reason a box can't
//     be made.
//
// The gate is inherently per-host: it runs on the daemon that will actually
// create the box. Peer-routed creates are forwarded to the target peer's own
// daemon, which runs its own gate against its own host, so no cross-host
// capacity view is needed here.

// admitCPURequest is the pure policy core: adding requestCores to a host that
// already commits committedCores of physicalCores, at the given overcommit
// factor, fits iff the projected total stays within physicalCores × factor.
// It also returns the projected overcommit ratio (committed+request : physical)
// for logging. A non-positive physicalCores means "capacity unknown" and
// always fits — the caller fails open.
func admitCPURequest(physicalCores, committedCores, requestCores, factor float64) (ratio float64, fits bool) {
	if physicalCores <= 0 {
		return 0, true
	}
	projected := committedCores + requestCores
	ratio = projected / physicalCores
	return ratio, projected <= physicalCores*factor
}

// admitCPUCapacity applies the overcommit policy to one incoming create. It
// returns a ResourceExhausted error only when the gate is enabled, enforcing,
// and the request would exceed the ceiling; otherwise nil (including every
// fail-open path). username is the tenant being (re)created — its own existing
// container, if any, is excluded so a resize-by-recreate doesn't double-count.
//
// Known gap (#1588): this is a check-then-act read with no lock or
// reservation held across the caller's subsequent mutation. Two concurrent
// callers (create, resize, or the cluster reconciler — every caller of this
// function) can each admit against a stale snapshot and jointly exceed the
// ceiling. Pre-existing since #1029 for create; #1579 extends the same
// window to resize without introducing a new kind of gap. Not fixed here —
// closing it needs serialization (or a reservation step) shared across
// every local operation that commits CPU, which is bigger than any one
// caller's scope.
func (s *ContainerServer) admitCPUCapacity(username, cpuRequest string) error {
	if s.cpuOvercommitFactor <= 0 {
		return nil // gate disabled (the default)
	}

	physical, err := s.hostPhysicalCores()
	if err != nil || physical <= 0 {
		log.Printf("[cpu-admission] capacity check skipped (host cores unavailable: %v) — allowing create for %s", err, username)
		return nil
	}
	committed, err := s.committedCoresExcluding(username)
	if err != nil {
		log.Printf("[cpu-admission] capacity check skipped (container list failed: %v) — allowing create for %s", err, username)
		return nil
	}
	request := incus.CommittedCores(cpuRequest)

	ratio, fits := admitCPURequest(physical, committed, request, s.cpuOvercommitFactor)
	if fits {
		return nil
	}

	detail := fmt.Sprintf(
		"host has %.0f logical CPUs; %.2f already committed + %.2f requested = %.2f would exceed the %.2f× overcommit ceiling (%.2f cores) — projected %.2f×",
		physical, committed, request, committed+request, s.cpuOvercommitFactor, physical*s.cpuOvercommitFactor, ratio)

	if !s.cpuOvercommitEnforce {
		log.Printf("[cpu-admission] ADVISORY (not enforced): would reject %s — %s", username, detail)
		return nil
	}
	log.Printf("[cpu-admission] REJECT %s — %s", username, detail)
	return status.Errorf(codes.ResourceExhausted,
		"CPU capacity exceeded on this backend: %s. Retry on a less-loaded backend/pool or a larger host, or ask an operator to raise the overcommit factor.", detail)
}

// admitCPUResize applies the capacity gate to a CPU-increasing resize
// (#1579 — closes the resize-side hole: a resize could push a host past
// capacity with no check at all, even though create already goes through
// admitCPUCapacity).
//
// It reuses admitCPUCapacity UNCHANGED rather than adding a delta-aware
// variant of it — do not change admitCPUCapacity's own signature, since
// dual_server.go wires that exact function into the cluster reconciler's
// SetAdmission for VM creation, and a signature change breaks that call site
// silently.
//
// committedCoresExcluding already excludes the tenant's own current
// container from the committed sum, so passing the resize's full new CPU
// value performs the same "would this fit if the box were (re)created at
// this size" check create already does — no delta is needed, and a delta
// would be wrong: checking committed_excl + (newCores - currentCores) would
// double-subtract the tenant's current allocation (committed_excl already
// has it removed once) and could silently admit a resize that should be
// rejected. Worked example: an 8-core host at factor 1 (ceiling 8), another
// tenant committing 4, this tenant currently at 4 (host exactly at the
// ceiling). Resizing to 8 must be rejected — true post-resize total is
// 4+8=12>8. The delta formula computes 4+(8-4)=8<=8 and wrongly admits it;
// passing the full new value correctly computes 4+8=12>8 and rejects.
//
// A resize that does not increase CPU is never blocked: if the new value
// parses to no more committed cores than the box's current one, the check
// is skipped outright rather than relying on the arithmetic to always admit
// a decrease — a host that is already over its ceiling (a legacy, pre-gate
// fleet) would otherwise have a decrease wrongly rejected too.
func (s *ContainerServer) admitCPUResize(username, currentCPU, newCPU string) error {
	if incus.CommittedCores(newCPU) <= incus.CommittedCores(currentCPU) {
		return nil
	}
	return s.admitCPUCapacity(username, newCPU)
}

// hostPhysicalCores reports the host's logical CPU count (vCPUs — Incus's
// TotalCPUs sums hardware threads, so this counts SMT threads, matching the
// unit limits.cpu itself uses). The hostCoresFn seam lets tests inject a count
// without a live Incus daemon (mirrors localHealthCheckFn); in production it
// reads Incus's own resource inventory, the same source GetSystemInfo uses.
func (s *ContainerServer) hostPhysicalCores() (float64, error) {
	if s.hostCoresFn != nil {
		return s.hostCoresFn()
	}
	client, err := incus.New()
	if err != nil {
		return 0, err
	}
	res, err := client.GetSystemResources()
	if err != nil {
		return 0, err
	}
	return float64(res.TotalCPUs), nil
}

// committedCoresExcluding sums the committed cores of every tenant container on
// this host, skipping core-infra boxes (postgres/caddy — not tenant workload)
// and the tenant being (re)created (so its own current commitment isn't counted
// against its replacement).
func (s *ContainerServer) committedCoresExcluding(username string) (float64, error) {
	containers, err := s.manager.List()
	if err != nil {
		return 0, err
	}
	selfName := username + "-container"
	return committedTenantCores(containers, func(c *incus.ContainerInfo) bool {
		return c.Name == selfName || c.Tenant == username
	}), nil
}

// committedTenantCores sums incus.CommittedCores over containers, always
// skipping core-role infra (postgres/caddy/control-plane — not tenant
// workload), and any container for which skip returns true (skip may be nil
// for a plain, unfiltered total).
//
// Shared between committedCoresExcluding (the admission check above, which
// additionally excludes the tenant being (re)sized/created) and
// SystemInfo.committed_cpu_cores (#1580, a plain total with no tenant
// excluded) so there is one summation to keep correct, not two independent
// copies that could drift apart.
//
// It deliberately reports TENANT capacity, not total host capacity: excluding
// core-role containers means this total does not include the platform's own
// Postgres/Caddy/control-plane CPU footprint. That is intentional — it is
// the number an operator sizing a tenant-facing overcommit factor actually
// wants — but it means committed_cpu_cores / total_cpus is a tenant-only
// ratio; an operator must separately budget the host's known core-infra CPU
// on top of it. See docs/architecture/cpu-reservation-and-overcommit-visibility.md
// section A/B for the full discussion.
func committedTenantCores(containers []incus.ContainerInfo, skip func(c *incus.ContainerInfo) bool) float64 {
	var sum float64
	for i := range containers {
		c := &containers[i]
		if c.Role.IsCoreRole() {
			continue
		}
		if skip != nil && skip(c) {
			continue
		}
		sum += incus.CommittedCores(c.CPU)
	}
	return sum
}
