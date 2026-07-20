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
		"host has %.0f physical cores; %.2f already committed + %.2f requested = %.2f would exceed the %.2f× overcommit ceiling (%.2f cores) — projected %.2f×",
		physical, committed, request, committed+request, s.cpuOvercommitFactor, physical*s.cpuOvercommitFactor, ratio)

	if !s.cpuOvercommitEnforce {
		log.Printf("[cpu-admission] ADVISORY (not enforced): would reject %s — %s", username, detail)
		return nil
	}
	log.Printf("[cpu-admission] REJECT %s — %s", username, detail)
	return status.Errorf(codes.ResourceExhausted,
		"CPU capacity exceeded on this backend: %s. Retry on a less-loaded backend/pool or a larger host, or ask an operator to raise the overcommit factor.", detail)
}

// hostPhysicalCores reports the host's physical core count. The hostCoresFn
// seam lets tests inject a count without a live Incus daemon (mirrors
// localHealthCheckFn); in production it reads Incus's own resource inventory,
// the same source GetSystemInfo uses.
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
	var sum float64
	for i := range containers {
		c := &containers[i]
		if c.Role.IsCoreRole() {
			continue
		}
		if c.Name == selfName || c.Tenant == username {
			continue
		}
		sum += incus.CommittedCores(c.CPU)
	}
	return sum, nil
}
