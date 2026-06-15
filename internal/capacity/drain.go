package capacity

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// DefaultDrainWindow is the bounded wall-clock budget a drain gets to evict the
// guest workloads a backend had implicitly offered as headroom. Picked to be
// generous enough for a clean per-workload graceful stop (the backend's stop
// path issues a SIGTERM with its own 30s timeout) across a handful of guests,
// while still being short enough that a control plane reclaiming the host is
// not left waiting indefinitely.
const DefaultDrainWindow = 120 * time.Second

// DrainStopper is the narrow capability the drainer needs: stop one workload,
// optionally forcing it. ContainerServer satisfies this by routing through the
// same StopContainer plumbing a manual stop uses, so a drained workload is
// indistinguishable on the event bus from any other stop and the control plane
// can reschedule it. Kept as an interface so the drain logic is unit-testable
// without the full server import graph.
type DrainStopper interface {
	// StopWorkload gracefully stops the workload owned by username. When force
	// is true the stop must not block on a graceful shutdown (the bounded window
	// has been exhausted). The implementation owns its own per-call timeout. The
	// username is the daemon's routing key — the same one StopContainer takes —
	// not the raw container name.
	StopWorkload(ctx context.Context, username string, force bool) error
}

// DrainCandidate is one guest workload selected for reclaim. Core-service and
// policy-excluded workloads are filtered out by the caller (DrainCandidates)
// before they ever reach the drainer, so the drainer treats every candidate as
// fair game. ContainerName is the display/audit identity; Username is the
// daemon routing key handed to the stopper (the same key StopContainer uses).
type DrainCandidate struct {
	ContainerName string
	Username      string
}

// DrainResult records what a single drain pass did. It is the audit trail the
// withdraw handler surfaces to the control plane: which workloads drained
// gracefully, which had to be force-stopped because the window ran out, and
// which failed outright.
type DrainResult struct {
	// Drained are workloads that stopped gracefully within the window.
	Drained []string
	// ForceStopped are workloads still running when the window expired; they
	// were force-stopped so the host is reliably reclaimed (no wedge).
	ForceStopped []string
	// Failed are workloads whose stop returned an error even after the force
	// fallback. The container name maps to the last error string.
	Failed map[string]string
	// WindowExceeded is true when the graceful budget was exhausted and the
	// drainer fell back to force-stopping the remainder.
	WindowExceeded bool
	// Elapsed is the wall-clock time the drain took.
	Elapsed time.Duration
}

// Drainer performs a bounded graceful reclaim of guest workloads. It is the
// new graceful-drain-with-window primitive the reclaim path needed: there was
// previously only a single-shot StopContainer (with an optional hard force) and
// the cutover stop inside MoveContainer — neither bounds a multi-workload
// graceful drain. The Drainer wraps the existing per-workload stop path with a
// total-window budget and a force fallback so a host that withdraws headroom is
// reliably reclaimed without hard-killing live guests up front.
//
// A single in-flight drain at a time is enforced by mu. Repeated
// advertise/withdraw cycles therefore cannot stack overlapping drains and wedge
// the host with N concurrent stop storms — a withdraw that arrives while a
// drain is already running is coalesced (Drain returns the in-flight guard's
// zero result via skipped=true) rather than spawning a second pass.
type Drainer struct {
	stopper DrainStopper

	mu       sync.Mutex
	draining bool

	// nowFn is injectable for deterministic tests of the window/deadline logic.
	// Production uses time.Now.
	nowFn func() time.Time
}

// NewDrainer builds a Drainer over the given stop capability.
func NewDrainer(stopper DrainStopper) *Drainer {
	return &Drainer{stopper: stopper, nowFn: time.Now}
}

// DrainCandidates selects the guest workloads a backend should reclaim when it
// withdraws headroom. It mirrors hostIdle's filtering exactly — core-service
// roles and policy-excluded workload classes are never candidates — so the set
// drained is precisely the set the backend was implicitly offering as spare.
// Stopped containers are skipped (nothing to drain). Pure; the caller passes a
// HostState snapshot.
func DrainCandidates(p Policy, st HostState) []DrainCandidate {
	var out []DrainCandidate
	for _, c := range st.Containers {
		if c.Role.IsCoreRole() {
			continue
		}
		if c.State != "Running" {
			continue
		}
		if p.excludes(c.Labels[WorkloadClassLabel]) {
			continue
		}
		// Username is the daemon's stop-routing key; fall back to the container
		// name when the host doesn't report one (the name-convention case).
		username := c.Username
		if username == "" {
			username = c.Name
		}
		out = append(out, DrainCandidate{ContainerName: c.Name, Username: username})
	}
	return out
}

// Drain reclaims the given candidates within the bounded window. It attempts a
// graceful stop of each candidate in turn; once the window is exhausted any
// remaining candidates (including the in-flight one's successors) are
// force-stopped so the host is reliably reclaimed. A window <= 0 falls back to
// DefaultDrainWindow.
//
// skipped is true when another drain was already in flight; in that case the
// returned result is zero and no stops are issued (the cycle is coalesced).
//
// Drain never returns an error: a per-workload stop failure is recorded in
// DrainResult.Failed and the drain proceeds to the next candidate, because a
// stuck single guest must not block reclaiming the rest of the host.
func (d *Drainer) Drain(ctx context.Context, candidates []DrainCandidate, window time.Duration) (DrainResult, bool) {
	d.mu.Lock()
	if d.draining {
		d.mu.Unlock()
		return DrainResult{}, true
	}
	d.draining = true
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		d.draining = false
		d.mu.Unlock()
	}()

	if window <= 0 {
		window = DefaultDrainWindow
	}
	start := d.now()
	deadline := start.Add(window)

	res := DrainResult{Failed: map[string]string{}}

	for _, c := range candidates {
		// Past the window: force-stop the remainder so the host is reclaimed
		// promptly. force=true skips the graceful shutdown wait, bounding the
		// total time the drain can consume.
		forced := !d.now().Before(deadline)
		if forced {
			res.WindowExceeded = true
		}

		if err := d.stopper.StopWorkload(ctx, c.Username, forced); err != nil {
			// Graceful attempt failed and we still have window left: try once
			// more with force before giving up, so a guest that ignores
			// SIGTERM is still reclaimed rather than left running.
			if !forced {
				if ferr := d.stopper.StopWorkload(ctx, c.Username, true); ferr != nil {
					res.Failed[c.ContainerName] = ferr.Error()
					log.Printf("[drain] force-stop %s failed: %v", c.ContainerName, ferr)
					continue
				}
				res.ForceStopped = append(res.ForceStopped, c.ContainerName)
				continue
			}
			res.Failed[c.ContainerName] = err.Error()
			log.Printf("[drain] force-stop %s failed: %v", c.ContainerName, err)
			continue
		}

		if forced {
			res.ForceStopped = append(res.ForceStopped, c.ContainerName)
		} else {
			res.Drained = append(res.Drained, c.ContainerName)
		}

		// Cancellation cuts the drain short — the caller's context expiring is a
		// stronger bound than the window. Remaining candidates are left for a
		// subsequent reconcile/withdraw to pick up.
		if ctx.Err() != nil {
			break
		}
	}

	res.Elapsed = d.now().Sub(start)
	return res, false
}

// now returns the drainer's clock (injectable for tests).
func (d *Drainer) now() time.Time {
	if d.nowFn != nil {
		return d.nowFn()
	}
	return time.Now()
}

// assert the incus container info shape is what DrainCandidates reads, so a
// field rename upstream is caught at compile time rather than silently
// selecting an empty candidate set.
var _ = func(c incus.ContainerInfo) (string, string) { return c.Name, c.State }
