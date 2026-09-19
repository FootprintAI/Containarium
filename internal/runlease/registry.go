package runlease

import "sync"

// Info is what other daemon components need to know about a
// currently-running skill run, keyed by run id — enough to resolve a
// verified JWT's run_id claim to the skill/model it belongs to, e.g.
// for the tracker broker's platform-stamped identity (#1922).
type Info struct {
	SkillID string
	Model   string
}

// Registry is an in-memory, in-process record of currently-live runs.
// Populated when a run starts and removed when its lease ends — see
// Register/Unregister. Deliberately NOT durable and NOT shared across
// daemon instances; see Live's doc comment for what that means for a
// caller.
type Registry struct {
	mu   sync.RWMutex
	runs map[string]Info
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{runs: make(map[string]Info)}
}

// Register records that runID has started. Call once a run's box has
// actually been provisioned — never before, so a run is never "live"
// for a provisioning attempt that didn't succeed.
func (r *Registry) Register(runID string, info Info) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.runs[runID] = info
}

// Unregister removes runID. Safe to call for a run id that was never
// registered (a no-op delete) — callers don't need to track whether
// Register actually ran before calling this at lease-end.
func (r *Registry) Unregister(runID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.runs, runID)
}

// Get returns the recorded Info for runID, if it's currently live.
func (r *Registry) Get(runID string) (Info, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	info, ok := r.runs[runID]
	return info, ok
}

// Live reports whether runID is currently registered in THIS daemon
// process.
//
// This is a single-process, in-memory view: it does not see a run
// live on another daemon instance, and it forgets everything on
// restart. The tracker broker's ClaimTrackerIssue design (#1922)
// accounts for exactly this gap with a `stale_after` window (default
// 2h) — a claim marker whose run isn't Live here is still honored if
// it's younger than that window, rather than requiring cross-daemon
// liveness, which this registry deliberately does not attempt to
// provide.
func (r *Registry) Live(runID string) bool {
	_, ok := r.Get(runID)
	return ok
}
