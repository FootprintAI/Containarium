// Package wake implements the "wake-on-HTTP" piece of the auto-sleep
// feature: when an auto-sleeping container's HTTP route is hit, Caddy
// proxies the request to the daemon's wake handler, the handler starts
// the container and waits until it's ready, then proxies the request
// through. Caddy's route is also flipped back to point at the container
// directly so subsequent requests bypass the daemon.
//
// The package contains three small pieces:
//
//   - WakeStateTracker: in-memory map of "which container names are
//     currently in wake mode". Read by RouteSyncJob before pushing a
//     route's upstream to Caddy — if the container is in wake mode,
//     RouteSync pushes the wake-handler address instead of the route's
//     direct target IP/port. Without this coordination the next
//     RouteSync tick (every ~5–30s) would silently revert the swap.
//
//   - Router: applies a route swap. On sleep, points Caddy at the
//     daemon's wake address and marks the tracker. On start, points
//     Caddy back at the container and clears the tracker.
//
//   - WakeProxy: HTTP handler at /wake/. Resolves the incoming Host
//     header to a container, wakes it (coalescing concurrent requests),
//     then reverse-proxies through to the now-running container. Also
//     fires-and-forgets a SwapToDirect so subsequent requests skip the
//     daemon entirely.
package wake

import (
	"sync"
)

// WakeStateTracker is the source of truth for "which usernames are
// currently in wake mode" — i.e. their Caddy route is pointing at the
// daemon's wake proxy instead of the container. RouteSyncJob consults
// this to avoid reverting wake-mode routes back to direct upstream.
//
// All entries are keyed on the Incus container name (e.g.
// "alice-container"), matching how RouteRecord.ContainerName is keyed.
// The map is rebuilt from in-memory state on daemon restart; that's
// intentional — after a daemon restart, RouteSync will publish all
// routes as direct, and any sleeping container will be woken back into
// wake mode on the next StopForAutoSleep tick.
type WakeStateTracker struct {
	mu     sync.RWMutex
	inWake map[string]WakeEntry
}

// WakeEntry records what the Caddy upstream was swapped to for a
// container in wake mode. RouteSyncJob reads this so it can push the
// same address on subsequent ticks rather than the route's direct
// TargetIP/TargetPort (which would revert the swap).
type WakeEntry struct {
	Subdomain string // route ID inside Caddy (route.Subdomain or FullDomain)
	WakeHost  string // daemon's IP that Caddy can reach, e.g. "10.0.3.1"
	WakePort  int    // daemon's HTTP port, e.g. 8080
}

// New constructs an empty tracker. Cheap; one per daemon.
func New() *WakeStateTracker {
	return &WakeStateTracker{inWake: make(map[string]WakeEntry)}
}

// MarkWakeMode records that a container is now in wake mode. Idempotent
// — calling it twice with the same containerName overwrites the prior
// entry, which is fine because the wakeHost/wakePort don't change at
// runtime.
func (w *WakeStateTracker) MarkWakeMode(containerName, subdomain, wakeHost string, wakePort int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.inWake[containerName] = WakeEntry{
		Subdomain: subdomain,
		WakeHost:  wakeHost,
		WakePort:  wakePort,
	}
}

// ClearWakeMode removes a container from wake mode. Safe to call when
// the container isn't in the map (no-op).
func (w *WakeStateTracker) ClearWakeMode(containerName string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.inWake, containerName)
}

// IsInWakeMode returns the (wakeHost, wakePort, ok) for a container.
//
// The signature is intentionally the (host, port, ok) triple rather
// than (WakeEntry, ok): RouteSyncJob — the heaviest reader — only
// needs the host/port to push to Caddy, and shaping the return this
// way lets it consume the tracker via an interface in package `app`
// without `app` having to import package `wake` (which would create
// an import cycle, since wake itself imports app for RouteRecord).
func (w *WakeStateTracker) IsInWakeMode(containerName string) (string, int, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	e, ok := w.inWake[containerName]
	if !ok {
		return "", 0, false
	}
	return e.WakeHost, e.WakePort, true
}

// Entry returns the full WakeEntry for a container if present. Used by
// tests and diagnostics. Production code paths that just need the
// host/port should use IsInWakeMode.
func (w *WakeStateTracker) Entry(containerName string) (WakeEntry, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	e, ok := w.inWake[containerName]
	return e, ok
}

// Snapshot returns a copy of the current wake map. Useful for tests and
// for diagnostics. The copy is independent — callers can iterate
// without holding the lock.
func (w *WakeStateTracker) Snapshot() map[string]WakeEntry {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make(map[string]WakeEntry, len(w.inWake))
	for k, v := range w.inWake {
		out[k] = v
	}
	return out
}
