package container

import (
	"sync"
	"time"
)

// existingContainerNamesCacheTTL bounds how stale ExistingContainerNames may
// be. /authorized-keys' orphan filter (#343) used to call ContainerExists —
// a live Incus round trip — once per home directory it enumerated; on a
// fleet-sized backend that serialized one round trip per tenant into a
// multi-second response, which the sentinel's event-driven key-resync push
// (#2018) intermittently timed out against (a 5s budget). A TTL this short
// is well inside every staleness tolerance the rest of the system already
// has — the periodic keysync poll itself runs on a multi-minute interval,
// and the push's own timeout is a handful of seconds — it only stops one
// HTTP request from taking a live inventory pass per tenant it happens to
// enumerate.
const existingContainerNamesCacheTTL = 2 * time.Second

// containerNameCache is Manager's cached view of ListContainers, keyed by
// container name (e.g. "alice-container") exactly as ContainerExists checks.
type containerNameCache struct {
	mu        sync.Mutex
	names     map[string]bool
	fetchedAt time.Time
}

// ExistingContainerNames returns the set of live container names, refreshed
// via a single ListContainers call at most once per TTL (existingContainerNamesCacheTTL,
// or Manager.nameCacheTTL in a test). Concurrent callers within the same TTL
// window all share one Incus round trip.
//
// On a refresh failure, the last good snapshot is served instead of the
// error — matching ContainerExists' own per-container semantics, where one
// backend's live-call failure only ever affected that one container's
// answer, never every other container's. Only the very first call (nothing
// cached yet) has no snapshot to fall back to and returns the error; callers
// should treat that case the same way a nil orphan filter is already treated
// elsewhere (i.e., don't filter, rather than drop every tenant on one
// transient Incus hiccup — a batched check's blast radius on failure is the
// whole fleet, not one tenant, so failing this open is the safer default).
func (m *Manager) ExistingContainerNames() (map[string]bool, error) {
	m.nameCache.mu.Lock()
	defer m.nameCache.mu.Unlock()

	ttl := m.nameCacheTTL
	if ttl <= 0 {
		ttl = existingContainerNamesCacheTTL
	}
	if m.nameCache.names != nil && time.Since(m.nameCache.fetchedAt) < ttl {
		return m.nameCache.names, nil
	}

	containers, err := m.incus.ListContainers()
	if err != nil {
		if m.nameCache.names != nil {
			return m.nameCache.names, nil
		}
		return nil, err
	}

	names := make(map[string]bool, len(containers))
	for _, c := range containers {
		names[c.Name] = true
	}
	m.nameCache.names = names
	m.nameCache.fetchedAt = time.Now()
	return names, nil
}
