package sentinel

import (
	"context"
	"sync"
)

// BackendType identifies the kind of backend.
type BackendType string

const (
	BackendGCP    BackendType = "gcp"
	BackendTunnel BackendType = "tunnel"
)

// Backend represents a single backend instance that the sentinel can forward to.
type Backend struct {
	ID           string
	Type         BackendType
	IP           string
	ExternalPort int           // externally reachable API port (for tunnel backends, e.g., 18001)
	Provider     CloudProvider // for diagnose/recover (GCP can restart VMs; tunnel cannot)
	Priority     int           // lower = higher priority for HTTP primary selection (GCP=0, tunnel=10)

	// Per-backend health tracking
	Healthy        bool
	healthyCount   int
	unhealthyCount int

	// Sync loop cancellation
	syncCancel context.CancelFunc
}

// BackendPool manages multiple backends with thread-safe access.
type BackendPool struct {
	mu       sync.RWMutex
	backends map[string]*Backend
}

// NewBackendPool creates an empty backend pool.
func NewBackendPool() *BackendPool {
	return &BackendPool{
		backends: make(map[string]*Backend),
	}
}

// Add registers a backend. If a backend with the same ID exists, it is replaced.
func (bp *BackendPool) Add(b *Backend) {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	// Cancel old sync loops if replacing
	if old, ok := bp.backends[b.ID]; ok && old.syncCancel != nil {
		old.syncCancel()
	}
	bp.backends[b.ID] = b
}

// Remove unregisters a backend and cancels its sync loops.
func (bp *BackendPool) Remove(id string) *Backend {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	b, ok := bp.backends[id]
	if !ok {
		return nil
	}
	if b.syncCancel != nil {
		b.syncCancel()
	}
	delete(bp.backends, id)
	return b
}

// Get returns a backend by ID, or nil.
func (bp *BackendPool) Get(id string) *Backend {
	bp.mu.RLock()
	defer bp.mu.RUnlock()
	return bp.backends[id]
}

// All returns a snapshot of all backends.
func (bp *BackendPool) All() []*Backend {
	bp.mu.RLock()
	defer bp.mu.RUnlock()
	result := make([]*Backend, 0, len(bp.backends))
	for _, b := range bp.backends {
		result = append(result, b)
	}
	return result
}

// Healthy returns all backends currently marked healthy.
func (bp *BackendPool) Healthy() []*Backend {
	bp.mu.RLock()
	defer bp.mu.RUnlock()
	var result []*Backend
	for _, b := range bp.backends {
		if b.Healthy {
			result = append(result, b)
		}
	}
	return result
}

// AnyHealthy returns true if at least one backend is healthy.
func (bp *BackendPool) AnyHealthy() bool {
	bp.mu.RLock()
	defer bp.mu.RUnlock()
	for _, b := range bp.backends {
		if b.Healthy {
			return true
		}
	}
	return false
}

// SelectPrimary returns the best healthy backend for HTTP forwarding.
// Prefers lower Priority value (GCP=0 > Tunnel=10).
func (bp *BackendPool) SelectPrimary() *Backend {
	bp.mu.RLock()
	defer bp.mu.RUnlock()

	var best *Backend
	for _, b := range bp.backends {
		if !b.Healthy {
			continue
		}
		if best == nil || b.Priority < best.Priority {
			best = b
		}
	}
	return best
}

// Count returns the number of backends.
func (bp *BackendPool) Count() int {
	bp.mu.RLock()
	defer bp.mu.RUnlock()
	return len(bp.backends)
}
