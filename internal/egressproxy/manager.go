package egressproxy

import (
	"context"
	"sync"
)

// Manager tracks per-key egress relays (keyed by box/container name) so the
// daemon can start one when an operator requests "egress via client" and tear
// it down on stop / disconnect. Lifetimes are process-local and ephemeral —
// relays are not persisted across a daemon restart (the operator's ssh -R dies
// with the daemon anyway, so a stale relay would be useless).
type Manager struct {
	mu     sync.Mutex
	relays map[string]context.CancelFunc
}

// NewManager returns an empty Manager.
func NewManager() *Manager {
	return &Manager{relays: make(map[string]context.CancelFunc)}
}

// Start (re)starts the relay for key. Any existing relay for the same key is
// torn down first (idempotent re-invoke). It binds synchronously so a bind
// error is returned to the caller; on success it returns the actually-bound
// listen address (useful when listen used port 0). logf may be nil.
func (m *Manager) Start(key, listen, upstream string, allow []string, logf func(string, ...any)) (string, error) {
	r, err := New(listen, upstream, allow, logf)
	if err != nil {
		return "", err
	}

	// Tear down a prior relay for this key before binding the new one, so the
	// new listener doesn't collide with the old on the same port.
	m.stop(key)

	ctx, cancel := context.WithCancel(context.Background())
	if err := r.StartBackground(ctx); err != nil {
		cancel()
		return "", err
	}

	m.mu.Lock()
	m.relays[key] = cancel
	m.mu.Unlock()
	return r.Addr(), nil
}

// Stop tears down the relay for key, reporting whether one was running.
func (m *Manager) Stop(key string) bool {
	return m.stop(key)
}

func (m *Manager) stop(key string) bool {
	m.mu.Lock()
	cancel, ok := m.relays[key]
	if ok {
		delete(m.relays, key)
	}
	m.mu.Unlock()
	if ok {
		cancel()
	}
	return ok
}

// Active reports the number of running relays (for observability/tests).
func (m *Manager) Active() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.relays)
}
