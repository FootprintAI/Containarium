package sentinel

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// Event-driven key resync (cloud #971).
//
// The sentinel learns about a box's SSH key by polling each backend's
// /authorized-keys on a ticker (RunSyncLoop, default 2m). A box created just
// after a tick is therefore RUNNING — and correct in every other respect —
// while sshpiper has no pipe for it, so SSH answers
// `Permission denied (publickey)` until the next tick. That is a 0–120s
// window, mean ~60s, which is exactly the ~50s users measured.
//
// This endpoint closes the window without shortening the tick: the daemon
// tells the sentinel "my key set changed, pull it now" whenever it installs
// or removes a host-side authorized_keys entry. The ticker stays as the
// convergence backstop for anything the notification missed (daemon crash
// mid-create, sentinel restart, a notification lost in flight).

// KeyResyncRequest is the JSON body POSTed to KeyResyncHandler by a daemon
// whose host-side authorized_keys set just changed.
type KeyResyncRequest struct {
	// BackendID identifies which backend to re-pull. Empty falls back to
	// resolving the backend by the request's source IP, which covers a
	// daemon that hasn't been told its own backend ID.
	BackendID string `json:"backend_id,omitempty"`

	// Reason is free-form and logged only (e.g. "create_container
	// cld-1a2b3c") so an operator reading sentinel logs can tell an
	// event-driven sync from a periodic one.
	Reason string `json:"reason,omitempty"`
}

// KeyResyncResponse reports what the resync did, so the daemon can log
// something more useful than "sent".
type KeyResyncResponse struct {
	// Synced is true when this call resulted in the backend's key set
	// being current — either this call pulled it, or a concurrent pull
	// that started after this request arrived already covered it.
	Synced bool `json:"synced"`

	// Users is the number of users the sentinel now routes for this
	// backend.
	Users int `json:"users"`

	// Coalesced is true when a concurrent resync covered this request and
	// no additional upstream fetch was issued.
	Coalesced bool `json:"coalesced,omitempty"`
}

// KeyResyncHandler pulls a backend's authorized keys immediately instead of
// waiting for the periodic tick, then rewrites the sshpiper routing table.
//
// Gated by the cluster-wide daemon HMAC secret
// (CONTAINARIUM_SENTINEL_AUTH_SECRET) at the mux, the same secret that
// already authenticates the sentinel's own pull of /authorized-keys. This is
// deliberately NOT the admin secret: re-reading a backend's own key set is
// not an authority decision, and the worst a holder of the daemon secret can
// do here is ask the sentinel to do work it already does on a timer. The
// handler never accepts key material from the request — it only triggers the
// authenticated pull, so a caller cannot inject a key for a box it doesn't
// own.
func (m *Manager) KeyResyncHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		if m.keyStore == nil {
			http.Error(w, `{"error":"keysync not enabled on this sentinel","code":501}`, http.StatusNotImplemented)
			return
		}

		var req KeyResyncRequest
		// An empty body is a valid "resync whoever I am" request (the
		// backend is then resolved by source IP), so only malformed JSON
		// is a client error.
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
			return
		}

		backend := m.resolveResyncBackend(req.BackendID, r.RemoteAddr)
		if backend == nil {
			http.Error(w, `{"error":"unknown backend","code":404}`, http.StatusNotFound)
			return
		}

		coalesced := m.resyncBackendKeys(backend)

		// Report what actually happened, not merely that we tried:
		// syncAndApply swallows a failed pull (it logs and lets the next
		// tick retry), so without this the daemon would log "key is live"
		// for a backend whose keys never arrived — the exact false
		// confidence this endpoint exists to remove.
		users, syncErr := m.keyStore.lastSyncResult(backend.ID)
		log.Printf("[keysync] event-driven resync for backend %s: %d users (coalesced=%v, ok=%v, reason=%q)",
			backend.ID, users, coalesced, syncErr == nil, req.Reason)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(KeyResyncResponse{
			Synced:    syncErr == nil,
			Users:     users,
			Coalesced: coalesced,
		})
	}
}

// resolveResyncBackend finds the backend to re-pull: by ID when the caller
// supplied one, otherwise by matching the request's source IP against the
// registered backends. Returns nil when neither resolves.
func (m *Manager) resolveResyncBackend(backendID, remoteAddr string) *Backend {
	if backendID != "" {
		return m.backends.Get(backendID)
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	if host == "" {
		return nil
	}
	for _, b := range m.backends.All() {
		if b.IP == host {
			return b
		}
	}
	return nil
}

// resyncBackendKeys pulls one backend's keys and rewrites the sshpiper
// config, serializing concurrent resyncs for the same backend. It returns
// true when a concurrent resync already covered this caller.
//
// Coalescing is correctness-preserving, not a rate limit: a sync pulls the
// backend's FULL key set, so any sync that started after this call arrived
// necessarily contains this caller's key. Skipping on that condition alone
// can never drop a key — whereas a time-based "synced recently, skip it"
// rate limit would, by matching a caller against a sync that ran before its
// key existed. That distinction is the whole bug this endpoint fixes, so it
// must not be reintroduced here.
func (m *Manager) resyncBackendKeys(b *Backend) bool {
	arrived := time.Now()

	gate := m.resyncGate(b.ID)
	gate.mu.Lock()
	defer gate.mu.Unlock()

	if gate.lastStart.After(arrived) {
		return true
	}
	gate.lastStart = time.Now()
	m.keyStore.syncAndApply(b.ID, b.IP, m.config.HealthPort)
	return false
}

// resyncGate returns the per-backend serialization gate, creating it on
// first use.
func (m *Manager) resyncGate(backendID string) *keyResyncGate {
	m.keyResyncMu.Lock()
	defer m.keyResyncMu.Unlock()
	if m.keyResyncGates == nil {
		m.keyResyncGates = make(map[string]*keyResyncGate)
	}
	g, ok := m.keyResyncGates[backendID]
	if !ok {
		g = &keyResyncGate{}
		m.keyResyncGates[backendID] = g
	}
	return g
}

// keyResyncGate serializes resyncs for one backend and records when the last
// one started, so a waiting caller can tell whether it was already covered.
type keyResyncGate struct {
	mu        sync.Mutex
	lastStart time.Time
}

// lastSyncResult reports how many users the store currently routes for a
// backend and the error from that backend's most recent pull (nil when it
// succeeded). A backend that has never been synced reports (0, nil).
func (ks *KeyStore) lastSyncResult(backendID string) (int, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	bk, ok := ks.backends[backendID]
	if !ok {
		return 0, nil
	}
	return len(bk.users), bk.lastErr
}
