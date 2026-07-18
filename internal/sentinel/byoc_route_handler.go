package sentinel

import (
	"encoding/json"
	"log"
	"net/http"
)

// BYOCRouteSyncRequest is the JSON body POSTed to BYOCRouteRegisterHandler
// by the cloud to push the FULL authoritative set of BYOC public-ingress
// bindings. Full-set (not delta): the sentinel replaces its map wholesale,
// so a binding the cloud dropped disappears without a separate delete, and
// the state converges after a sentinel restart or a missed event. #733.
type BYOCRouteSyncRequest struct {
	Routes []BYOCRoute `json:"routes"`
}

// BYOCRouteRegisterHandler lets the cloud control plane push the
// authoritative `subdomain → BYOC host` bindings onto a running sentinel.
// The sentinel's SNI router consults these to terminate TLS for a tenant
// subdomain and plaintext-forward to the box over the tunnel (#733).
//
// Gated by CONTAINARIUM_SENTINEL_ADMIN_SECRET (the same higher-privilege
// secret that guards tunnel-token registration) — deliberately NOT the
// cluster-wide CONTAINARIUM_SENTINEL_AUTH_SECRET every daemon holds.
// Binding a public hostname to a backend is an authority decision: only
// the cloud may make it, and a host must never be able to claim a
// hostname itself (anti-hijack).
func (m *Manager) BYOCRouteRegisterHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		if m.byocRoutes == nil {
			http.Error(w, `{"error":"byoc ingress not enabled on this sentinel","code":501}`, http.StatusNotImplemented)
			return
		}
		var req BYOCRouteSyncRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
			return
		}

		m.byocRoutes.ReplaceAll(req.Routes)

		// Persist the (validated) current set so it survives a restart
		// without waiting for the cloud's next reconcile. Best-effort:
		// a persistence failure must not fail the push — the bindings are
		// already live for this process, and the cloud re-pushes on its
		// loop anyway.
		if err := m.persistBYOCRoutes(); err != nil {
			log.Printf("[sentinel] WARNING: failed to persist byoc routes (won't survive a restart until next cloud sync): %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// persistBYOCRoutes writes the registry's current snapshot to the store
// path. Safe to call with a nil store path (no-op) so tests and
// unconfigured deployments don't error.
func (m *Manager) persistBYOCRoutes() error {
	if m.byocRoutes == nil {
		return nil
	}
	path := m.byocRouteStorePath
	if path == "" {
		path = DefaultBYOCRouteStorePath
	}
	return SaveBYOCRouteStore(path, m.byocRoutes.Snapshot())
}
