package sentinel

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

// AuditIngestTokenRegisterRequest is the JSON body POSTed to
// AuditIngestTokenRegisterHandler.
type AuditIngestTokenRegisterRequest struct {
	// BackendID is the sentinel's id for the backend (the same id keysync
	// and the backend pool use).
	BackendID string `json:"backend_id"`
	// Token is a JWT minted ON that backend with the audit:ingest scope.
	Token string `json:"token"`
}

// AuditIngestTokenDeregisterRequest is the JSON body sent (DELETE) to
// AuditIngestTokenDeregisterHandler.
type AuditIngestTokenDeregisterRequest struct {
	BackendID string `json:"backend_id"`
}

// SetAuditIngestTokenStorePath overrides where audit-ingest tokens are
// persisted. Tests point it at a tmp dir; production leaves it unset and
// uses DefaultAuditIngestTokenStorePath.
func (m *Manager) SetAuditIngestTokenStorePath(path string) {
	m.auditIngestTokenStorePath = path
}

// AuditIngestTokenStorePath returns the effective store path.
func (m *Manager) AuditIngestTokenStorePath() string {
	if m.auditIngestTokenStorePath != "" {
		return m.auditIngestTokenStorePath
	}
	return DefaultAuditIngestTokenStorePath
}

// AuditIngestTokenRegisterHandler registers (or rotates) the audit-ingest
// token for one backend. Gated by the sentinel ADMIN secret at the route,
// like tunnel-token registration: granting the sentinel write access to a
// backend's audit chain is an authority decision, not an intra-cluster
// operation, so the cluster-wide keysync secret must not be enough.
//
// The file is the source of truth (the shipper re-reads it every pass), so a
// success response means the token is durably on disk — a persist failure is
// a 500 and the caller retries, the same contract #1772 established for
// tunnel tokens.
func (m *Manager) AuditIngestTokenRegisterHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		var req AuditIngestTokenRegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
			return
		}
		if req.BackendID == "" {
			http.Error(w, `{"error":"backend_id is required"}`, http.StatusBadRequest)
			return
		}
		if req.Token == "" || strings.ContainsAny(req.Token, " \t\r\n") {
			http.Error(w, `{"error":"token is required and must not contain whitespace"}`, http.StatusBadRequest)
			return
		}

		m.auditIngestTokenStoreMu.Lock()
		defer m.auditIngestTokenStoreMu.Unlock()
		path := m.AuditIngestTokenStorePath()
		entries, err := LoadAuditIngestTokenStore(path)
		if err == nil {
			err = SaveAuditIngestTokenStore(path, upsertAuditIngestTokenEntry(entries, req.BackendID, req.Token))
		}
		if err != nil {
			log.Printf("[sentinel] ERROR: failed to persist audit-ingest token for backend %q: %v", req.BackendID, err)
			http.Error(w, `{"error":"token not persisted; retry"}`, http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// AuditIngestTokenDeregisterHandler removes a backend's audit-ingest token.
// Idempotent: removing one that was never registered is success, because the
// end state is the same and a decommission caller cannot know whether
// registration ever landed.
func (m *Manager) AuditIngestTokenDeregisterHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		var req AuditIngestTokenDeregisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
			return
		}
		if req.BackendID == "" {
			http.Error(w, `{"error":"backend_id is required"}`, http.StatusBadRequest)
			return
		}

		m.auditIngestTokenStoreMu.Lock()
		defer m.auditIngestTokenStoreMu.Unlock()
		path := m.AuditIngestTokenStorePath()
		entries, err := LoadAuditIngestTokenStore(path)
		if err == nil {
			err = SaveAuditIngestTokenStore(path, removeAuditIngestTokenEntry(entries, req.BackendID))
		}
		if err != nil {
			log.Printf("[sentinel] ERROR: failed to remove audit-ingest token for backend %q: %v", req.BackendID, err)
			http.Error(w, `{"error":"token not removed; retry"}`, http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
