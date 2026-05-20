package sentinel

import (
	"encoding/json"
	"net/http"
)

// CAHandler returns the peer-CA certificate PEM that daemons pin
// when calling other peers over HTTPS. Wrapped by the existing
// HMAC middleware (auth.SentinelHMACMiddleware) when registered —
// only callers that hold CONTAINARIUM_SENTINEL_AUTH_SECRET can
// fetch it.
//
// 503 when no peer-CA is configured. The daemon's bootstrap code
// uses that as a signal to fall back to plain HTTP (rollout mode);
// once the CA is on every sentinel the daemon should refuse to
// start.
func (m *Manager) CAHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		caPEM := m.CACertPEM()
		if caPEM == nil {
			http.Error(w, `{"error":"peer CA not configured on this sentinel","code":503}`, http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(caPEM)
	}
}

// PeerCertRequest is the JSON body POSTed to PeerCertHandler.
type PeerCertRequest struct {
	PeerID string `json:"peer_id"`
}

// PeerCertResponse carries the issued cert + key + CA bundle.
// `key_pem` is the leaf's *private* key — only ever returned over
// the HMAC-gated channel and never persisted server-side. The
// daemon writes it to a mode-0600 path on its own disk.
type PeerCertResponse struct {
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
	CAPEM   string `json:"ca_pem"`
}

// PeerCertHandler issues a fresh peer-leaf cert for the requested
// peer ID. POSTed by a daemon at startup (and on cert renewal).
//
// Authentication: caller must have signed the request with the
// shared HMAC secret (the wrapping middleware enforces this). The
// peer_id is taken from the request body — same trust model as the
// existing /authorized-keys flow.
//
// Future hardening: bind the issuance to a tunnel-proven identity
// so two peers can't impersonate each other even if they share the
// HMAC secret. Tracked in docs/security/ZERO-TRUST-TODO.md.
func (m *Manager) PeerCertHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		var req PeerCertRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
			return
		}
		if req.PeerID == "" {
			http.Error(w, `{"error":"peer_id is required"}`, http.StatusBadRequest)
			return
		}

		certPEM, keyPEM, err := m.IssuePeerCert(req.PeerID)
		if err != nil {
			http.Error(w, `{"error":"peer CA not configured on this sentinel","code":503}`, http.StatusServiceUnavailable)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(PeerCertResponse{
			CertPEM: string(certPEM),
			KeyPEM:  string(keyPEM),
			CAPEM:   string(m.CACertPEM()),
		})
	}
}
