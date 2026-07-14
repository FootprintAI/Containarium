package sentinel

import (
	"encoding/json"
	"log"
	"net/http"
)

// TunnelTokenRegisterRequest is the JSON body POSTed to
// TunnelTokenRegisterHandler to make a freshly-issued join token valid
// on this already-running sentinel.
type TunnelTokenRegisterRequest struct {
	// Token is the tunnel-handshake token to authorize (opaque string,
	// matched verbatim against TunnelHandshake.Token).
	Token string `json:"token"`

	// Pools lists the pools this token may join. Empty/omitted means
	// PoolAny — the common case for a one-off BYOC join token, which
	// isn't scoped to a specific pool ahead of time.
	Pools []Pool `json:"pools,omitempty"`
}

// TunnelTokenRegisterHandler lets an authorized caller (the cloud
// control plane's token-issuance service, or an operator) register a
// tunnel-join token on a running sentinel without a restart.
//
// The sentinel's TokenPolicy is otherwise 100% static — built once at
// startup from --tunnel-token/--tunnel-token-policy CLI flags (see
// PolicyFromCLI) — so a token minted after the sentinel started had no
// way to ever become valid; every handshake using it failed with
// "invalid token" regardless of how fresh or correctly-formed the
// token was. This endpoint is the missing runtime path.
//
// Gated by CONTAINARIUM_SENTINEL_ADMIN_SECRET — deliberately not the
// same secret as CONTAINARIUM_SENTINEL_AUTH_SECRET, which every
// cluster daemon already holds for keysync/certsync. Admitting a
// brand-new node into a pool is a materially bigger capability than
// those intra-cluster operations; a compromised daemon shouldn't be
// able to mint join tokens for other pools just because it has the
// cluster-wide keysync secret.
func (m *Manager) TunnelTokenRegisterHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		if m.tunnelPolicy == nil {
			http.Error(w, `{"error":"tunnel mode not enabled on this sentinel","code":501}`, http.StatusNotImplemented)
			return
		}
		var req TunnelTokenRegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
			return
		}
		if req.Token == "" {
			http.Error(w, `{"error":"token is required"}`, http.StatusBadRequest)
			return
		}
		pools := req.Pools
		if len(pools) == 0 {
			pools = []Pool{PoolAny}
		}
		m.tunnelPolicy.Allow(req.Token, pools...)
		// Persist so this registration survives a sentinel restart (#936) —
		// TokenPolicy itself is pure in-memory and would otherwise silently
		// forget every dynamically-registered token the moment this process
		// exits, permanently locking out any host whose tunnel session
		// needs to re-handshake after that restart. Best-effort: a
		// persistence failure must not fail a legitimate BYOC join, since
		// the token is already valid for this process's lifetime either
		// way — it only affects survival across a *future* restart.
		if err := m.persistTunnelToken(req.Token, pools); err != nil {
			log.Printf("[sentinel] WARNING: failed to persist tunnel token registration (won't survive a restart): %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
