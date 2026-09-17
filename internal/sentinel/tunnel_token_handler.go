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
		// needs to re-handshake after that restart.
		//
		// The in-memory Allow above stays applied even on a persist failure
		// below — same "safe direction" as the deregister handler's Deny:
		// the token is already valid for this process's lifetime either
		// way, and undoing it would drop a legitimate, just-joined host's
		// live tunnel session for no reason.
		//
		// But reporting SUCCESS when the durable record wasn't actually
		// written was the bug (#1772): the caller had no way to know its
		// token wouldn't survive a restart, and the gap surfaced days
		// later, indirectly, as an unexplained permanent disconnect after
		// an unrelated reboot — no error at the time it mattered, no
		// signal at restart time either. Report the failure as retryable
		// instead: a caller that retries lands on the same idempotent
		// Allow and gets a fresh chance to persist.
		if err := m.persistTunnelToken(req.Token, pools); err != nil {
			log.Printf("[sentinel] ERROR: failed to persist tunnel token registration (token allowed in-memory now, but WILL be lost on the next restart): %v", err)
			http.Error(w, `{"error":"token allowed but persistence failed; retry"}`, http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// TunnelTokenDeregisterRequest is the JSON body sent to
// TunnelTokenDeregisterHandler to revoke a previously-registered token.
type TunnelTokenDeregisterRequest struct {
	// Token is the tunnel-handshake token to revoke — the inverse of
	// TunnelTokenRegisterRequest.Token.
	Token string `json:"token"`
}

// TunnelTokenDeregisterHandler is TunnelTokenRegisterHandler's inverse
// (cloud#999 step 4): it makes a previously-registered tunnel token stop
// validating, without a sentinel restart. Exists so decommissioning a BYOC
// host can purge its tunnel-token registration from the sentinel — until
// now, RegisterTunnelToken had no way to be undone short of restarting the
// sentinel with a different --tunnel-token-policy.
//
// Gated by the SAME admin secret as registration (deliberately not the
// cluster-wide daemon HMAC secret) — deregistering another host's token is
// at least as sensitive a capability as registering one; a compromised
// daemon must not be able to knock any other host off its tunnel just
// because it holds the intra-cluster keysync secret.
//
// Deregistering a token that was never registered (or already was) is
// success, not an error: a decommission caller cannot know in advance
// whether registration ever landed, and the end state — this token does
// not validate — is identical either way.
func (m *Manager) TunnelTokenDeregisterHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		if m.tunnelPolicy == nil {
			http.Error(w, `{"error":"tunnel mode not enabled on this sentinel","code":501}`, http.StatusNotImplemented)
			return
		}
		var req TunnelTokenDeregisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
			return
		}
		if req.Token == "" {
			http.Error(w, `{"error":"token is required"}`, http.StatusBadRequest)
			return
		}
		m.tunnelPolicy.Deny(req.Token)
		// The in-memory Deny above stays applied even on a persist failure
		// below — that's the safe direction, and undoing it would put a
		// token BACK in effect that the caller just asked to revoke.
		//
		// But unlike the register side's best-effort persist (a disk
		// hiccup there just means a legitimate host has to re-register —
		// annoying, not dangerous), reporting SUCCESS here when the durable
		// record wasn't actually written is a real problem: this is the
		// call a decommission flow depends on to make sure a revoked token
		// can never come back, and a caller that believed 204 has no reason
		// to retry. Report the failure as retryable instead (review
		// follow-up on cloud#999 step 4).
		if err := m.unpersistTunnelToken(req.Token); err != nil {
			log.Printf("[sentinel] ERROR: failed to persist tunnel token deregistration (token denied in-memory now, but the on-disk store still lists it and it WILL reappear on the next restart): %v", err)
			http.Error(w, `{"error":"token denied but persistence failed; retry"}`, http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
