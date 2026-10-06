package gateway

import (
	"net/http"
	"time"

	"github.com/footprintai/containarium/internal/auth"
)

// AnonDoorEnsurePath is the REST path grpc-gateway maps
// AnonymousBoxService.EnsureAnonymousBox to (anonbox.proto).
const AnonDoorEnsurePath = "/v1/anon/boxes:ensure"

// AnonDoorUsername is the subject a sentinel-signed EnsureAnonymousBox call
// acts as. It is not a tenant and holds no role — only the anon:door scope,
// which is the one thing the door needs.
const AnonDoorUsername = "sentinel-door"

// anonDoorHandler is the one place a /v1 route accepts the sentinel's own
// request signature instead of a JWT (#2197, design doc §"Sentinel ↔
// daemon": "the sentinel does not get a new secret").
//
// A request carrying the sentinel signature headers is verified by v and,
// on success, forwarded to inner with a door identity in its context —
// username AnonDoorUsername, no roles, scope anon:door. annotateContext
// turns that into the gRPC metadata EnsureAnonymousBox's
// RequireRoleOrScope reads, exactly as the JWT middleware's claims would.
// A request without those headers takes jwtHandler, the ordinary
// authenticated chain, so a token with anon:door (or admin) still works.
// A request that is signed but does not verify is 401 — it never falls
// through to the JWT path, so a bad signature cannot be "fixed" by a
// cookie that happens to be present.
func anonDoorHandler(v auth.SentinelVerifier, jwtHandler, inner http.Handler, now func() time.Time) http.Handler {
	if now == nil {
		now = time.Now
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(auth.SentinelHeaderSignature) == "" && r.Header.Get(auth.SentinelHeaderTimestamp) == "" {
			jwtHandler.ServeHTTP(w, r)
			return
		}
		if err := v.VerifyRequest(r, now()); err != nil {
			http.Error(w, `{"error": "invalid sentinel signature", "code": 401}`, http.StatusUnauthorized)
			return
		}
		ctx := auth.ContextWithClaims(r.Context(), &auth.Claims{
			Username: AnonDoorUsername,
			Roles:    []string{},
			Scopes:   []string{auth.ScopeAnonDoor},
		})
		inner.ServeHTTP(w, r.WithContext(ctx))
	})
}
