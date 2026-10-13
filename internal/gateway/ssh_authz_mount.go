package gateway

import (
	"net/http"
	"time"

	"github.com/footprintai/containarium/internal/auth"
)

// SSHAuthzPath is the REST path generated for SSHAuthzService.Authorize.
const SSHAuthzPath = "/v1/ssh/authorize"

// SSHAuthzUsername identifies sentinel-originated authorization checks in
// request context and audit records. It grants no user role or scope.
const SSHAuthzUsername = "sentinel-ssh-authz"

// sshAuthzHandler verifies the sentinel signature before a request can reach
// the generated grpc-gateway handler. Missing, incomplete and invalid
// signatures all fail closed with 401; this endpoint never falls back to JWT.
func sshAuthzHandler(v auth.SentinelVerifier, inner http.Handler, now func() time.Time) http.Handler {
	if now == nil {
		now = time.Now
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := v.VerifyRequest(r, now()); err != nil {
			http.Error(w, `{"error": "invalid sentinel signature", "code": 401}`, http.StatusUnauthorized)
			return
		}
		ctx := auth.ContextWithClaims(r.Context(), &auth.Claims{
			Username: SSHAuthzUsername,
			Roles:    []string{},
			Scopes:   []string{},
		})
		inner.ServeHTTP(w, r.WithContext(ctx))
	})
}
