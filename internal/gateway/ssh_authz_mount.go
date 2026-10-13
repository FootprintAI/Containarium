package gateway

import (
	"net/http"
	"time"

	"github.com/footprintai/containarium/internal/auth"
)

const SSHAuthzPath = "/v1/ssh/authorize"

// SSHAuthzHandler protects the generated gateway with the existing sentinel
// verifier. Unlike the anonymous door, this endpoint has no JWT fallback:
// missing, invalid or unconfigured sentinel signatures always return 401.
// The identity is forwarded only over the trusted in-process gRPC transport.
func SSHAuthzHandler(v auth.SentinelVerifier, inner http.Handler, now func() time.Time) http.Handler {
	if now == nil {
		now = time.Now
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := v.VerifyRequest(r, now()); err != nil {
			http.Error(w, `{"error":"invalid sentinel signature","code":401}`, http.StatusUnauthorized)
			return
		}
		ctx := auth.ContextWithClaims(r.Context(), &auth.Claims{
			Username: "sentinel-ssh-authz", Roles: []string{}, Scopes: []string{auth.ScopeSSHAuthorize},
		})
		inner.ServeHTTP(w, r.WithContext(auth.ContextWithVerifiedSentinelSSHAuthz(ctx)))
	})
}
