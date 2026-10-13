package gateway

import (
	"bytes"
	"errors"
	"io"
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
		if !v.Configured() || r.Header.Get(auth.SentinelHeaderTimestamp) == "" || r.Header.Get(auth.SentinelHeaderSignature) == "" {
			http.Error(w, `{"error":"invalid sentinel signature","code":401}`, http.StatusUnauthorized)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if err != nil {
			var tooLarge *http.MaxBytesError
			code := http.StatusBadRequest
			if errors.As(err, &tooLarge) {
				code = http.StatusRequestEntityTooLarge
			}
			http.Error(w, "invalid SSH authorization request body", code)
			return
		}
		_ = r.Body.Close()
		if err := v.VerifyBodyRequest(r, body, now()); err != nil {
			http.Error(w, `{"error":"invalid sentinel signature","code":401}`, http.StatusUnauthorized)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		ctx := auth.ContextWithClaims(r.Context(), &auth.Claims{
			Username: "sentinel-ssh-authz", Roles: []string{}, Scopes: []string{auth.ScopeSSHAuthorize},
		})
		inner.ServeHTTP(w, r.WithContext(auth.ContextWithVerifiedSentinelSSHAuthz(ctx)))
	})
}
