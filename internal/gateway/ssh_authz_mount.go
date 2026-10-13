package gateway

import (
	"net/http"

	"github.com/footprintai/containarium/internal/auth"
)

// SSHAuthzAuthorizePath is the REST path grpc-gateway maps
// SSHAuthzService.Authorize to (ssh_authz.proto).
const SSHAuthzAuthorizePath = "/v1/ssh/authorize"

// SSHAuthzUsername is the subject a sentinel-signed Authorize call acts as.
// It is not a tenant and holds no role — only the ssh:authorize scope.
const SSHAuthzUsername = "sentinel-ssh-authz"

// MountSSHAuthz registers the sentinel-only route for
// SSHAuthzService.Authorize (#2516) on httpMux, as an exact path so it
// wins over the "/v1/" catch-all.
//
// Unlike the anonymous door there is no JWT fallback: the route is
// sentinel-to-daemon plumbing, so a request that does not carry a valid
// sentinel signature is 401 from v.Middleware (fail-closed when no
// sentinel key is configured). A verified request is forwarded to inner
// with a sentinel identity in its context — username SSHAuthzUsername, no
// roles, scope ssh:authorize — which annotateContext turns into the gRPC
// metadata the handler reads.
func MountSSHAuthz(httpMux *http.ServeMux, v auth.SentinelVerifier, inner http.Handler) {
	httpMux.Handle(SSHAuthzAuthorizePath, v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := auth.ContextWithClaims(r.Context(), &auth.Claims{
			Username: SSHAuthzUsername,
			Roles:    []string{},
			Scopes:   []string{auth.ScopeSSHAuthorize},
		})
		inner.ServeHTTP(w, r.WithContext(ctx))
	})))
}
