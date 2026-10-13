package gateway

import (
	"context"
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
//
// The exact-path registration alone does not keep other callers out:
// http.ServeMux matches the escaped path, so a spelling such as
// /v1/ssh%2Fauthorize misses this pattern and falls through to "/v1/",
// while grpc-gateway still routes it to Authorize. GuardSSHAuthzPath closes
// that: inner must be the guarded REST handler, and only a request that
// came through this mount carries the marker the guard requires.
func MountSSHAuthz(httpMux *http.ServeMux, v auth.SentinelVerifier, inner http.Handler) {
	httpMux.Handle(SSHAuthzAuthorizePath, v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := auth.ContextWithClaims(r.Context(), &auth.Claims{
			Username: SSHAuthzUsername,
			Roles:    []string{},
			Scopes:   []string{auth.ScopeSSHAuthorize},
		})
		ctx = context.WithValue(ctx, sshAuthzVerifiedKey{}, true)
		inner.ServeHTTP(w, r.WithContext(ctx))
	})))
}

// sshAuthzVerifiedKey marks a request whose sentinel signature
// MountSSHAuthz verified. Unexported, so nothing outside this package —
// and no client header — can set it.
type sshAuthzVerifiedKey struct{}

// GuardSSHAuthzPath wraps the REST mux so the authorize route is reachable
// only through MountSSHAuthz, whatever the request's spelling. It compares
// the fully decoded path, which is what grpc-gateway routes on; any request
// grpc-gateway would send to Authorize decodes to SSHAuthzAuthorizePath.
// Every other path passes through untouched.
func GuardSSHAuthzPath(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == SSHAuthzAuthorizePath {
			if ok, _ := r.Context().Value(sshAuthzVerifiedKey{}).(bool); !ok {
				http.Error(w, `{"error":"sentinel auth required","code":401}`, http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
