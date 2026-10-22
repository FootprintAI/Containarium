package gateway

import (
	"context"
	"net/http"
	"strings"

	"github.com/footprintai/containarium/internal/auth"
)

// SSHAuthzAuthorizePath is the REST path grpc-gateway maps
// SSHAuthzService.Authorize to (ssh_authz.proto).
const SSHAuthzAuthorizePath = "/v1/ssh/authorize"

// SSHAuthzUsername is the subject a sentinel-signed Authorize call acts as.
// It is not a tenant and holds no role — only the ssh:authorize scope.
const SSHAuthzUsername = "sentinel-ssh-authz"

// SSHAuthzTokenFallbackRequiredScope is the only scope that lets a JWT
// reach Authorize through MountSSHAuthz's token fallback. It is matched
// literally: the wildcard does not count, so enabling the fallback admits
// tokens minted for this one query and not every admin token.
const SSHAuthzTokenFallbackRequiredScope = auth.ScopeSSHAuthorize

// MountSSHAuthz registers the route for SSHAuthzService.Authorize (#2516)
// on httpMux, as an exact path so it wins over the "/v1/" catch-all.
//
// The sentinel is the primary caller: a request carrying the sentinel
// signature headers is verified by v (fail-closed when no sentinel key is
// configured) and forwarded to inner with a sentinel identity in its
// context — username SSHAuthzUsername, no roles, scope ssh:authorize —
// which annotateContext turns into the gRPC metadata the handler reads. A
// request that is signed but does not verify is 401; it never falls
// through to the token path.
//
// tokenAuth is the token fallback (#2527), for the jump host's
// AuthorizedKeysCommand, which holds a JWT carrying ssh:authorize and
// never the sentinel secret. Nil (the default) keeps the route
// sentinel-only, so an unsigned request is 401 from v.Middleware. When
// set, an unsigned request is authenticated by tokenAuth (the gateway's
// JWT middleware) and must also carry SSHAuthzTokenFallbackRequiredScope
// explicitly; it then reaches inner with the token's own identity.
//
// The exact-path registration alone does not keep other callers out:
// http.ServeMux matches the escaped path, so a spelling such as
// /v1/ssh%2Fauthorize misses this pattern and falls through to "/v1/",
// while grpc-gateway still routes it to Authorize. GuardSSHAuthzPath closes
// that: inner must be the guarded REST handler, and only a request that
// came through this mount carries the marker the guard requires.
func MountSSHAuthz(httpMux *http.ServeMux, v auth.SentinelVerifier, tokenAuth func(http.Handler) http.Handler, inner http.Handler) {
	sentinel := v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := auth.ContextWithClaims(r.Context(), &auth.Claims{
			Username: SSHAuthzUsername,
			Roles:    []string{},
			Scopes:   []string{auth.ScopeSSHAuthorize},
		})
		ctx = context.WithValue(ctx, sshAuthzVerifiedKey{}, true)
		inner.ServeHTTP(w, r.WithContext(ctx))
	}))
	if tokenAuth == nil {
		httpMux.Handle(SSHAuthzAuthorizePath, sentinel)
		return
	}
	token := tokenAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scopes, _ := auth.ScopesFromContext(r.Context())
		if !hasLiteralScope(scopes, SSHAuthzTokenFallbackRequiredScope) {
			http.Error(w, `{"error":"scope required: `+SSHAuthzTokenFallbackRequiredScope+`","code":403}`, http.StatusForbidden)
			return
		}
		inner.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sshAuthzVerifiedKey{}, true)))
	}))
	httpMux.Handle(SSHAuthzAuthorizePath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(auth.SentinelHeaderSignature) == "" && r.Header.Get(auth.SentinelHeaderTimestamp) == "" {
			token.ServeHTTP(w, r)
			return
		}
		sentinel.ServeHTTP(w, r)
	}))
}

// hasLiteralScope reports whether want is in granted, ignoring the wildcard.
func hasLiteralScope(granted []string, want string) bool {
	for _, s := range granted {
		if strings.TrimSpace(s) == want {
			return true
		}
	}
	return false
}

// sshAuthzVerifiedKey marks a request whose sentinel signature
// MountSSHAuthz verified. Unexported, so nothing outside this package —
// and no client header — can set it.
type sshAuthzVerifiedKey struct{}

// GuardSSHAuthzPath wraps the REST mux so the authorize route is reachable
// only through MountSSHAuthz (sentinel signature or, when enabled, the token
// fallback), whatever the request's spelling. It compares
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
