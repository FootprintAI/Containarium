package gateway

import (
	"net/http"
	"time"

	"github.com/footprintai/containarium/internal/auth"
)

// SSHAuthorizePath is the REST path grpc-gateway maps
// SSHAuthzService.Authorize to (ssh_authz.proto).
const SSHAuthorizePath = "/v1/ssh/authorize"

// SSHAuthzUsername is the subject a sentinel-signed Authorize call acts as.
// Not a tenant, no role — only the ssh:authz scope, which is the one thing
// the authorization query needs.
const SSHAuthzUsername = "sentinel-authz"

// sshAuthzHandler mounts /v1/ssh/authorize behind the sentinel's own
// request signature instead of a JWT (#2516, design doc "Deviations from
// the default stack": sentinel-to-daemon plumbing, read-only, and
// fail-closed enforcement must never depend on an operator registering a
// token). Same verifier as /authorized-keys, same identity shape as the
// anonymous door (anonDoorHandler).
//
// Unlike the door there is NO JWT fall-through: a request without a valid
// signature is 401 whatever else it carries, and a signed-but-invalid one
// never reaches the gateway. A verified request is forwarded to inner with
// username SSHAuthzUsername, no roles and scope ssh:authz in its context;
// annotateContext turns that into the gRPC metadata the handler's
// RequireRoleOrScope reads.
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
			Scopes:   []string{auth.ScopeSSHAuthz},
		})
		inner.ServeHTTP(w, r.WithContext(ctx))
	})
}
