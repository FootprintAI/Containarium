package gateway

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Token fallback on /v1/ssh/authorize (#2527): the jump host's
// AuthorizedKeysCommand holds a JWT carrying ssh:authorize, never the
// sentinel secret.

const sshAuthzJWTSecret = "ssh-authz-token-fallback-test-secret-0123456789"

func sshAuthzTokenManager(t *testing.T) *auth.TokenManager {
	t.Helper()
	tm, err := auth.NewTokenManager(sshAuthzJWTSecret, "containarium")
	if err != nil {
		t.Fatal(err)
	}
	return tm
}

// sshAuthzTokenMux builds the routes as Start does with the fallback on
// (tokenAuth set) or off (nil), the REST mux behind GuardSSHAuthzPath.
func sshAuthzTokenMux(t *testing.T, tokenAuth func(http.Handler) http.Handler, srv pb.SSHAuthzServiceServer) *http.ServeMux {
	t.Helper()
	gw := NewRESTMux()
	if err := pb.RegisterSSHAuthzServiceHandlerServer(context.Background(), gw, srv); err != nil {
		t.Fatal(err)
	}
	httpMux := http.NewServeMux()
	httpMux.Handle("/v1/", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, jwtFallbackBody, http.StatusUnauthorized)
	}))
	MountSSHAuthz(httpMux, auth.NewSentinelVerifier(nil, sshAuthzSecret), tokenAuth, GuardSSHAuthzPath(gw))
	return httpMux
}

func bearer(t *testing.T, tm *auth.TokenManager, roles []string, scopes ...string) string {
	t.Helper()
	tok, err := tm.GenerateAccessToken("ssh-authz-keys", roles, time.Hour, scopes...)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestSSHAuthzTokenFallback_ScopedTokenReachesHandlerWithItsIdentity(t *testing.T) {
	tm := sshAuthzTokenManager(t)
	probe := &identityProbe{}
	mux := sshAuthzTokenMux(t, auth.NewAuthMiddleware(tm).HTTPMiddleware, probe)

	req := newSSHAuthzRequest()
	req.Header.Set("Authorization", "Bearer "+bearer(t, tm, nil, auth.ScopeSSHAuthorize))
	code, body := serve(mux, req)
	if code != http.StatusOK {
		t.Fatalf("code = %d body = %s, want 200", code, body)
	}
	if got := probe.md.Get(auth.MDKeyUsername); len(got) != 1 || got[0] != "ssh-authz-keys" {
		t.Errorf("username = %v, want the token's subject, not the sentinel's", got)
	}
	if got := probe.md.Get(auth.MDKeyScopes); len(got) != 1 || got[0] != auth.ScopeSSHAuthorize {
		t.Errorf("scopes = %v, want [%s]", got, auth.ScopeSSHAuthorize)
	}
}

func TestSSHAuthzTokenFallback_RefusesTokensWithoutTheLiteralScope(t *testing.T) {
	tm := sshAuthzTokenManager(t)
	tests := []struct {
		name  string
		token string
		want  int
	}{
		// The wildcard does not count: enabling the fallback must not open
		// the route to every admin token.
		{"wildcard scope", bearer(t, tm, []string{auth.RoleAdmin}, auth.ScopeWildcard), http.StatusForbidden},
		{"admin, no scopes claim", bearer(t, tm, []string{auth.RoleAdmin}), http.StatusForbidden},
		{"other scope", bearer(t, tm, nil, auth.ScopeSSHWrite), http.StatusForbidden},
		{"invalid token", "not-a-jwt", http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			probe := &countingAuthz{}
			mux := sshAuthzTokenMux(t, auth.NewAuthMiddleware(tm).HTTPMiddleware, probe)
			req := newSSHAuthzRequest()
			req.Header.Set("Authorization", "Bearer "+tt.token)
			code, body := serve(mux, req)
			if code != tt.want || probe.calls != 0 {
				t.Fatalf("code = %d body = %s calls = %d, want %d and no call", code, body, probe.calls, tt.want)
			}
		})
	}
}

// A request carrying sentinel headers is judged by the sentinel verifier
// alone: a bad signature is 401 even next to a valid scoped token.
func TestSSHAuthzTokenFallback_BadSignatureDoesNotFallThroughToToken(t *testing.T) {
	tm := sshAuthzTokenManager(t)
	probe := &countingAuthz{}
	mux := sshAuthzTokenMux(t, auth.NewAuthMiddleware(tm).HTTPMiddleware, probe)

	req := newSSHAuthzRequest()
	auth.SignSentinelRequest(req, []byte(strings.Repeat("x", auth.SentinelMinSecretLen)))
	req.Header.Set("Authorization", "Bearer "+bearer(t, tm, nil, auth.ScopeSSHAuthorize))
	code, body := serve(mux, req)
	if code != http.StatusUnauthorized || probe.calls != 0 || !strings.Contains(body, "sentinel auth") {
		t.Fatalf("code = %d body = %s calls = %d, want the sentinel verifier's 401", code, body, probe.calls)
	}
}

func TestSSHAuthzTokenFallback_SentinelStillWorksWhenEnabled(t *testing.T) {
	tm := sshAuthzTokenManager(t)
	probe := &identityProbe{}
	mux := sshAuthzTokenMux(t, auth.NewAuthMiddleware(tm).HTTPMiddleware, probe)

	req := newSSHAuthzRequest()
	auth.SignSentinelRequest(req, sshAuthzSecret)
	if code, body := serve(mux, req); code != http.StatusOK {
		t.Fatalf("code = %d body = %s, want 200", code, body)
	}
	if got := probe.md.Get(auth.MDKeyUsername); len(got) != 1 || got[0] != SSHAuthzUsername {
		t.Errorf("username = %v, want [%s]", got, SSHAuthzUsername)
	}
}

// Off by default: even a correctly scoped token is refused at the mount.
func TestSSHAuthzTokenFallback_DisabledRefusesScopedToken(t *testing.T) {
	tm := sshAuthzTokenManager(t)
	probe := &countingAuthz{}
	mux := sshAuthzTokenMux(t, nil, probe)

	req := newSSHAuthzRequest()
	req.Header.Set("Authorization", "Bearer "+bearer(t, tm, nil, auth.ScopeSSHAuthorize))
	code, body := serve(mux, req)
	if code != http.StatusUnauthorized || probe.calls != 0 || !strings.Contains(body, "sentinel auth") {
		t.Fatalf("code = %d body = %s calls = %d, want the sentinel verifier's 401", code, body, probe.calls)
	}
}
