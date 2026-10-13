package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

var sshAuthzSecret = []byte(strings.Repeat("k", auth.SentinelMinSecretLen))

// sshAuthzGatewayMux is the real generated SSHAuthzService gateway shim over
// the daemon's Unimplemented stub shape, with the production error handler,
// so the status a signed request ends on is the one the sentinel will see.
func sshAuthzGatewayMux(t *testing.T) *runtime.ServeMux {
	t.Helper()
	srv := grpc.NewServer(
		grpc.Creds(auth.NewServerTransportCredentials(nil)),
		grpc.ChainUnaryInterceptor(auth.TransportIdentityUnaryInterceptor()),
	)
	pb.RegisterSSHAuthzServiceServer(srv, pb.UnimplementedSSHAuthzServiceServer{})
	lis := auth.NewInternalListener()
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	mux := runtime.NewServeMux(
		runtime.WithErrorHandler(customErrorHandler),
		runtime.WithMetadata(annotateContext),
		runtime.WithIncomingHeaderMatcher(incomingHeaderMatcher),
	)
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(lis.DialContext),
	}
	if err := pb.RegisterSSHAuthzServiceHandlerFromEndpoint(context.Background(), mux, "passthrough:///containarium-internal", opts); err != nil {
		t.Fatal(err)
	}
	return mux
}

const sshAuthzBody = `{"login":"alice","credential":{"publicKey":{"fingerprintSha256":"SHA256:fp","keyType":"SSH_KEY_TYPE_ED25519"}}}`

// Done-when 3 (#2516): a signed request reaches the stub, which answers
// Unimplemented; the gateway maps that to 501. A 404 would mean the proto
// mapping and the mount path drifted; a 401 would mean the verifier
// rejected a good signature.
func TestSSHAuthzHandler_ValidSignatureReachesStub501(t *testing.T) {
	h := sshAuthzHandler(auth.NewSentinelVerifier(nil, sshAuthzSecret), sshAuthzGatewayMux(t), nil)

	req := httptest.NewRequest(http.MethodPost, SSHAuthorizePath, strings.NewReader(sshAuthzBody))
	req.Header.Set("Content-Type", "application/json")
	auth.SignSentinelRequest(req, sshAuthzSecret)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotImplemented {
		t.Fatalf("signed POST %s → %d (%s), want 501 from the Unimplemented stub", SSHAuthorizePath, rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"code":501`) {
		t.Errorf("body = %s, want the gateway's JSON error with code 501", rr.Body.String())
	}
}

// The mount stamps the verified sentinel as a door-style identity — no
// roles, exactly the ssh:authz scope — so the handler's RequireRoleOrScope
// sees the same shape a JWT would give it.
func TestSSHAuthzHandler_ValidSignatureGetsAuthzIdentity(t *testing.T) {
	var username string
	var roles, scopes []string
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		username, _ = auth.UsernameFromContext(r.Context())
		roles, _ = auth.RolesFromContext(r.Context())
		scopes, _ = auth.ScopesFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	h := sshAuthzHandler(auth.NewSentinelVerifier(nil, sshAuthzSecret), inner, nil)

	req := httptest.NewRequest(http.MethodPost, SSHAuthorizePath, strings.NewReader(sshAuthzBody))
	auth.SignSentinelRequest(req, sshAuthzSecret)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK || !called {
		t.Fatalf("code=%d called=%v, want the inner handler with 200", rr.Code, called)
	}
	if username != SSHAuthzUsername {
		t.Errorf("username = %q, want %q", username, SSHAuthzUsername)
	}
	if len(scopes) != 1 || scopes[0] != auth.ScopeSSHAuthz {
		t.Errorf("scopes = %v, want [%s] only", scopes, auth.ScopeSSHAuthz)
	}
	if len(roles) != 0 {
		t.Errorf("roles = %v, want none: the sentinel is not an admin", roles)
	}
}

// Done-when 3 (#2516): without a valid sentinel signature the request is
// 401 and never reaches the gateway — there is no JWT fall-through on this
// route, by design (the architecture doc's "sentinel signature instead of a
// JWT" deviation).
func TestSSHAuthzHandler_WithoutValidSignatureIs401(t *testing.T) {
	tests := []struct {
		name string
		mut  func(*http.Request)
		v    auth.SentinelVerifier
	}{
		{"unsigned", func(*http.Request) {}, auth.NewSentinelVerifier(nil, sshAuthzSecret)},
		{"bearer token only", func(r *http.Request) { r.Header.Set("Authorization", "Bearer not-a-sentinel") }, auth.NewSentinelVerifier(nil, sshAuthzSecret)},
		{"wrong secret", func(r *http.Request) {
			auth.SignSentinelRequest(r, []byte(strings.Repeat("x", auth.SentinelMinSecretLen)))
		}, auth.NewSentinelVerifier(nil, sshAuthzSecret)},
		{"tampered path", func(r *http.Request) {
			auth.SignSentinelRequest(r, sshAuthzSecret)
			r.URL.Path = "/v1/ssh/authorize-other"
		}, auth.NewSentinelVerifier(nil, sshAuthzSecret)},
		{"stale timestamp", func(r *http.Request) {
			auth.SignSentinelRequest(r, sshAuthzSecret)
			r.Header.Set(auth.SentinelHeaderTimestamp, "1000000000")
		}, auth.NewSentinelVerifier(nil, sshAuthzSecret)},
		{"signature header only", func(r *http.Request) { r.Header.Set(auth.SentinelHeaderSignature, "abc") }, auth.NewSentinelVerifier(nil, sshAuthzSecret)},
		{"verifier unconfigured (fail closed)", func(r *http.Request) { auth.SignSentinelRequest(r, sshAuthzSecret) }, auth.NewSentinelVerifier(nil, nil)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reached := false
			inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { reached = true; w.WriteHeader(http.StatusOK) })
			h := sshAuthzHandler(tt.v, inner, func() time.Time { return time.Now() })

			req := httptest.NewRequest(http.MethodPost, SSHAuthorizePath, strings.NewReader(sshAuthzBody))
			tt.mut(req)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if rr.Code != http.StatusUnauthorized || reached {
				t.Fatalf("code=%d reached=%v, want 401 and the gateway never reached", rr.Code, reached)
			}
		})
	}
}

// The mount path is exactly the proto's REST mapping; a drift here would
// leave the generated route reachable through the JWT catch-all instead.
func TestSSHAuthorizePath_MatchesGeneratedRoute(t *testing.T) {
	mux := sshAuthzGatewayMux(t)
	req := httptest.NewRequest(http.MethodPost, SSHAuthorizePath, strings.NewReader(sshAuthzBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code == http.StatusNotFound {
		t.Fatalf("POST %s → 404: no grpc-gateway pattern matched (%s)", SSHAuthorizePath, rr.Body.String())
	}
}
