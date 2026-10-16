package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/grpc/metadata"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

var sshAuthzSecret = []byte(strings.Repeat("s", auth.SentinelMinSecretLen))

// jwtFallbackBody stands in for the "/v1/" JWT chain's refusal, so a test
// can tell the sentinel mount's 401 from a fall-through.
const jwtFallbackBody = `{"error":"jwt chain","code":401}`

// sshAuthzMux builds the routes the way Start does: a "/v1/" catch-all that
// is not the sentinel mount, then MountSSHAuthz over the production REST
// mux serving srv.
func sshAuthzMux(t *testing.T, v auth.SentinelVerifier, srv pb.SSHAuthzServiceServer) *http.ServeMux {
	t.Helper()
	gw := NewRESTMux()
	if err := pb.RegisterSSHAuthzServiceHandlerServer(context.Background(), gw, srv); err != nil {
		t.Fatalf("register handler: %v", err)
	}
	httpMux := http.NewServeMux()
	httpMux.Handle("/v1/", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, jwtFallbackBody, http.StatusUnauthorized)
	}))
	MountSSHAuthz(httpMux, v, nil, gw)
	return httpMux
}

func newSSHAuthzRequest() *http.Request {
	return httptest.NewRequest(http.MethodPost, SSHAuthzAuthorizePath, strings.NewReader(`{"login":"alice"}`))
}

func serve(h http.Handler, req *http.Request) (int, string) {
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	body, _ := io.ReadAll(rr.Result().Body)
	return rr.Code, string(body)
}

func TestSSHAuthzMount_SignedRequestReachesStub(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		v    auth.SentinelVerifier
		sign func(*http.Request)
	}{
		{"hmac", auth.NewSentinelVerifier(nil, sshAuthzSecret), func(r *http.Request) { auth.SignSentinelRequest(r, sshAuthzSecret) }},
		{"ed25519", auth.NewSentinelVerifier(pub, nil), func(r *http.Request) { auth.SignSentinelRequestEd25519(r, priv) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newSSHAuthzRequest()
			tt.sign(req)
			code, body := serve(sshAuthzMux(t, tt.v, unimplementedAuthz{}), req)
			if code != http.StatusNotImplemented {
				t.Fatalf("code = %d body = %s, want 501 from the Unimplemented stub", code, body)
			}
		})
	}
}

func TestSSHAuthzMount_UnverifiedRequestIs401AtTheMount(t *testing.T) {
	tests := []struct {
		name string
		v    auth.SentinelVerifier
		mut  func(*http.Request)
	}{
		{"unsigned", auth.NewSentinelVerifier(nil, sshAuthzSecret), func(*http.Request) {}},
		{"wrong secret", auth.NewSentinelVerifier(nil, sshAuthzSecret), func(r *http.Request) {
			auth.SignSentinelRequest(r, []byte(strings.Repeat("x", auth.SentinelMinSecretLen)))
		}},
		{"stale timestamp", auth.NewSentinelVerifier(nil, sshAuthzSecret), func(r *http.Request) {
			auth.SignSentinelRequest(r, sshAuthzSecret)
			r.Header.Set(auth.SentinelHeaderTimestamp, "1000000000")
		}},
		{"signed for another path", auth.NewSentinelVerifier(nil, sshAuthzSecret), func(r *http.Request) {
			r.URL.Path = AnonDoorEnsurePath
			auth.SignSentinelRequest(r, sshAuthzSecret)
			r.URL.Path = SSHAuthzAuthorizePath
		}},
		{"verifier unconfigured", auth.NewSentinelVerifier(nil, nil), func(r *http.Request) { auth.SignSentinelRequest(r, sshAuthzSecret) }},
		// A bearer token is not a way in: this route has no JWT fallback.
		{"bearer only", auth.NewSentinelVerifier(nil, sshAuthzSecret), func(r *http.Request) { r.Header.Set("Authorization", "Bearer x") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newSSHAuthzRequest()
			tt.mut(req)
			code, body := serve(sshAuthzMux(t, tt.v, unimplementedAuthz{}), req)
			if code != http.StatusUnauthorized {
				t.Fatalf("code = %d body = %s, want 401", code, body)
			}
			if !strings.Contains(body, "sentinel auth") {
				t.Fatalf("body = %q, want the sentinel verifier's refusal (not the /v1/ fallback)", body)
			}
		})
	}
}

// unimplementedAuthz is the generated stub: what the daemon's server returns
// once its own scope check passes (that check is tested in internal/server,
// which this package cannot import).
type unimplementedAuthz struct {
	pb.UnimplementedSSHAuthzServiceServer
}

// identityProbe records the identity metadata the gRPC handler sees.
type identityProbe struct {
	pb.UnimplementedSSHAuthzServiceServer
	md metadata.MD
}

func (p *identityProbe) Authorize(ctx context.Context, _ *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error) {
	p.md, _ = metadata.FromIncomingContext(ctx)
	return &pb.AuthorizeSSHResponse{}, nil
}

func TestSSHAuthzMount_VerifiedRequestCarriesSentinelIdentity(t *testing.T) {
	probe := &identityProbe{}
	req := newSSHAuthzRequest()
	auth.SignSentinelRequest(req, sshAuthzSecret)
	code, body := serve(sshAuthzMux(t, auth.NewSentinelVerifier(nil, sshAuthzSecret), probe), req)
	if code != http.StatusOK {
		t.Fatalf("code = %d body = %s, want 200", code, body)
	}
	if got := probe.md.Get(auth.MDKeyUsername); len(got) != 1 || got[0] != SSHAuthzUsername {
		t.Errorf("username = %v, want [%s]", got, SSHAuthzUsername)
	}
	if got := probe.md.Get(auth.MDKeyScopes); len(got) != 1 || got[0] != auth.ScopeSSHAuthorize {
		t.Errorf("scopes = %v, want [%s] only", got, auth.ScopeSSHAuthorize)
	}
	if got := probe.md.Get(auth.MDKeyRoles); len(got) != 0 {
		t.Errorf("roles = %v, want none: the sentinel is not an admin", got)
	}
}

// countingAuthz counts calls that reached the Authorize handler.
type countingAuthz struct {
	pb.UnimplementedSSHAuthzServiceServer
	calls int
}

func (c *countingAuthz) Authorize(context.Context, *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error) {
	c.calls++
	return &pb.AuthorizeSSHResponse{}, nil
}

// TestSSHAuthzMount_EncodedPathCannotBypassSentinel wires the routes as Start
// does — the REST mux behind GuardSSHAuthzPath, reached both from the "/v1/"
// JWT chain and from MountSSHAuthz — and sends spellings of the authorize
// path that http.ServeMux does not match to the exact-path mount but
// grpc-gateway still routes to Authorize. The "/v1/" stand-in is a caller
// holding a token with admin and ssh:authorize, the strongest JWT there is:
// without a sentinel signature none of them may reach the handler.
func TestSSHAuthzMount_EncodedPathCannotBypassSentinel(t *testing.T) {
	probe := &countingAuthz{}
	gw := NewRESTMux()
	if err := pb.RegisterSSHAuthzServiceHandlerServer(context.Background(), gw, probe); err != nil {
		t.Fatal(err)
	}
	rest := GuardSSHAuthzPath(gw)
	httpMux := http.NewServeMux()
	httpMux.Handle("/v1/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := auth.ContextWithClaims(r.Context(), &auth.Claims{
			Username: "token-holder",
			Roles:    []string{auth.RoleAdmin},
			Scopes:   []string{auth.ScopeSSHAuthorize},
		})
		rest.ServeHTTP(w, r.WithContext(ctx))
	}))
	MountSSHAuthz(httpMux, auth.NewSentinelVerifier(nil, sshAuthzSecret), nil, rest)

	for _, target := range []string{
		"/v1/ssh/authorize",
		"/v1/ssh%2Fauthorize",
		"/v1/ssh%2fauthorize",
		"/v1/%73sh/authorize",
		"/v1/ssh/%61uthorize",
		"/v1/ssh%2F%61uthorize",
		"/v1%2Fssh%2Fauthorize",
	} {
		t.Run(target, func(t *testing.T) {
			before := probe.calls
			req := httptest.NewRequest(http.MethodPost, "http://daemon"+target, strings.NewReader(`{"login":"alice"}`))
			code, body := serve(httpMux, req)
			if probe.calls != before {
				t.Fatalf("unsigned %s reached Authorize (code %d, body %s)", target, code, body)
			}
			if code != http.StatusUnauthorized && code != http.StatusNotFound && code != http.StatusTemporaryRedirect && code != http.StatusMovedPermanently {
				t.Fatalf("unsigned %s: code = %d body = %s, want a refusal", target, code, body)
			}
		})
	}

	// The sentinel's own canonical, signed request still gets through.
	req := newSSHAuthzRequest()
	auth.SignSentinelRequest(req, sshAuthzSecret)
	if code, body := serve(httpMux, req); code != http.StatusOK || probe.calls == 0 {
		t.Fatalf("signed canonical request: code = %d body = %s calls = %d, want 200 and a call", code, body, probe.calls)
	}
}
