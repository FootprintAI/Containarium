package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/gateway"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestSSHAuthzServer_AuthorizeRequiresExplicitScope(t *testing.T) {
	tests := []struct {
		name string
		md   metadata.MD
		want codes.Code
	}{
		{"no subject", metadata.MD{}, codes.Unauthenticated},
		{"admin without the scope", metadata.Pairs(auth.MDKeyUsername, "root", auth.MDKeyRoles, auth.RoleAdmin), codes.PermissionDenied},
		{"unscoped token", metadata.Pairs(auth.MDKeyUsername, "alice"), codes.PermissionDenied},
		{"other scope", metadata.Pairs(auth.MDKeyUsername, gateway.AnonDoorUsername, auth.MDKeyScopes, auth.ScopeAnonDoor), codes.PermissionDenied},
		{"mTLS peer", metadata.Pairs(auth.MDKeyUsername, "mtls:peer"), codes.PermissionDenied},
		{"sentinel scope", metadata.Pairs(auth.MDKeyUsername, gateway.SSHAuthzUsername, auth.MDKeyScopes, auth.ScopeSSHAuthorize), codes.Unimplemented},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := metadata.NewIncomingContext(context.Background(), tt.md)
			_, err := NewSSHAuthzServer().Authorize(ctx, &pb.AuthorizeSSHRequest{Login: "alice"})
			if got := status.Code(err); got != tt.want {
				t.Fatalf("code = %v (%v), want %v", got, err, tt.want)
			}
		})
	}
}

// TestSSHAuthzServer_SentinelSignedRequestReachesStub runs the daemon's chain
// end to end: sentinel-signed POST → gateway.MountSSHAuthz → the production
// REST mux → this package's server, whose scope check must pass on the
// identity the mount stamps and then answer Unimplemented (501).
func TestSSHAuthzServer_SentinelSignedRequestReachesStub(t *testing.T) {
	secret := []byte(strings.Repeat("s", auth.SentinelMinSecretLen))
	gw := gateway.NewRESTMux()
	if err := pb.RegisterSSHAuthzServiceHandlerServer(context.Background(), gw, NewSSHAuthzServer()); err != nil {
		t.Fatal(err)
	}
	httpMux := http.NewServeMux()
	gateway.MountSSHAuthz(httpMux, auth.NewSentinelVerifier(nil, secret), nil, gateway.GuardSSHAuthzPath(gw))

	signed := httptest.NewRequest(http.MethodPost, gateway.SSHAuthzAuthorizePath, strings.NewReader(`{"login":"alice"}`))
	auth.SignSentinelRequest(signed, secret)
	rr := httptest.NewRecorder()
	httpMux.ServeHTTP(rr, signed)
	body, _ := io.ReadAll(rr.Result().Body)
	if rr.Code != http.StatusNotImplemented {
		t.Fatalf("signed: code = %d body = %s, want 501 (scope check passed, stub reached)", rr.Code, body)
	}

	unsigned := httptest.NewRequest(http.MethodPost, gateway.SSHAuthzAuthorizePath, strings.NewReader(`{"login":"alice"}`))
	rr = httptest.NewRecorder()
	httpMux.ServeHTTP(rr, unsigned)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned: code = %d, want 401", rr.Code)
	}
}

type stubDecider struct {
	got  *pb.AuthorizeSSHRequest
	resp *pb.AuthorizeSSHResponse
}

func (d *stubDecider) Decide(_ context.Context, req *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error) {
	d.got = req
	return d.resp, nil
}

// With a decider wired (the self-host decider, #2517), a scoped call is
// answered by it; a call without the scope never reaches it.
func TestSSHAuthzServer_DispatchesToDecider(t *testing.T) {
	want := &pb.AuthorizeSSHResponse{Decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW, UserId: "alice"}
	d := &stubDecider{resp: want}
	s := NewSSHAuthzServer()
	s.SetDecider(d)

	unscoped := metadata.NewIncomingContext(context.Background(), metadata.Pairs(auth.MDKeyUsername, "alice"))
	if _, err := s.Authorize(unscoped, &pb.AuthorizeSSHRequest{Login: "alice"}); status.Code(err) != codes.PermissionDenied || d.got != nil {
		t.Fatalf("unscoped call: err = %v, decider reached = %v", err, d.got != nil)
	}

	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs(auth.MDKeyUsername, gateway.SSHAuthzUsername, auth.MDKeyScopes, auth.ScopeSSHAuthorize))
	resp, err := s.Authorize(ctx, &pb.AuthorizeSSHRequest{Login: "alice"})
	if err != nil || resp != want || d.got.GetLogin() != "alice" {
		t.Fatalf("got (%v, %v), want the decider's response", resp, err)
	}
}

// TestSSHAuthzServer_TokenFallbackReachesDecider runs the jump host's path
// end to end (#2527): an ssh:authorize JWT → gateway.MountSSHAuthz with the
// token fallback on → the production REST mux → this server, whose scope
// check must pass on the token's own identity and dispatch to the decider.
func TestSSHAuthzServer_TokenFallbackReachesDecider(t *testing.T) {
	tm, err := auth.NewTokenManager("ssh-authz-keys-e2e-test-secret-0123456789abcdef", "containarium")
	if err != nil {
		t.Fatal(err)
	}
	d := &stubDecider{resp: &pb.AuthorizeSSHResponse{Decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW, UserId: "alice"}}
	s := NewSSHAuthzServer()
	s.SetDecider(d)
	gw := gateway.NewRESTMux()
	if err := pb.RegisterSSHAuthzServiceHandlerServer(context.Background(), gw, s); err != nil {
		t.Fatal(err)
	}
	httpMux := http.NewServeMux()
	gateway.MountSSHAuthz(httpMux, auth.NewSentinelVerifier(nil, nil), auth.NewAuthMiddleware(tm).HTTPMiddleware, gateway.GuardSSHAuthzPath(gw))

	token, err := tm.GenerateAccessToken("ssh-authz-keys", nil, time.Hour, auth.ScopeSSHAuthorize)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, gateway.SSHAuthzAuthorizePath, strings.NewReader(`{"login":"alice"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	httpMux.ServeHTTP(rr, req)
	body, _ := io.ReadAll(rr.Result().Body)
	if rr.Code != http.StatusOK || d.got.GetLogin() != "alice" || !strings.Contains(string(body), "ALLOW") {
		t.Fatalf("code = %d body = %s decider reached = %v, want 200 with the decider's ALLOW", rr.Code, body, d.got != nil)
	}
}
