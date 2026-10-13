package sshauthz_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/gateway"
	server "github.com/footprintai/containarium/internal/server/sshauthz"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type echoServer struct {
	pb.UnimplementedSSHAuthzServiceServer
	mu       sync.Mutex
	response *pb.AuthorizeSSHResponse
	seen     *pb.AuthorizeSSHRequest
}

func (s *echoServer) Authorize(_ context.Context, r *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen = proto.Clone(r).(*pb.AuthorizeSSHRequest)
	return proto.Clone(s.response).(*pb.AuthorizeSSHResponse), nil
}

// This stack uses the generated Go client inside the generated gateway and
// the production transport interceptor and signature mount, with a narrow
// metadata annotator matching the gateway's trusted identity bridge.
func stack(t *testing.T, impl pb.SSHAuthzServiceServer, verifier auth.SentinelVerifier) *httptest.Server {
	t.Helper()
	listener := auth.NewInternalListener()
	gs := grpc.NewServer(grpc.Creds(auth.NewServerTransportCredentials(nil)), grpc.UnaryInterceptor(auth.TransportIdentityUnaryInterceptor()))
	pb.RegisterSSHAuthzServiceServer(gs, impl)
	go func() { _ = gs.Serve(listener) }()
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient("passthrough:///authz-test", grpc.WithContextDialer(listener.DialContext), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	mux := runtime.NewServeMux(runtime.WithMetadata(func(ctx context.Context, _ *http.Request) metadata.MD {
		username, _ := auth.UsernameFromContext(ctx)
		scopes, _ := auth.ScopesFromContext(ctx)
		md := metadata.Pairs(auth.MDKeyUsername, username, auth.MDKeyScopes, strings.Join(scopes, ","))
		if auth.VerifiedSentinelSSHAuthz(ctx) {
			md.Set(auth.SentinelSSHAuthzVerifiedMDKey, "1")
		}
		return md
	}))
	if err := pb.RegisterSSHAuthzServiceHandlerClient(context.Background(), mux, pb.NewSSHAuthzServiceClient(conn)); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(gateway.SSHAuthzHandler(verifier, mux, nil))
	t.Cleanup(ts.Close)
	return ts
}

func TestContractRoundTripEveryDenyReason(t *testing.T) {
	secret := []byte(strings.Repeat("s", auth.SentinelMinSecretLen))
	srv := &echoServer{}
	ts := stack(t, srv, auth.NewSentinelVerifier(nil, secret))
	req := &pb.AuthorizeSSHRequest{Login: "alice", ClientIp: "192.0.2.1", SentinelId: "test", ApprovalId: "approval", Credential: &pb.SSHCredential{Kind: &pb.SSHCredential_PublicKey{PublicKey: &pb.SSHPublicKeyCredential{FingerprintSha256: "SHA256:key", KeyType: pb.SSHKeyType_SSH_KEY_TYPE_ED25519}}}}
	body, err := protojson.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	for reason := range pb.SSHDenyReason_name {
		t.Run(pb.SSHDenyReason(reason).String(), func(t *testing.T) {
			want := &pb.AuthorizeSSHResponse{Decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY, DenyReason: pb.SSHDenyReason(reason), UserId: "user-a", CacheTtl: durationpb.New(30 * time.Second), Approval: &pb.SSHDeviceApproval{ApprovalId: "approval", Code: "1234", Url: "https://example.com/approve", PollAfter: durationpb.New(time.Second), ExpiresAt: timestamppb.New(time.Unix(1000, 0))}}
			srv.mu.Lock()
			srv.response = want
			srv.mu.Unlock()
			r, err := http.NewRequest(http.MethodPost, ts.URL+gateway.SSHAuthzPath, bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			r.Header.Set("Content-Type", "application/json")
			auth.SignSentinelBodyRequest(r, secret, body)
			resp, err := ts.Client().Do(r)
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status %d: %s", resp.StatusCode, data)
			}
			got := new(pb.AuthorizeSSHResponse)
			if err := protojson.Unmarshal(data, got); err != nil {
				t.Fatal(err)
			}
			if !proto.Equal(want, got) {
				t.Fatalf("round trip: got %v want %v", got, want)
			}
			srv.mu.Lock()
			seen := srv.seen
			srv.mu.Unlock()
			if !proto.Equal(req, seen) {
				t.Fatalf("request drift: %v", seen)
			}
		})
	}
}

func TestSignatureSecurityReachesStub(t *testing.T) {
	secret := []byte(strings.Repeat("s", auth.SentinelMinSecretLen))
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		sign     func(*http.Request)
		verifier auth.SentinelVerifier
		want     int
	}{
		{"missing", nil, auth.NewSentinelVerifier(nil, secret), 401},
		{"JWT is not sentinel", func(r *http.Request) { r.Header.Set("Authorization", "Bearer jwt") }, auth.NewSentinelVerifier(nil, secret), 401},
		{"bad HMAC", func(r *http.Request) {
			auth.SignSentinelBodyRequest(r, []byte(strings.Repeat("x", 32)), []byte(`{"login":"alice"}`))
		}, auth.NewSentinelVerifier(nil, secret), 401},
		{"stale", func(r *http.Request) {
			auth.SignSentinelBodyRequest(r, secret, []byte(`{"login":"alice"}`))
			r.Header.Set(auth.SentinelHeaderTimestamp, "1")
		}, auth.NewSentinelVerifier(nil, secret), 401},
		{"unconfigured", func(r *http.Request) { auth.SignSentinelBodyRequest(r, secret, []byte(`{"login":"alice"}`)) }, auth.NewSentinelVerifier(nil, nil), 401},
		{"HMAC reaches Unimplemented", func(r *http.Request) { auth.SignSentinelBodyRequest(r, secret, []byte(`{"login":"alice"}`)) }, auth.NewSentinelVerifier(nil, secret), 501},
		{"ed25519 reaches Unimplemented", func(r *http.Request) { auth.SignSentinelBodyRequestEd25519(r, priv, []byte(`{"login":"alice"}`)) }, auth.NewSentinelVerifier(pub, nil), 501},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := stack(t, &server.SSHAuthzServer{}, tc.verifier)
			r, err := http.NewRequest(http.MethodPost, ts.URL+gateway.SSHAuthzPath, strings.NewReader(`{"login":"alice"}`))
			if err != nil {
				t.Fatal(err)
			}
			if tc.sign != nil {
				tc.sign(r)
			}
			resp, err := ts.Client().Do(r)
			if err != nil {
				t.Fatal(err)
			}
			data, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Fatalf("status=%d want=%d body=%s", resp.StatusCode, tc.want, data)
			}
		})
	}
}

func TestStubScopeGuard(t *testing.T) {
	for _, tc := range []struct {
		name string
		ctx  context.Context
		want codes.Code
	}{
		{"anonymous", context.Background(), codes.Unauthenticated},
		{"unscoped admin", auth.ContextWithTestSubjectScopes(context.Background(), "admin", []string{"admin"}, nil), codes.PermissionDenied},
		{"scope without verified signature", auth.ContextWithTestSubjectScopes(context.Background(), "sentinel", nil, []string{auth.ScopeSSHAuthorize}), codes.PermissionDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := (&server.SSHAuthzServer{}).Authorize(tc.ctx, &pb.AuthorizeSSHRequest{})
			if status.Code(err) != tc.want {
				t.Fatalf("%v", err)
			}
		})
	}
}

// Prevent an external mTLS/plaintext peer from injecting the internal scope.
func TestExternalPlaintextCannotForgeScope(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer(grpc.Creds(auth.NewServerTransportCredentials(nil)), grpc.UnaryInterceptor(auth.TransportIdentityUnaryInterceptor()))
	pb.RegisterSSHAuthzServiceServer(gs, &server.SSHAuthzServer{})
	go func() { _ = gs.Serve(listener) }()
	defer gs.Stop()
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(context.Background(), metadata.Pairs(auth.MDKeyUsername, "sentinel", auth.MDKeyScopes, auth.ScopeSSHAuthorize)), time.Second)
	defer cancel()
	_, err = pb.NewSSHAuthzServiceClient(conn).Authorize(ctx, &pb.AuthorizeSSHRequest{})
	if err == nil || status.Code(err) == codes.Unimplemented {
		t.Fatalf("forged peer reached stub: %v", err)
	}
}
