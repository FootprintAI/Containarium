package sshauthz

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestHTTPAuthorizerSignedContract(t *testing.T) {
	secret := []byte("test-sentinel-secret-32-bytes-long")
	verifier := auth.NewSentinelVerifier(nil, secret)
	for reasonNumber := int32(0); reasonNumber <= 7; reasonNumber++ {
		t.Run(pb.SSHDenyReason(reasonNumber).String(), func(t *testing.T) {
			reason := pb.SSHDenyReason(reasonNumber)
			response := &pb.AuthorizeSSHResponse{Decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY, DenyReason: reason, UserId: "user-test"}
			if reasonNumber == 0 {
				response.Decision = pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW
				response.CacheTtl = durationpb.New(17 * time.Second)
			}
			daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != AuthorizePath || r.Header.Get("Content-Type") != "application/json" {
					t.Errorf("bad request: %s %s", r.Method, r.URL)
				}
				if err := verifier.VerifyRequest(r, time.Now()); err != nil {
					t.Errorf("signature: %v", err)
					w.WriteHeader(401)
					return
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("request body: %v", err)
				}
				req := &pb.AuthorizeSSHRequest{}
				if err := protojson.Unmarshal(body, req); err != nil || req.GetLogin() != "alice" || req.GetCredential().GetPublicKey().GetFingerprintSha256() != "SHA256:test" {
					t.Errorf("request: %v %v", req, err)
				}
				raw, err := protojson.Marshal(response)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = w.Write(raw)
			}))
			defer daemon.Close()
			a := &HTTPAuthorizer{BackendURL: func(id string) (string, error) {
				if id != "backend" {
					t.Errorf("backend %s", id)
				}
				return daemon.URL, nil
			}, Sign: func(r *http.Request) { auth.SignSentinelRequest(r, secret) }}
			got, err := a.Authorize(context.Background(), "backend", &pb.AuthorizeSSHRequest{Login: "alice", Credential: &pb.SSHCredential{Kind: &pb.SSHCredential_PublicKey{PublicKey: &pb.SSHPublicKeyCredential{FingerprintSha256: "SHA256:test", KeyType: pb.SSHKeyType_SSH_KEY_TYPE_ED25519}}}})
			if err != nil || got.GetDecision() != response.GetDecision() || got.GetDenyReason() != reason || got.GetUserId() != "user-test" || got.GetCacheTtl().AsDuration() != response.GetCacheTtl().AsDuration() {
				t.Fatalf("response: %v %v", got, err)
			}
		})
	}
}

func TestHTTPAuthorizerStatusAndRedirect(t *testing.T) {
	for _, status := range []int{401, 403, 429, 500, 503, 302} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			targetCalls := 0
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				targetCalls++
				_, _ = w.Write([]byte(`{"decision":"SSH_AUTHZ_DECISION_ALLOW"}`))
			}))
			defer target.Close()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", target.URL)
				w.WriteHeader(status)
			}))
			defer server.Close()
			a := &HTTPAuthorizer{BackendURL: func(string) (string, error) { return server.URL, nil }}
			_, err := a.Authorize(context.Background(), "b", &pb.AuthorizeSSHRequest{Login: "alice"})
			if err == nil || isOutage(err) != (status >= 500) || targetCalls != 0 {
				t.Fatalf("status %d: %v, redirect calls %d", status, err, targetCalls)
			}
		})
	}
}

func TestBridgeUsesLiveRouteAndPreservesContract(t *testing.T) {
	backend := "backend-a"
	calls := 0
	resolver := resolverFunc(func(_ context.Context, login string) (string, bool, error) { return backend, login == "alice", nil })
	authorizer := authorizerFunc(func(_ context.Context, b string, r *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error) {
		calls++
		if b != backend || r.GetLogin() != "alice" {
			t.Error("bad forwarding")
		}
		return allowed("user"), nil
	})
	socket := filepath.Join(t.TempDir(), "bridge.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: BridgeHandler(resolver, authorizer), ReadHeaderTimeout: time.Second}
	defer func() { _ = srv.Close() }()
	go func() { _ = srv.Serve(ln) }()
	client := NewBridgeClient(socket)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	b, known, err := client.ResolveBackend(ctx, "alice")
	if err != nil || !known || b != backend {
		t.Fatalf("route: %s %v %v", b, known, err)
	}
	_, known, err = client.ResolveBackend(ctx, "missing")
	if err != nil || known {
		t.Fatal("unknown login")
	}
	res, err := client.Authorize(ctx, b, &pb.AuthorizeSSHRequest{Login: "alice"})
	if err != nil || res.GetUserId() != "user" {
		t.Fatalf("authorize: %v %v", res, err)
	}
	backend = "backend-b"
	if _, err := client.Authorize(ctx, b, &pb.AuthorizeSSHRequest{Login: "alice"}); err == nil || isOutage(err) {
		t.Fatal("route change must reject without grace")
	}
	if calls != 1 {
		t.Fatalf("forwarded stale route: calls %d", calls)
	}
	b, known, err = client.ResolveBackend(ctx, "alice")
	if err != nil || !known || b != backend {
		t.Fatal("route snapshot is stale")
	}
}

// The bridge passes the resolver's routing readiness through; a resolver
// without the signal is always authoritative, and a dead bridge reads as not
// ready, which is the safer thing for the enforcing plugin to log.
func TestBridgeReportsRoutingReadiness(t *testing.T) {
	authorizer := authorizerFunc(nil)
	for _, tt := range []struct {
		name     string
		resolver BackendResolver
		want     bool
	}{
		{name: "no signal is ready", resolver: resolverFunc(nil), want: true},
		{name: "synced is ready", resolver: readyResolver{resolverFunc: resolverFunc(nil), ready: true}, want: true},
		{name: "unsynced is not ready", resolver: readyResolver{resolverFunc: resolverFunc(nil), ready: false}, want: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			socket := filepath.Join(t.TempDir(), "bridge.sock")
			ln, err := net.Listen("unix", socket)
			if err != nil {
				t.Fatal(err)
			}
			srv := &http.Server{Handler: BridgeHandler(tt.resolver, authorizer), ReadHeaderTimeout: time.Second}
			go func() { _ = srv.Serve(ln) }()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			client := NewBridgeClient(socket)
			if got := client.RoutingReady(ctx); got != tt.want {
				t.Fatalf("RoutingReady = %v, want %v", got, tt.want)
			}
			_ = srv.Close()
			if client.RoutingReady(ctx) {
				t.Fatal("a dead bridge must read as not ready")
			}
		})
	}
}

func TestBridgePropagatesDeadlineAndProtocolFailure(t *testing.T) {
	resolver := resolverFunc(func(context.Context, string) (string, bool, error) { return "backend", true, nil })
	for _, protocolFailure := range []bool{false, true} {
		authorizer := authorizerFunc(func(ctx context.Context, _ string, _ *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error) {
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) > 250*time.Millisecond {
				t.Error("plugin deadline was not propagated")
			}
			if protocolFailure {
				return nil, &ProtocolError{fmt.Errorf("bad response")}
			}
			<-ctx.Done()
			return nil, ctx.Err()
		})
		socket := filepath.Join(t.TempDir(), "bridge.sock")
		ln, err := net.Listen("unix", socket)
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{Handler: BridgeHandler(resolver, authorizer), ReadHeaderTimeout: time.Second}
		go func() { _ = srv.Serve(ln) }()
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		_, err = NewBridgeClient(socket).Authorize(ctx, "backend", &pb.AuthorizeSSHRequest{Login: "alice"})
		cancel()
		_ = srv.Close()
		if err == nil || isOutage(err) == protocolFailure {
			t.Fatalf("protocol failure=%v err=%v", protocolFailure, err)
		}
	}
}
