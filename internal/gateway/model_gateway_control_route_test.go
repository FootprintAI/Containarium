package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// ModelGatewayService's REST mapping, end to end through the real grpc-gateway
// mux (#1726).
//
// internal/client/http_model_gateway_route_test.go pins the paths the CLIENT
// builds; this pins that the generated .pb.gw.go patterns actually MATCH those
// paths. Both halves are needed: a client path and a server pattern can each be
// self-consistent and still not meet.
//
// A 501 means the mux routed the request into the (Unimplemented) handler — which
// is the assertion. A 404 means no pattern matched, i.e. drift.
func TestModelGatewayControlRoutes(t *testing.T) {
	srv := grpc.NewServer(
		grpc.Creds(auth.NewServerTransportCredentials(nil)),
		grpc.ChainUnaryInterceptor(auth.TransportIdentityUnaryInterceptor()),
	)
	pb.RegisterModelGatewayServiceServer(srv, pb.UnimplementedModelGatewayServiceServer{})
	lis := auth.NewInternalListener()
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	mux := runtime.NewServeMux(runtime.WithIncomingHeaderMatcher(incomingHeaderMatcher))
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(lis.DialContext),
	}
	if err := pb.RegisterModelGatewayServiceHandlerFromEndpoint(context.Background(), mux, "passthrough:///containarium-internal", opts); err != nil {
		t.Fatal(err)
	}

	// The owner id carries a ':' — a path segment that grpc-gateway's mux must
	// NOT read as a custom :verb. It is not the last segment on any of these
	// routes, which is what makes that safe; this test is the proof.
	const keyPath = "/v1/model-gateway/keys/org:11111111-2222-3333-4444-555555555555/GATEWAY_PROVIDER_KAFEIDO"

	tests := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"SetTenantProviderKey", http.MethodPut, keyPath, `{"apiKey":"sk-live"}`},
		{"GetTenantProviderKeyStatus", http.MethodGet, keyPath, ""},
		{"DeleteTenantProviderKey", http.MethodDelete, keyPath, ""},
		{"MintGatewayToken", http.MethodPost, "/v1/model-gateway/tokens", `{"box":"alice","provider":"GATEWAY_PROVIDER_KAFEIDO"}`},
		{"ListGatewayModels", http.MethodGet, "/v1/model-gateway/GATEWAY_PROVIDER_KAFEIDO/models", ""},
		{"ListGatewayModels with a box", http.MethodGet, "/v1/model-gateway/GATEWAY_PROVIDER_KAFEIDO/models?box=alice", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body *strings.Reader
			if tt.body != "" {
				body = strings.NewReader(tt.body)
			} else {
				body = strings.NewReader("")
			}
			req := httptest.NewRequest(tt.method, tt.path, body)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code == http.StatusNotFound {
				t.Fatalf("%s %s → 404: no grpc-gateway pattern matched, so the proto mapping and this path have drifted (%s)",
					tt.method, tt.path, rec.Body.String())
			}
			if rec.Code != http.StatusNotImplemented {
				t.Fatalf("%s %s → HTTP %d (%s), want 501 from the Unimplemented handler",
					tt.method, tt.path, rec.Code, rec.Body.String())
			}
		})
	}
}

// The control plane's /v1/model-gateway/ prefix must not collide with the
// gateway's DATA plane at /v1/model/. A data-plane URL must not match any
// control-plane pattern.
func TestModelGatewayControlRoutes_DoNotShadowTheDataPlane(t *testing.T) {
	mux := runtime.NewServeMux(runtime.WithIncomingHeaderMatcher(incomingHeaderMatcher))
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	if err := pb.RegisterModelGatewayServiceHandlerFromEndpoint(context.Background(), mux, "passthrough:///containarium-internal", opts); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/v1/model/kafeido/v1/chat/completions",
		"/v1/model/anthropic/v1/messages",
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}")))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s matched a ModelGatewayService pattern (HTTP %d); the control plane must not shadow the data plane", path, rec.Code)
		}
	}
}
