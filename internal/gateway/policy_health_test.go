package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/policyreadiness"
)

// #2483: policy-store readiness is grpc.health.v1 on the daemon's gRPC
// server, served by the grpc-gateway at policyreadiness.HTTPPath without a
// token, so `containarium doctor` on the host can read it. Same transport
// chain as the daemon: in-process listener, transport-identity interceptor.
func TestPolicyHealthEndpoint_ServedThroughGatewayWithoutToken(t *testing.T) {
	srv := grpc.NewServer(
		grpc.Creds(auth.NewServerTransportCredentials(nil)),
		grpc.ChainUnaryInterceptor(auth.TransportIdentityUnaryInterceptor()),
	)
	h := health.NewServer()
	healthpb.RegisterHealthServer(srv, h)
	for _, svc := range policyreadiness.Services() {
		h.SetServingStatus(svc, healthpb.HealthCheckResponse_NOT_SERVING)
	}
	lis := auth.NewInternalListener()
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	conn, err := grpc.NewClient("passthrough:///containarium-internal",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(lis.DialContext))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	httpMux := http.NewServeMux()
	// Everything else on the mux requires auth; the health path must not.
	httpMux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	MountPolicyHealth(httpMux, NewRESTMux(), healthpb.NewHealthClient(conn))
	web := httptest.NewServer(httpMux)
	defer web.Close()

	check := policyreadiness.HTTPCheck(web.Client(), web.URL)
	for _, r := range policyreadiness.Run(context.Background(), check) {
		if r.Err != nil || r.Status != healthpb.HealthCheckResponse_NOT_SERVING {
			t.Fatalf("%s before recovery = %v, %v; want NOT_SERVING", r.Service, r.Status, r.Err)
		}
	}
	for _, svc := range policyreadiness.Services() {
		h.SetServingStatus(svc, healthpb.HealthCheckResponse_SERVING)
	}
	for _, r := range policyreadiness.Run(context.Background(), check) {
		if !r.Ready() {
			t.Fatalf("%s after recovery = %v, %v; want SERVING", r.Service, r.Status, r.Err)
		}
	}
}
