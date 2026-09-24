package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// The REST gateway must reach the transport-authenticated gRPC server through
// the in-process listener. An Unimplemented reply (REST 501) proves the call
// got past the transport check into the handler; a rejected transport would
// surface as 401/503 instead.
func TestGatewayReachesGRPCServerOverInternalListener(t *testing.T) {
	srv := grpc.NewServer(
		grpc.Creds(auth.NewServerTransportCredentials(nil)),
		grpc.ChainUnaryInterceptor(auth.TransportIdentityUnaryInterceptor()),
	)
	pb.RegisterContainerServiceServer(srv, pb.UnimplementedContainerServiceServer{})
	lis := auth.NewInternalListener()
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	mux := runtime.NewServeMux(runtime.WithIncomingHeaderMatcher(incomingHeaderMatcher))
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(lis.DialContext),
	}
	if err := pb.RegisterContainerServiceHandlerFromEndpoint(context.Background(), mux, "passthrough:///containarium-internal", opts); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/containers", nil)
	req.Header.Set("Grpc-Metadata-Roles", "admin") // must be dropped, not forwarded
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("gateway → internal listener: got HTTP %d (%s), want 501 from the Unimplemented handler", rec.Code, rec.Body.String())
	}
}
