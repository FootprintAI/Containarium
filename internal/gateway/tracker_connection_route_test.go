package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #2035: GET /v1/tracker/connections/{username}/{name} (GetTrackerConnection)
// collides with GET /v1/tracker/{username}/{connection}/<literal> (e.g.
// ListTrackerRoutes's .../routes, ListTrackerIssues's .../issues) when a
// connection is literally named one of those literals — grpc-gateway v2
// resolves the later-registered pattern, so GetTrackerConnection becomes
// unreachable over REST for that connection name.
//
// The fix (SetTrackerConnection rejects the reserved names — see
// internal/server/tracker_server.go's reservedTrackerConnectionNames /
// reservedTrackerUsernames) is proven in internal/server/tracker_server_test.go.
// This file proves the REST half end to end through the real grpc-gateway
// mux: every name the validator accepts actually reaches
// GetTrackerConnection (not some other, differently-shaped pattern), and —
// as a characterization check documenting the bug the fix exists for — a
// reserved literal used as a connection name really would be shadowed if
// it ever reached the gateway.
//
// fakeTrackerRouteServer tags each response with the RPC that handled it,
// so a 501 alone can't hide a misroute the way it would with
// pb.UnimplementedTrackerServiceServer shared across every method.
type fakeTrackerRouteServer struct {
	pb.UnimplementedTrackerServiceServer
}

func (fakeTrackerRouteServer) GetTrackerConnection(context.Context, *pb.GetTrackerConnectionRequest) (*pb.GetTrackerConnectionResponse, error) {
	return nil, status.Error(codes.Unimplemented, "called:GetTrackerConnection")
}

func (fakeTrackerRouteServer) ListTrackerRoutes(context.Context, *pb.ListTrackerRoutesRequest) (*pb.ListTrackerRoutesResponse, error) {
	return nil, status.Error(codes.Unimplemented, "called:ListTrackerRoutes")
}

func (fakeTrackerRouteServer) ListTrackerIssues(context.Context, *pb.ListTrackerIssuesRequest) (*pb.ListTrackerIssuesResponse, error) {
	return nil, status.Error(codes.Unimplemented, "called:ListTrackerIssues")
}

// newTrackerRouteTestMux wires a real grpc-gateway ServeMux in front of a
// real gRPC server (over an in-memory listener), exactly as the daemon
// does — the same shape as TestModelGatewayControlRoutes.
func newTrackerRouteTestMux(t *testing.T) *runtime.ServeMux {
	t.Helper()
	srv := grpc.NewServer(
		grpc.Creds(auth.NewServerTransportCredentials(nil)),
		grpc.ChainUnaryInterceptor(auth.TransportIdentityUnaryInterceptor()),
	)
	pb.RegisterTrackerServiceServer(srv, fakeTrackerRouteServer{})
	lis := auth.NewInternalListener()
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	mux := runtime.NewServeMux(runtime.WithIncomingHeaderMatcher(incomingHeaderMatcher))
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(lis.DialContext),
	}
	if err := pb.RegisterTrackerServiceHandlerFromEndpoint(context.Background(), mux, "passthrough:///containarium-internal", opts); err != nil {
		t.Fatal(err)
	}
	return mux
}

// TestTrackerConnectionGetRoute_ReachableForAcceptedNames proves every
// connection name SetTrackerConnection's validator now accepts (#2035's
// reservedTrackerConnectionNames does not list these) is reachable over
// REST as GetTrackerConnection — including names that merely contain a
// reserved word as a substring, which must NOT be treated as reserved.
func TestTrackerConnectionGetRoute_ReachableForAcceptedNames(t *testing.T) {
	mux := newTrackerRouteTestMux(t)

	for _, name := range []string{"default", "my-connection", "issues-tracker", "routes2"} {
		t.Run(name, func(t *testing.T) {
			path := "/v1/tracker/connections/alice/" + name
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code == http.StatusNotFound {
				t.Fatalf("GET %s → 404: no grpc-gateway pattern matched (%s)", path, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "called:GetTrackerConnection") {
				t.Fatalf("GET %s → %s, want it routed to GetTrackerConnection", path, rec.Body.String())
			}
		})
	}
}

// TestTrackerConnectionGetRoute_ShadowedForReservedNames is a
// characterization test: it documents the collision #2035 fixes by
// confirming that a reserved literal used as a connection name really
// would be misrouted to a different RPC if SetTrackerConnection ever let
// one through. This is what makes rejecting these names at write time
// (rather than, say, only warning) the correct fix.
func TestTrackerConnectionGetRoute_ShadowedForReservedNames(t *testing.T) {
	mux := newTrackerRouteTestMux(t)

	tests := []struct {
		reservedName string
		wantCalled   string
	}{
		{"routes", "called:ListTrackerRoutes"},
		{"issues", "called:ListTrackerIssues"},
	}
	for _, tt := range tests {
		t.Run(tt.reservedName, func(t *testing.T) {
			path := "/v1/tracker/connections/alice/" + tt.reservedName
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if !strings.Contains(rec.Body.String(), tt.wantCalled) {
				t.Fatalf("GET %s → %s, want it shadowed by %s (proving the collision #2035 guards against)", path, rec.Body.String(), tt.wantCalled)
			}
		})
	}
}
