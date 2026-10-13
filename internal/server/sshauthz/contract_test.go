package sshauthz

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/encoding/protojson"
)

type denyReasonServer struct {
	pb.UnimplementedSSHAuthzServiceServer
	reason pb.SSHDenyReason
}

func (s *denyReasonServer) Authorize(context.Context, *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error) {
	return &pb.AuthorizeSSHResponse{
		Decision:   pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY,
		DenyReason: s.reason,
		UserId:     "user-contract-test",
	}, nil
}

func TestGeneratedGatewayRoundTripsEverySSHDenyReason(t *testing.T) {
	reasons := []pb.SSHDenyReason{
		pb.SSHDenyReason_SSH_DENY_REASON_UNSPECIFIED,
		pb.SSHDenyReason_SSH_DENY_REASON_UNKNOWN_KEY,
		pb.SSHDenyReason_SSH_DENY_REASON_USER_INACTIVE,
		pb.SSHDenyReason_SSH_DENY_REASON_NO_ACCESS,
		pb.SSHDenyReason_SSH_DENY_REASON_KEY_EXPIRED,
		pb.SSHDenyReason_SSH_DENY_REASON_APPROVAL_PENDING,
		pb.SSHDenyReason_SSH_DENY_REASON_APPROVAL_DENIED,
		pb.SSHDenyReason_SSH_DENY_REASON_UPSTREAM_UNAVAILABLE,
	}

	for _, reason := range reasons {
		t.Run(reason.String(), func(t *testing.T) {
			listener := bufconn.Listen(1024 * 1024)
			grpcServer := grpc.NewServer()
			pb.RegisterSSHAuthzServiceServer(grpcServer, &denyReasonServer{reason: reason})
			go func() {
				_ = grpcServer.Serve(listener)
			}()
			t.Cleanup(func() {
				grpcServer.Stop()
				_ = listener.Close()
			})

			conn, err := grpc.NewClient(
				"passthrough:///ssh-authz-contract-test",
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
					return listener.DialContext(ctx)
				}),
			)
			if err != nil {
				t.Fatalf("create generated client connection: %v", err)
			}
			t.Cleanup(func() { _ = conn.Close() })

			mux := runtime.NewServeMux()
			client := pb.NewSSHAuthzServiceClient(conn)
			if err := pb.RegisterSSHAuthzServiceHandlerClient(context.Background(), mux, client); err != nil {
				t.Fatalf("register generated gateway: %v", err)
			}

			req := httptest.NewRequest(http.MethodPost, "/v1/ssh/authorize", strings.NewReader(`{"login":"box-user"}`))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
			}
			var got pb.AuthorizeSSHResponse
			if err := protojson.Unmarshal(rr.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode generated JSON: %v; body = %s", err, rr.Body.String())
			}
			if got.GetDenyReason() != reason {
				t.Fatalf("deny reason = %s, want %s; body = %s", got.GetDenyReason(), reason, rr.Body.String())
			}
			if got.GetDecision() != pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY {
				t.Fatalf("decision = %s, want DENY", got.GetDecision())
			}
			if got.GetUserId() != "user-contract-test" {
				t.Fatalf("user id = %q, want contract-test id", got.GetUserId())
			}
		})
	}
}

func TestServerStubReturnsUnimplemented(t *testing.T) {
	_, err := NewServer().Authorize(context.Background(), &pb.AuthorizeSSHRequest{})
	if status.Code(err) != codes.Unimplemented || !strings.Contains(fmt.Sprint(err), "not implemented") {
		t.Fatalf("Authorize error = %v, want Unimplemented stub", err)
	}
}
