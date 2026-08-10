package platformstats

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestUnaryInterceptor_ClassifiesByFinalStatus(t *testing.T) {
	tests := []struct {
		name       string
		handlerErr error
		wantClass  CodeClass
	}{
		{"nil error is ok", nil, CodeClassOK},
		{"InvalidArgument status is client_error", status.Error(codes.InvalidArgument, "bad"), CodeClassClientError},
		{"NotFound status is client_error", status.Error(codes.NotFound, "missing"), CodeClassClientError},
		{"Internal status is server_error", status.Error(codes.Internal, "boom"), CodeClassServerError},
		{"plain non-status error maps to Unknown -> server_error", errors.New("plain error"), CodeClassServerError},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stats := New()
			interceptor := UnaryInterceptor(stats)

			handler := func(ctx context.Context, req interface{}) (interface{}, error) {
				return "resp", tc.handlerErr
			}
			info := &grpc.UnaryServerInfo{FullMethod: "/containarium.v1.ContainerService/CreateContainer"}

			resp, err := interceptor(context.Background(), "req", info, handler)
			if !errors.Is(err, tc.handlerErr) && tc.handlerErr != nil && err.Error() != tc.handlerErr.Error() {
				t.Errorf("interceptor changed the error: got %v, want %v", err, tc.handlerErr)
			}
			if tc.handlerErr == nil && resp != "resp" {
				t.Errorf("interceptor changed the response: got %v", resp)
			}

			snap := stats.SnapshotAPI()
			if snap.RequestsByClass[tc.wantClass] != 1 {
				t.Errorf("requests[%s] = %d, want 1 (full snapshot: %+v)", tc.wantClass, snap.RequestsByClass[tc.wantClass], snap.RequestsByClass)
			}
			for class, n := range snap.RequestsByClass {
				if class != tc.wantClass && n != 0 {
					t.Errorf("unexpected count in unrelated class %s: %d", class, n)
				}
			}
		})
	}
}

// TestUnaryInterceptor_PassesThroughHandler guards that the interceptor
// is purely an observer — it must never alter the request, response, or
// error the wrapped handler produces.
func TestUnaryInterceptor_PassesThroughHandler(t *testing.T) {
	stats := New()
	interceptor := UnaryInterceptor(stats)

	sentinelErr := status.Error(codes.PermissionDenied, "no")
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		if req != "the request" {
			t.Fatalf("handler received %v, want %q", req, "the request")
		}
		return "the response", sentinelErr
	}
	info := &grpc.UnaryServerInfo{FullMethod: "/x/Y"}

	resp, err := interceptor(context.Background(), "the request", info, handler)
	if resp != "the response" {
		t.Errorf("resp = %v, want %q", resp, "the response")
	}
	if err != sentinelErr {
		t.Errorf("err = %v, want the exact sentinel error passed through unmodified", err)
	}
}
