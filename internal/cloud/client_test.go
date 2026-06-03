package cloud

import (
	"context"
	"net"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"

	cloudv1 "github.com/footprintai/containarium/pkg/pb/containarium/cloud/v1"
)

// fakeActuation records the host-bearer metadata it saw on Heartbeat.
type fakeActuation struct {
	cloudv1.UnimplementedActuationServiceServer
	mu     sync.Mutex
	bearer string
	beats  int
}

func (f *fakeActuation) Heartbeat(ctx context.Context, _ *cloudv1.HeartbeatRequest) (*cloudv1.HeartbeatResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.beats++
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if v := md.Get(hostBearerMetadataKey); len(v) > 0 {
			f.bearer = v[0]
		}
	}
	return &cloudv1.HeartbeatResponse{}, nil
}

// newTestClient wires a Client to a bufconn-backed fake server, bypassing dial.
func newTestClient(t *testing.T, cfg *Config) (*Client, *fakeActuation) {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	fake := &fakeActuation{}
	cloudv1.RegisterActuationServiceServer(srv, fake)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough://bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial bufconn: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	c := &Client{cfg: cfg, interval: defaultHeartbeatInterval, ac: cloudv1.NewActuationServiceClient(conn)}
	return c, fake
}

func TestHeartbeatSendsHostBearer(t *testing.T) {
	cfg := &Config{ControlPlane: "bufconn", HostID: "host-1", Token: "host-1.secretbearer"}
	c, fake := newTestClient(t, cfg)

	if err := c.heartbeatOnce(context.Background()); err != nil {
		t.Fatalf("heartbeatOnce: %v", err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.beats != 1 {
		t.Errorf("expected 1 heartbeat, got %d", fake.beats)
	}
	if fake.bearer != "host-1.secretbearer" {
		t.Errorf("server saw bearer %q, want the configured token", fake.bearer)
	}
}

func TestNewRejectsIncompleteConfig(t *testing.T) {
	if _, err := New(&Config{HostID: "h", Token: "t"}); err == nil {
		t.Error("New must reject a config missing control_plane")
	}
}
