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

// WatchAssignments sends one batch (with the canned policies) then closes the
// stream, so watchOnce reconciles once and returns cleanly.
func (f *fakeActuation) WatchAssignments(_ *cloudv1.WatchAssignmentsRequest, stream cloudv1.ActuationService_WatchAssignmentsServer) error {
	return stream.Send(&cloudv1.AssignmentBatch{
		NetworkPolicies: []*cloudv1.NetworkPolicy{
			{OrgId: "org-1", EgressCidrs: []string{"8.8.8.8/32"}, Mode: cloudv1.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE},
		},
	})
}

// recordingSink captures the policies handed to it.
type recordingSink struct {
	mu       sync.Mutex
	policies []*cloudv1.NetworkPolicy
	calls    int
}

func (s *recordingSink) SyncNetworkPolicies(_ context.Context, p []*cloudv1.NetworkPolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.policies = p
	return nil
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
	c.ctx, c.cancel = context.WithCancel(context.Background())
	t.Cleanup(c.cancel)
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
	if _, err := New(&Config{HostID: "h", Token: "t"}, nil); err == nil {
		t.Error("New must reject a config missing control_plane")
	}
}

func TestWatchOnceSyncsNetworkPolicies(t *testing.T) {
	cfg := &Config{ControlPlane: "bufconn", HostID: "host-1", Token: "host-1.bearer"}
	c, _ := newTestClient(t, cfg)
	sink := &recordingSink{}
	c.sink = sink

	// watchOnce reconciles the one batch the fake sends, then returns on EOF.
	_ = c.watchOnce()

	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.calls == 0 {
		t.Fatal("sink never received a batch")
	}
	if len(sink.policies) != 1 || sink.policies[0].GetOrgId() != "org-1" {
		t.Fatalf("sink got wrong policies: %+v", sink.policies)
	}
	if sink.policies[0].GetMode() != cloudv1.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE {
		t.Errorf("mode not propagated: %v", sink.policies[0].GetMode())
	}
}

func TestReconcileNilSinkIsNoop(t *testing.T) {
	c := &Client{} // no sink
	c.ctx = context.Background()
	c.reconcile(&cloudv1.AssignmentBatch{NetworkPolicies: []*cloudv1.NetworkPolicy{{OrgId: "x"}}}) // must not panic
}
