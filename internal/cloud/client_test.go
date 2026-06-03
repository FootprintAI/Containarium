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
	mu            sync.Mutex
	bearer        string
	beats         int
	reportedID    string
	reportedState string
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

// ReportContainerState records what the client reported.
func (f *fakeActuation) ReportContainerState(ctx context.Context, req *cloudv1.ReportContainerStateRequest) (*cloudv1.ReportContainerStateResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reportedID = req.GetContainerId()
	f.reportedState = req.GetState()
	return &cloudv1.ReportContainerStateResponse{}, nil
}

// fakeActuator records the container actions the reconciler drove.
type fakeActuator struct {
	mu      sync.Mutex
	running []ContainerSpec
	stopped []string
	deleted []string
}

func (a *fakeActuator) EnsureRunning(_ context.Context, s ContainerSpec) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.running = append(a.running, s)
	return nil
}
func (a *fakeActuator) EnsureStopped(_ context.Context, name string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stopped = append(a.stopped, name)
	return nil
}
func (a *fakeActuator) EnsureDeleted(_ context.Context, name string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.deleted = append(a.deleted, name)
	return nil
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
	if _, err := New(&Config{HostID: "h", Token: "t"}, Deps{}); err == nil {
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

func TestReconcileNilDepsIsNoop(t *testing.T) {
	c := &Client{} // no sink, no actuator
	c.ctx = context.Background()
	c.reconcile(&cloudv1.AssignmentBatch{
		NetworkPolicies: []*cloudv1.NetworkPolicy{{OrgId: "x"}},
		Assignments:     []*cloudv1.Assignment{{ContainerId: "c", DesiredState: "running"}},
	}) // must not panic
}

func TestReconcileAssignment_RunningCreatesAndReports(t *testing.T) {
	cfg := &Config{ControlPlane: "bufconn", HostID: "h", Token: "h.b"}
	c, fake := newTestClient(t, cfg)
	act := &fakeActuator{}
	c.containers = act

	c.reconcileAssignment(&cloudv1.Assignment{
		ContainerId:  "11111111-2222-3333-4444-555555555555",
		OrgId:        "org-9",
		DesiredState: "running",
		Image:        "ubuntu:24.04",
		RamMb:        512,
	})

	act.mu.Lock()
	defer act.mu.Unlock()
	if len(act.running) != 1 {
		t.Fatalf("expected 1 EnsureRunning, got %d", len(act.running))
	}
	got := act.running[0]
	if got.OrgID != "org-9" || got.Image != "ubuntu:24.04" || got.RAMMB != 512 {
		t.Errorf("spec not propagated: %+v", got)
	}
	if got.LocalName != "cld-111111112222" {
		t.Errorf("local name = %q, want cld-111111112222", got.LocalName)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.reportedState != "active" || fake.reportedID != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("report = (%q,%q), want (container-id, active)", fake.reportedID, fake.reportedState)
	}
}

func TestReconcileAssignment_DesiredStates(t *testing.T) {
	cfg := &Config{ControlPlane: "bufconn", HostID: "h", Token: "h.b"}
	c, _ := newTestClient(t, cfg)
	act := &fakeActuator{}
	c.containers = act

	c.reconcileAssignment(&cloudv1.Assignment{ContainerId: "aaaa", DesiredState: "stopped"})
	c.reconcileAssignment(&cloudv1.Assignment{ContainerId: "bbbb", DesiredState: "deleted"})

	act.mu.Lock()
	defer act.mu.Unlock()
	if len(act.stopped) != 1 || act.stopped[0] != "cld-aaaa" {
		t.Errorf("stopped = %v, want [cld-aaaa]", act.stopped)
	}
	if len(act.deleted) != 1 || act.deleted[0] != "cld-bbbb" {
		t.Errorf("deleted = %v, want [cld-bbbb]", act.deleted)
	}
}

func TestLocalContainerName(t *testing.T) {
	cases := map[string]string{
		"11111111-2222-3333-4444-555555555555": "cld-111111112222",
		"short":                                "cld-short",
		"":                                     "cld-unknown",
	}
	for in, want := range cases {
		if got := localContainerName(in); got != want {
			t.Errorf("localContainerName(%q) = %q, want %q", in, got, want)
		}
	}
}
