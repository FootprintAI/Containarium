package cloud

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"

	cloudv1 "github.com/footprintai/containarium/pkg/pb/containarium/cloud/v1"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakeActuation records the host-bearer metadata it saw on Heartbeat.
type fakeActuation struct {
	cloudv1.UnimplementedActuationServiceServer
	mu              sync.Mutex
	bearer          string
	beats           int
	reportedID      string
	reportedState   string
	enrollToken     string
	enrollHostID    string
	enrollDriverTok string
	enrollBackendID string
	// enrollAdoptForeign records the #1006 acknowledgement flag, so a test can
	// prove `cloud enroll --adopt-foreign` actually reaches the control plane.
	enrollAdoptForeign bool
	// enrollHostIDOverride, when set, makes EnrollHost return this id instead
	// of the join token's own embedded id — simulating a cloud #572 re-enroll,
	// where the cloud resolves to a pre-existing host row with a different id.
	enrollHostIDOverride string
	statusBearer         string
	statusReq            *cloudv1.ReportHostStatusRequest
	statusReports        int

	// sshTrustVersion/sshTrustKeys configure the canned SSH CA trust bundle.
	// Zero value = "no SSH CA configured": Heartbeat leaves ssh_trust_version
	// empty and the client is expected to never call GetSSHTrustBundle.
	sshTrustVersion      string
	sshTrustKeys         []*cloudv1.SSHCAKey
	sshTrustCalls        int
	authorizeReq         *pb.AuthorizeSSHRequest
	authorizeBearer      string
	authorizeHasDeadline bool
	authorizeResp        *pb.AuthorizeSSHResponse
	authorizeErr         error
}

// EnrollHost echoes back the host id embedded in the join token (first
// dotted segment) so the client's Enroll returns it.
func (f *fakeActuation) EnrollHost(_ context.Context, req *cloudv1.EnrollHostRequest) (*cloudv1.EnrollHostResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enrollToken = req.GetJoinToken()
	f.enrollDriverTok = req.GetDriverToken()
	f.enrollBackendID = req.GetOssBackendId()
	f.enrollAdoptForeign = req.GetAdoptForeign()
	id := req.GetJoinToken()
	if i := indexByte(id, '.'); i >= 0 {
		id = id[:i]
	}
	if f.enrollHostIDOverride != "" {
		id = f.enrollHostIDOverride
	}
	f.enrollHostID = id
	return &cloudv1.EnrollHostResponse{HostId: id}, nil
}

// ReportHostStatus records the capability report + the bearer it arrived with.
func (f *fakeActuation) ReportHostStatus(ctx context.Context, req *cloudv1.ReportHostStatusRequest) (*cloudv1.ReportHostStatusResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statusReports++
	f.statusReq = req
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if v := md.Get(hostBearerMetadataKey); len(v) > 0 {
			f.statusBearer = v[0]
		}
	}
	return &cloudv1.ReportHostStatusResponse{}, nil
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
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
	return &cloudv1.HeartbeatResponse{SshTrustVersion: f.sshTrustVersion}, nil
}

func (f *fakeActuation) AuthorizeSSH(ctx context.Context, req *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.authorizeReq = req
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if v := md.Get(hostBearerMetadataKey); len(v) > 0 {
			f.authorizeBearer = v[0]
		}
	}
	_, f.authorizeHasDeadline = ctx.Deadline()
	if f.authorizeResp == nil && f.authorizeErr == nil {
		return &pb.AuthorizeSSHResponse{Decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW}, nil
	}
	return f.authorizeResp, f.authorizeErr
}

// GetSSHTrustBundle mirrors the real server's known_version short-circuit
// (internal/server/actuation_server.go's GetSSHTrustBundle on the cloud
// side) so tests exercise the real protocol, not just canned responses.
func (f *fakeActuation) GetSSHTrustBundle(_ context.Context, req *cloudv1.GetSSHTrustBundleRequest) (*cloudv1.GetSSHTrustBundleResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sshTrustCalls++
	if known := req.GetKnownVersion(); known != "" && known == f.sshTrustVersion {
		return &cloudv1.GetSSHTrustBundleResponse{Unchanged: true, Version: f.sshTrustVersion}, nil
	}
	return &cloudv1.GetSSHTrustBundleResponse{Version: f.sshTrustVersion, CaKeys: f.sshTrustKeys}, nil
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

	gc := cloudv1.NewActuationServiceClient(conn)
	c := &Client{cfg: cfg, interval: defaultHeartbeatInterval, ac: gc, watchAC: gc, sshAC: gc}
	c.ctx, c.cancel = context.WithCancel(context.Background())
	t.Cleanup(c.cancel)
	return c, fake
}

func TestAuthorizeSSHSendsBearerAndDeadline(t *testing.T) {
	cfg := &Config{ControlPlane: "bufconn", HostID: "host-1", Token: "host-1.secretbearer"}
	c, fake := newTestClient(t, cfg)
	req := &pb.AuthorizeSSHRequest{Login: "alice", SentinelId: "sentinel-1"}
	resp, err := c.AuthorizeSSH(context.Background(), req)
	if err != nil {
		t.Fatalf("AuthorizeSSH: %v", err)
	}
	if resp.GetDecision() != pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW {
		t.Fatalf("decision = %v, want ALLOW", resp.GetDecision())
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if !proto.Equal(fake.authorizeReq, req) {
		t.Fatalf("request changed: got %v, want %v", fake.authorizeReq, req)
	}
	if fake.authorizeBearer != cfg.Token {
		t.Fatalf("server saw bearer %q, want %q", fake.authorizeBearer, cfg.Token)
	}
	if !fake.authorizeHasDeadline {
		t.Fatal("AuthorizeSSH request has no deadline")
	}
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

// TestHeartbeatFetchesTrustBundleOnNewVersion is the core #1928 regression
// guard: a heartbeat that advertises a new ssh_trust_version must cause the
// client to fetch and cache the bundle, and a SUBSEQUENT heartbeat at the
// SAME version must NOT re-fetch (the whole point of the version hint is a
// near-free poll once converged).
func TestHeartbeatFetchesTrustBundleOnNewVersion(t *testing.T) {
	cfg := &Config{ControlPlane: "bufconn", HostID: "host-1", Token: "host-1.secretbearer"}
	c, fake := newTestClient(t, cfg)
	fake.sshTrustVersion = "v1"
	fake.sshTrustKeys = []*cloudv1.SSHCAKey{
		{KeyId: "ca-1", PublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA", Active: true},
	}

	if err := c.heartbeatOnce(context.Background()); err != nil {
		t.Fatalf("heartbeatOnce: %v", err)
	}

	content, version, ok := c.SSHTrustedUserCAKeys()
	if !ok {
		t.Fatal("SSHTrustedUserCAKeys: ok = false, want true after a heartbeat advertising a new version")
	}
	if version != "v1" {
		t.Errorf("version = %q, want %q", version, "v1")
	}
	if !strings.Contains(content, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA") {
		t.Errorf("content = %q, want it to contain the CA public key", content)
	}
	if !strings.Contains(content, "kid=ca-1") {
		t.Errorf("content = %q, want the key-id comment for operator visibility", content)
	}

	fake.mu.Lock()
	calls := fake.sshTrustCalls
	fake.mu.Unlock()
	if calls != 1 {
		t.Fatalf("GetSSHTrustBundle calls = %d, want 1 before the second heartbeat", calls)
	}

	// Second heartbeat at the same version: no re-fetch.
	if err := c.heartbeatOnce(context.Background()); err != nil {
		t.Fatalf("heartbeatOnce (2nd): %v", err)
	}
	fake.mu.Lock()
	calls = fake.sshTrustCalls
	fake.mu.Unlock()
	if calls != 1 {
		t.Errorf("GetSSHTrustBundle calls after 2nd heartbeat at the same version = %d, want still 1 (short-circuit)", calls)
	}
}

// TestHeartbeatSkipsTrustFetchWhenNoCAConfigured covers a cloud daemon with
// no SSH CA at all: Heartbeat leaves ssh_trust_version empty, and the client
// must never call GetSSHTrustBundle (which would 501 Unimplemented on such a
// daemon per the real server — see actuation_server.go).
func TestHeartbeatSkipsTrustFetchWhenNoCAConfigured(t *testing.T) {
	cfg := &Config{ControlPlane: "bufconn", HostID: "host-1", Token: "host-1.secretbearer"}
	c, fake := newTestClient(t, cfg)

	if err := c.heartbeatOnce(context.Background()); err != nil {
		t.Fatalf("heartbeatOnce: %v", err)
	}

	if _, _, ok := c.SSHTrustedUserCAKeys(); ok {
		t.Error("SSHTrustedUserCAKeys: ok = true, want false when the cloud daemon has no SSH CA configured")
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.sshTrustCalls != 0 {
		t.Errorf("GetSSHTrustBundle calls = %d, want 0", fake.sshTrustCalls)
	}
}

// TestRefreshSSHTrustBundleIfStale_EmptyCaKeysRefused pins the safety
// refusal: a non-unchanged response with zero CA keys (a cloud-side bug, or
// a wire hiccup) must NOT overwrite a good cached bundle — installing an
// empty TrustedUserCAKeys file would trust nothing and lock out every
// certificate-auth user, which is worse than serving stale-but-working trust.
func TestRefreshSSHTrustBundleIfStale_EmptyCaKeysRefused(t *testing.T) {
	cfg := &Config{ControlPlane: "bufconn", HostID: "host-1", Token: "host-1.secretbearer"}
	c, fake := newTestClient(t, cfg)
	fake.sshTrustVersion = "v1"
	fake.sshTrustKeys = []*cloudv1.SSHCAKey{{KeyId: "ca-1", PublicKey: "ssh-ed25519 AAAA", Active: true}}
	if err := c.heartbeatOnce(context.Background()); err != nil {
		t.Fatalf("heartbeatOnce (seed v1): %v", err)
	}
	seededContent, _, _ := c.SSHTrustedUserCAKeys()

	// Cloud rotates to v2 but (bug/hiccup) serves no keys for it.
	fake.mu.Lock()
	fake.sshTrustVersion = "v2"
	fake.sshTrustKeys = nil
	fake.mu.Unlock()
	if err := c.heartbeatOnce(context.Background()); err != nil {
		t.Fatalf("heartbeatOnce (v2, empty keys): %v", err)
	}

	content, version, ok := c.SSHTrustedUserCAKeys()
	if !ok {
		t.Fatal("SSHTrustedUserCAKeys: ok = false, want the v1 cache to survive")
	}
	if version != "v1" {
		t.Errorf("version = %q, want the refusal to keep %q", version, "v1")
	}
	if content != seededContent {
		t.Errorf("content changed despite the empty-keys refusal: got %q, want %q", content, seededContent)
	}
}

func TestRenderTrustedUserCAKeysFile(t *testing.T) {
	got := renderTrustedUserCAKeysFile([]*cloudv1.SSHCAKey{
		{KeyId: "ca-1", PublicKey: "  ssh-ed25519 AAAAactive  \n", Active: true},
		{KeyId: "ca-0", PublicKey: "ssh-ed25519 AAAAretired", Active: false},
	})
	want := "# kid=ca-1 (active)\nssh-ed25519 AAAAactive\n# kid=ca-0 (retired)\nssh-ed25519 AAAAretired\n"
	if got != want {
		t.Errorf("renderTrustedUserCAKeysFile() =\n%q\nwant\n%q", got, want)
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

// fakeProbe is a canned StatusProbe for the report-loop test.
type fakeProbe struct{ st HostStatus }

func (p fakeProbe) Probe(context.Context) (HostStatus, error) { return p.st, nil }

func TestReportStatusOnce_SendsCapabilityWithBearer(t *testing.T) {
	c, fake := newTestClient(t, &Config{
		ControlPlane: "bufnet", HostID: "h1", Token: "h1.secret", Insecure: true,
	})
	c.status = fakeProbe{st: HostStatus{
		AgentVersion: "v0.29.0", CPUCores: 8, TotalRAMMB: 32768, AvailRAMMB: 30000,
		SelfCheckOK: false,
		Checks:      []HostCheck{{Name: "useradd", OK: false, Detail: "blocked"}},
	}}

	c.reportStatusOnce()

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.statusReports != 1 {
		t.Fatalf("want 1 status report, got %d", fake.statusReports)
	}
	if fake.statusBearer != "h1.secret" {
		t.Errorf("status report missing host bearer: got %q", fake.statusBearer)
	}
	req := fake.statusReq
	if req.GetAgentVersion() != "v0.29.0" || req.GetCpuCores() != 8 || req.GetTotalRamMb() != 32768 {
		t.Errorf("capability fields not mapped: %+v", req)
	}
	if req.GetSelfCheckOk() {
		t.Error("self_check_ok should be false")
	}
	if len(req.GetChecks()) != 1 || req.GetChecks()[0].GetName() != "useradd" || req.GetChecks()[0].GetOk() {
		t.Errorf("self-check breakdown not mapped: %+v", req.GetChecks())
	}
}

// TestRefreshDriverTokenOnce_PushesMintedToken covers #557: the refresh loop
// mints a fresh driver token and pushes it via ReportHostStatus with the host
// bearer attached, so the cloud can reseal + overwrite the stored credential.
func TestRefreshDriverTokenOnce_PushesMintedToken(t *testing.T) {
	c, fake := newTestClient(t, &Config{
		ControlPlane: "bufnet", HostID: "h1", Token: "h1.secret", Insecure: true,
	})
	c.driver = func() (string, error) { return "fresh.minted.jwt", nil }

	c.refreshDriverTokenOnce()

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.statusReports != 1 {
		t.Fatalf("want 1 status report, got %d", fake.statusReports)
	}
	if fake.statusBearer != "h1.secret" {
		t.Errorf("driver-token refresh missing host bearer: got %q", fake.statusBearer)
	}
	if got := fake.statusReq.GetDriverToken(); got != "fresh.minted.jwt" {
		t.Errorf("driver token not pushed: got %q", got)
	}
}

// TestRefreshDriverTokenOnce_MintFailureSkipsPush confirms a mint error is
// swallowed (logged) and no RPC is sent — the old token stays valid until the
// next cycle.
func TestRefreshDriverTokenOnce_MintFailureSkipsPush(t *testing.T) {
	c, fake := newTestClient(t, &Config{
		ControlPlane: "bufnet", HostID: "h1", Token: "h1.secret", Insecure: true,
	})
	c.driver = func() (string, error) { return "", errMintFailed }

	c.refreshDriverTokenOnce()

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.statusReports != 0 {
		t.Fatalf("mint failure must not push a status report, got %d", fake.statusReports)
	}
}

var errMintFailed = errorString("mint failed")

type errorString string

func (e errorString) Error() string { return string(e) }

func TestEnroll_RedeemsTokenAndReturnsHostID(t *testing.T) {
	// Enroll dials its own connection, so use a real loopback TCP server
	// (bufconn isn't reachable by grpc.NewClient(addr)).
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	fake := &fakeActuation{}
	cloudv1.RegisterActuationServiceServer(srv, fake)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	hostID, bearer, err := Enroll(context.Background(), lis.Addr().String(), "host-uuid.secret", true,
		EnrollOptions{DriverToken: "admin.jwt.tok", OSSBackendID: "tunnel-gpu-1"})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if hostID != "host-uuid" {
		t.Errorf("want host id host-uuid, got %q", hostID)
	}
	if bearer != "host-uuid.secret" {
		t.Errorf("want bearer host-uuid.secret, got %q", bearer)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.enrollToken != "host-uuid.secret" {
		t.Errorf("server saw token %q", fake.enrollToken)
	}
	if fake.enrollDriverTok != "admin.jwt.tok" {
		t.Errorf("server saw driver token %q", fake.enrollDriverTok)
	}
	if fake.enrollBackendID != "tunnel-gpu-1" {
		t.Errorf("server saw backend id %q", fake.enrollBackendID)
	}
}

// TestEnroll_ReEnrollRebuildsBearerFromReturnedHostID pins the cloud #572
// re-enroll case over gRPC (mirrors TestEnrollREST_ReEnroll for the REST
// transport): the server resolves the join token to an EXISTING host row
// whose id differs from the token's own embedded (throwaway) id. The
// persisted bearer must be rebuilt from the RETURNED id, or every subsequent
// heartbeat 401s forever.
func TestEnroll_ReEnrollRebuildsBearerFromReturnedHostID(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	fake := &fakeActuation{enrollHostIDOverride: "existing-host-999"}
	cloudv1.RegisterActuationServiceServer(srv, fake)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	hostID, bearer, err := Enroll(context.Background(), lis.Addr().String(), "throwaway-host-123.secret", true, EnrollOptions{})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if hostID != "existing-host-999" {
		t.Errorf("want host id existing-host-999, got %q", hostID)
	}
	if bearer != "existing-host-999.secret" {
		t.Errorf("want bearer rebuilt from the returned id (existing-host-999.secret), got %q", bearer)
	}
}

func TestDefaultStatusProbe_ReportsVersionAndCPU(t *testing.T) {
	st, err := DefaultStatusProbe{}.Probe(context.Background())
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if st.AgentVersion == "" {
		t.Error("agent version should be set")
	}
	if st.CPUCores <= 0 {
		t.Errorf("cpu cores should be positive, got %d", st.CPUCores)
	}
	// SelfCheckOK / Checks are environment-dependent (root + useradd needed to
	// pass), so we don't assert their values — only that the self-check ran and
	// populated the breakdown on this (non-windows) platform.
	if len(st.Checks) == 0 {
		t.Error("doctor self-check should populate at least one check on non-windows")
	}
}

// fakeTerminator records the users whose sessions the reconciler ended.
type fakeTerminator struct {
	mu    sync.Mutex
	users []string
	err   error
}

func (f *fakeTerminator) TerminateUserSessions(_ context.Context, userID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.users = append(f.users, userID)
	return f.err
}

func (f *fakeTerminator) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.users...)
}

// A TERMINATE_USER_SESSIONS assignment reaches the session terminator, never
// the container actuator, and a replay of the same assignment_id is a no-op
// (#2522): WatchAssignments resends the full snapshot on every batch.
func TestReconcileAssignment_TerminateUserSessionsIdempotent(t *testing.T) {
	cfg := &Config{ControlPlane: "bufconn", HostID: "h", Token: "h.b"}
	c, fake := newTestClient(t, cfg)
	act := &fakeActuator{}
	term := &fakeTerminator{}
	c.containers, c.sessions = act, term

	batch := &cloudv1.AssignmentBatch{Assignments: []*cloudv1.Assignment{{
		AssignmentId: "as-1",
		Kind:         cloudv1.AssignmentKind_ASSIGNMENT_KIND_TERMINATE_USER_SESSIONS,
		UserId:       "alice",
	}}}
	c.reconcile(batch)
	c.reconcile(batch) // replay: same assignment_id

	if got := term.calls(); len(got) != 1 || got[0] != "alice" {
		t.Fatalf("terminator calls = %v, want exactly [alice]", got)
	}
	act.mu.Lock()
	if len(act.running)+len(act.stopped)+len(act.deleted) != 0 {
		t.Errorf("terminate assignment reached the container actuator: %+v", act)
	}
	act.mu.Unlock()
	fake.mu.Lock()
	if fake.reportedID != "" {
		t.Errorf("terminate assignment reported container state for %q", fake.reportedID)
	}
	fake.mu.Unlock()

	// A new assignment for the same user is a new request and runs.
	c.reconcile(&cloudv1.AssignmentBatch{Assignments: []*cloudv1.Assignment{{
		AssignmentId: "as-2",
		Kind:         cloudv1.AssignmentKind_ASSIGNMENT_KIND_TERMINATE_USER_SESSIONS,
		UserId:       "alice",
	}}})
	if got := term.calls(); len(got) != 2 {
		t.Errorf("a new assignment_id should run again: %v", got)
	}
}

// A failed termination is not recorded as done, so the next delivery retries.
func TestReconcileAssignment_TerminateFailureRetries(t *testing.T) {
	c := &Client{ctx: context.Background()}
	term := &fakeTerminator{err: errors.New("db down")}
	c.sessions = term
	a := &cloudv1.Assignment{
		AssignmentId: "as-1",
		Kind:         cloudv1.AssignmentKind_ASSIGNMENT_KIND_TERMINATE_USER_SESSIONS,
		UserId:       "alice",
	}
	c.reconcileAssignment(a)
	term.mu.Lock()
	term.err = nil
	term.mu.Unlock()
	c.reconcileAssignment(a)
	c.reconcileAssignment(a)
	if got := term.calls(); len(got) != 2 {
		t.Errorf("calls = %v, want a retry after the failure and then nothing", got)
	}
}

// Without a terminator (or without a user) nothing runs and nothing panics.
func TestReconcileAssignment_TerminateWithoutDeps(t *testing.T) {
	c := &Client{ctx: context.Background()}
	c.reconcile(&cloudv1.AssignmentBatch{Assignments: []*cloudv1.Assignment{{
		AssignmentId: "as-1", Kind: cloudv1.AssignmentKind_ASSIGNMENT_KIND_TERMINATE_USER_SESSIONS, UserId: "alice",
	}}})
	term := &fakeTerminator{}
	c.sessions = term
	c.reconcileAssignment(&cloudv1.Assignment{
		AssignmentId: "as-2", Kind: cloudv1.AssignmentKind_ASSIGNMENT_KIND_TERMINATE_USER_SESSIONS,
	})
	if got := term.calls(); len(got) != 0 {
		t.Errorf("an assignment without user_id ran: %v", got)
	}
}

// An id the host cannot map to a local login (#2602) is logged at warn with
// the assignment id and reported as its own outcome, distinct from a walk
// that found no live sessions. Redelivery of either is a no-op.
func TestReconcileTermination_UnmappedIsDistinctFromZeroSessions(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	assignment := func(id, user string) *cloudv1.Assignment {
		return &cloudv1.Assignment{AssignmentId: id, Kind: cloudv1.AssignmentKind_ASSIGNMENT_KIND_TERMINATE_USER_SESSIONS, UserId: user}
	}

	unmapped := &fakeTerminator{err: fmt.Errorf("%w: cp-user-9", ErrUserNotMapped)}
	c := &Client{ctx: context.Background(), sessions: unmapped}
	if got := c.reconcileTermination(assignment("as-unmapped", "cp-user-9")); got != terminationUnmapped {
		t.Errorf("unmapped outcome = %v, want %v", got, terminationUnmapped)
	}
	line := buf.String()
	if !strings.Contains(line, "WARN") || !strings.Contains(line, "as-unmapped") || !strings.Contains(line, "cp-user-9") {
		t.Errorf("log = %q, want a warning naming the assignment and user", line)
	}
	if got := c.reconcileTermination(assignment("as-unmapped", "cp-user-9")); got != terminationReplayed {
		t.Errorf("redelivered unmapped outcome = %v, want %v", got, terminationReplayed)
	}
	if n := len(unmapped.calls()); n != 1 {
		t.Errorf("terminator calls = %d, want 1 (redelivery is a no-op)", n)
	}

	buf.Reset()
	zero := &fakeTerminator{} // mapped, but the walk ended nothing
	c = &Client{ctx: context.Background(), sessions: zero}
	if got := c.reconcileTermination(assignment("as-zero", "alice")); got != terminationEnded {
		t.Errorf("zero-session outcome = %v, want %v", got, terminationEnded)
	}
	if strings.Contains(buf.String(), "WARN") {
		t.Errorf("a successful walk logged a warning: %q", buf.String())
	}
	if got := c.reconcileTermination(assignment("as-zero", "alice")); got != terminationReplayed {
		t.Errorf("redelivered outcome = %v, want %v", got, terminationReplayed)
	}
	if n := len(zero.calls()); n != 1 {
		t.Errorf("terminator calls = %d, want 1", n)
	}

	failing := &fakeTerminator{err: errors.New("db down")}
	c = &Client{ctx: context.Background(), sessions: failing}
	if got := c.reconcileTermination(assignment("as-fail", "alice")); got != terminationFailed {
		t.Errorf("failure outcome = %v, want %v", got, terminationFailed)
	}
}
