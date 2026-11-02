package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/zfskey"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func dryRunCtx() context.Context {
	return auth.ContextWithTestSubjectScopes(context.Background(), "alice", nil, []string{auth.ScopeContainersWrite})
}

// dryRunNoPanic calls CreateContainer and turns a panic into a failed
// assertion: a bare ContainerServer has no manager, so any path that reaches
// provisioning would dereference nil.
func dryRunNoPanic(t *testing.T, srv *ContainerServer, req *pb.CreateContainerRequest) (*pb.CreateContainerResponse, error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("CreateContainer reached provisioning on a dry run: %v", r)
		}
	}()
	return srv.CreateContainer(dryRunCtx(), req)
}

// #2925: a valid dry run passes every pre-flight check and returns before
// anything is provisioned, so a daemon with no manager at all answers it.
func TestCreateContainer_DryRun_ValidRequestProvisionsNothing(t *testing.T) {
	resp, err := dryRunNoPanic(t, &ContainerServer{}, &pb.CreateContainerRequest{
		Username: "alice", Stack: "nodejs", TtlSeconds: 3600, DryRun: true,
	})
	if err != nil {
		t.Fatalf("dry run of a valid request failed: %v", err)
	}
	if !resp.GetDryRun() {
		t.Error("response.dry_run = false: the caller cannot tell nothing was created")
	}
	if resp.GetContainer() != nil {
		t.Errorf("a dry run returned a container: %v", resp.GetContainer())
	}
}

// Every rejection a real create gives, a dry run gives, with the same code and
// text: that is what makes it safe to delete the old box after it passes.
func TestCreateContainer_DryRun_RejectsExactlyWhatARealCreateRejects(t *testing.T) {
	cases := []struct {
		name string
		req  *pb.CreateContainerRequest
		want codes.Code
	}{
		{"unknown stack", &pb.CreateContainerRequest{Username: "alice", Stack: "no-such-stack"}, codes.InvalidArgument},
		{"ttl out of range", &pb.CreateContainerRequest{Username: "alice", TtlSeconds: 1 << 40}, codes.InvalidArgument},
		{"negative idle stop", &pb.CreateContainerRequest{Username: "alice", IdleStopMinutes: -1}, codes.InvalidArgument},
		{"contradictory auto-sleep", &pb.CreateContainerRequest{Username: "alice", DisableAutoSleep: true, IdleStopMinutes: 5}, codes.InvalidArgument},
		{"negative delete-after-stopped", &pb.CreateContainerRequest{Username: "alice", DeleteAfterStoppedSeconds: -1}, codes.InvalidArgument},
		{"foreign tenant id", &pb.CreateContainerRequest{Username: "alice", TenantId: "some-other-tenant"}, codes.InvalidArgument},
		{"encrypted without key custody", &pb.CreateContainerRequest{Username: "alice", Encrypted: true}, codes.FailedPrecondition},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			real, realErr := dryRunNoPanic(t, &ContainerServer{}, tc.req)
			if realErr == nil || real != nil {
				t.Fatalf("precondition: the real create should reject %q, got resp=%v err=%v", tc.name, real, realErr)
			}
			dry := cloneCreateReq(tc.req)
			dry.DryRun = true
			resp, err := dryRunNoPanic(t, &ContainerServer{}, dry)
			if err == nil {
				t.Fatalf("dry run accepted a request the real create rejects: %v", resp)
			}
			if status.Code(err) != tc.want || status.Code(err) != status.Code(realErr) {
				t.Errorf("dry run code = %v, real = %v, want %v", status.Code(err), status.Code(realErr), tc.want)
			}
			if err.Error() != realErr.Error() {
				t.Errorf("dry run error %q differs from the real create's %q", err, realErr)
			}
		})
	}
}

// A create bound for a peer is validated locally only: forwarding a dry run
// to a peer that predates the field would make it really create the box.
func TestCreateContainer_DryRun_IsNotForwardedToAPeer(t *testing.T) {
	var hits int32
	peerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only a create is what a forwarded dry run would be. The read-only
		// GET /v1/stacks the daemon makes to check the peer's catalog (#2952)
		// is expected.
		if r.Method == http.MethodPost {
			atomic.AddInt32(&hits, 1)
		}
		_, _ = w.Write([]byte("{}"))
	}))
	defer peerSrv.Close()

	pool := NewPeerPool("local", "", nil, "")
	pool.mu.Lock()
	pool.peers["remote"] = &PeerClient{ID: "remote", Addr: peerSrv.Listener.Addr().String(), Healthy: true, client: peerSrv.Client()}
	pool.mu.Unlock()

	resp, err := dryRunNoPanic(t, &ContainerServer{peerPool: pool}, &pb.CreateContainerRequest{
		Username: "alice", Stack: "peer-only-stack", BackendId: "remote", DryRun: true,
	})
	if err != nil {
		t.Fatalf("dry run bound for a peer failed: %v", err)
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Fatalf("the peer received %d create(s) for a dry run; it could really create the box", n)
	}
	if !resp.GetDryRun() {
		t.Error("response.dry_run = false")
	}
	if resp.GetMessage() == "" {
		t.Error("the response should say the peer's own checks were not run")
	}
}

// CPU admission is checked (an over-ceiling dry run is refused like the real
// create) but the cores it reserves are released before returning.
func TestCreateContainer_DryRun_ChecksCPUAdmissionAndLeavesNoReservation(t *testing.T) {
	s := seedServer(t, 8, []incus.ContainerInfo{tenant("a", "8"), tenant("b", "4")}) // 12 of 16 committed
	// Non-admin local creates now require the enforced native account namespace.
	// This fixture isolates CPU admission after that readiness gate.
	s.nativeTenantReady = func() bool { return true }
	s.SetCPUOvercommitPolicy(2, true)

	if _, err := dryRunNoPanic(t, s, &pb.CreateContainerRequest{
		Username: "alice", Resources: &pb.ResourceLimits{Cpu: "2"}, DryRun: true,
	}); err != nil {
		t.Fatalf("a dry run that fits was rejected: %v", err)
	}
	s.cpuReservationsMu.Lock()
	left := len(s.cpuReservations)
	s.cpuReservationsMu.Unlock()
	if left != 0 {
		t.Fatalf("%d CPU reservation(s) left behind by a dry run: it would block real creates for the reservation TTL", left)
	}

	_, err := dryRunNoPanic(t, s, &pb.CreateContainerRequest{
		Username: "alice", Resources: &pb.ResourceLimits{Cpu: "8"}, DryRun: true,
	})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("an over-ceiling dry run: got %v, want ResourceExhausted", err)
	}
}

func cloneCreateReq(r *pb.CreateContainerRequest) *pb.CreateContainerRequest {
	return proto.Clone(r).(*pb.CreateContainerRequest)
}

// Key custody configured but no encryption storage wired: the real create
// refuses (it would otherwise land on the default pool in plaintext), and a
// dry run must refuse the same way without calling EnsureTenantStorage, which
// creates the tenant's dataset.
func TestCreateContainer_DryRun_EncryptedWithoutStorageWiringRefusedLikeARealCreate(t *testing.T) {
	keys, err := zfskey.NewFileKeyProvider(filepath.Join(t.TempDir(), "keys"))
	if err != nil {
		t.Fatalf("NewFileKeyProvider: %v", err)
	}
	req := &pb.CreateContainerRequest{Username: "alice", Encrypted: true}

	_, realErr := dryRunNoPanic(t, &ContainerServer{keyProvider: keys}, req)
	dry := cloneCreateReq(req)
	dry.DryRun = true
	_, dryErr := dryRunNoPanic(t, &ContainerServer{keyProvider: keys}, dry)

	if status.Code(realErr) != codes.FailedPrecondition {
		t.Fatalf("precondition: real create = %v, want FailedPrecondition", realErr)
	}
	if dryErr == nil || dryErr.Error() != realErr.Error() {
		t.Fatalf("dry run = %v, want the real create's refusal %v", dryErr, realErr)
	}
}
