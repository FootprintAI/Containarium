package sshupstream

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/sentinel/sshcontrol"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/tg123/sshpiper/libplugin"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"
)

// guardedFixture creates the real shared service before wrapping the test child.
func guardedFixture(t *testing.T) (libplugin.SshPiperPluginConfig, *sshcontrol.Peer, *int) {
	t.Helper()
	now := time.Now()
	dir, err := os.MkdirTemp("", "sshguard-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	p := &pb.SSHUpstreamPolicy{InitialDelay: durationpb.New(time.Second), MaxDelay: durationpb.New(8 * time.Second), Window: durationpb.New(time.Minute), SetupTimeout: durationpb.New(5 * time.Second), FailureBudget: 2, RiskPerAttempt: 1, MaxBackends: 8, MaxPending: 8, MaxConnections: 32, EgressGroup: "fixture", Routes: []*pb.SSHUpstreamRoute{{BackendId: "backend", Endpoint: "127.0.0.1:22"}}}
	c, err := sshcontrol.New(sshcontrol.Config{Policy: p, StatePath: filepath.Join(dir, "risk.json"), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	t.Cleanup(func() { _ = c.Close() })
	stop, err := sshcontrol.ListenControl(filepath.Join(dir, "control.sock"), c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)
	peer, err := sshcontrol.DialPeer(filepath.Join(dir, "control.sock"), pb.SSHBanListener_SSH_BAN_LISTENER_MAIN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	dials := new(int)
	child := &routingClient{callbacks: []string{"PublicKeyAuth"}, upstream: &libplugin.Upstream{Uri: "tcp://127.0.0.1:22", Auth: libplugin.CreatePrivateKeyAuth([]byte("proxy-key"))}}
	cfg, err := NewAdapter(t.Context(), child, func(context.Context, Attempt) (net.Conn, error) {
		*dials++
		a, b := net.Pipe()
		t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
		return a, nil
	}, WithControl(peer))
	if err != nil {
		t.Fatal(err)
	}
	return cfg, peer, dials
}

// TestGuardedAdapterSharesCooldownAndTypedAttribution limits real dial callbacks.
func TestGuardedAdapterSharesCooldownAndTypedAttribution(t *testing.T) {
	cfg, peer, dials := guardedFixture(t)
	for i, id := range []string{"first", "second"} {
		meta := &libplugin.ConnMeta{UniqId: id, FromAddr: "127.0.0.2:" + []string{"20001", "20002"}[i]}
		if cfg.NewConnectionCallback == nil {
			t.Fatal("guarded adapter never opens the shared transport")
		}
		if err := cfg.NewConnectionCallback(meta); err != nil {
			t.Fatal(err)
		}
		u, err := cfg.PublicKeyCallback(meta, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = cfg.CreateConnCallback(u.Uri)
		if i == 0 {
			if err != nil {
				t.Fatal(err)
			}
			cfg.UpstreamAuthFailureCallback(meta, "publickey", errors.New("backend rejected configured key"), nil)
		} else if err == nil {
			t.Fatal("second connection bypassed backend cooldown")
		}
		ctx, cancel := sshcontrol.CallContext(t.Context())
		r, e := peer.Client.ConsumeSSHUpstreamFailure(ctx, &pb.ConsumeSSHUpstreamFailureRequest{Connection: peer.Find(id, meta.FromAddr), Kind: pb.SSHUpstreamFailureKind_SSH_UPSTREAM_FAILURE_KIND_AUTH})
		cancel()
		if e != nil || r.GetCountSourceFailure() {
			t.Fatalf("confirmed backend failure charged source: %v", e)
		}
	}
	if *dials != 1 {
		t.Fatalf("backend dials=%d, want one shared admitted setup", *dials)
	}
}

// TestGuardedAdapterKeepsReadySessionOnControlLoss preserves authenticated SSH.
func TestGuardedAdapterKeepsReadySessionOnControlLoss(t *testing.T) {
	cfg, peer, _ := guardedFixture(t)
	meta := &libplugin.ConnMeta{UniqId: "ready", FromAddr: "127.0.0.2:20003"}
	if cfg.NewConnectionCallback == nil {
		t.Fatal("missing guarded transport registration")
	}
	if err := cfg.NewConnectionCallback(meta); err != nil {
		t.Fatal(err)
	}
	u, err := cfg.PublicKeyCallback(meta, nil)
	if err != nil {
		t.Fatal(err)
	}
	socket, err := cfg.CreateConnCallback(u.Uri)
	if err != nil {
		t.Fatal(err)
	}
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	cfg.PipeStartCallback(meta)
	if err := socket.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("controller RPC failure killed an authenticated session: %v", err)
	}
}

// outcomeRecorder captures the verified setup stage without mocking SSH itself.
type outcomeRecorder struct {
	pb.SentinelSSHUpstreamServiceClient
	got pb.SSHUpstreamOutcome
}

// CompleteSSHUpstream records which risk disposition the adapter actually reports.
func (r *outcomeRecorder) CompleteSSHUpstream(_ context.Context, req *pb.CompleteSSHUpstreamRequest, _ ...grpc.CallOption) (*pb.CompleteSSHUpstreamResponse, error) {
	r.got = req.Outcome
	return &pb.CompleteSSHUpstreamResponse{Accepted: true}, nil
}

// TestGuardedAdapterLateUnknownFailureRetainsRisk never refunds a post-dial timeout.
func TestGuardedAdapterLateUnknownFailureRetainsRisk(t *testing.T) {
	r := &outcomeRecorder{}
	a := &adapter{ctx: t.Context(), control: &sshcontrol.Peer{Client: r}, setups: map[string]binding{"late": {attempt: Attempt{ConnectionID: "late"}, lease: "lease", expires: time.Now().Add(-time.Second)}}, bindings: map[string]binding{}}
	a.finish("late", "", pb.SSHUpstreamOutcome_SSH_UPSTREAM_OUTCOME_SETUP_FAILED)
	if r.got != pb.SSHUpstreamOutcome_SSH_UPSTREAM_OUTCOME_SETUP_FAILED {
		t.Fatal("unknown failure was mislabeled as pure TCP failure and refunded")
	}
}
