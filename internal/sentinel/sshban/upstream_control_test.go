package sshban

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/sentinel/sshcontrol"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/tg123/sshpiper/libplugin"
	"google.golang.org/protobuf/types/known/durationpb"
)

// TestSourcePolicyUsesTypedBackendProvenance keeps server outages out of IP bans.
func TestSourcePolicyUsesTypedBackendProvenance(t *testing.T) {
	dir, err := os.MkdirTemp("", "sshsource-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	now := time.Now()
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
	peer, err := sshcontrol.DialPeer(filepath.Join(dir, "control.sock"), mainListener)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	g, _ := fixture(t, nil)
	cfg := g.PluginConfig(peer)
	m := &libplugin.ConnMeta{UniqId: "one", FromAddr: "192.0.2.1:12345"}
	if err := cfg.NewConnectionCallback(m); err != nil {
		t.Fatal(err)
	}
	ref, err := peer.Open(t.Context(), m.UniqId, m.FromAddr)
	if err != nil {
		t.Fatal(err)
	}
	route, err := peer.Client.BeginSSHUpstreamRoute(t.Context(), &pb.BeginSSHUpstreamRouteRequest{Connection: ref})
	if err != nil {
		t.Fatal(err)
	}
	l, err := peer.Client.AcquireSSHUpstream(t.Context(), &pb.AcquireSSHUpstreamRequest{Connection: ref, RouteToken: route.RouteToken, AttemptId: "one", Endpoint: "127.0.0.1:22", ProxyCredential: true})
	if err != nil || !l.GetAdmitted() {
		t.Fatalf("admission: %v", err)
	}
	if _, err := peer.Client.CompleteSSHUpstream(t.Context(), &pb.CompleteSSHUpstreamRequest{Connection: ref, RouteToken: route.RouteToken, LeaseToken: l.LeaseToken, Outcome: pb.SSHUpstreamOutcome_SSH_UPSTREAM_OUTCOME_PROXY_AUTH_REJECTED}); err != nil {
		t.Fatal(err)
	}
	cfg.UpstreamAuthFailureCallback(m, "publickey", errors.New("arbitrary text"), nil)
	if snapshot(t, g, "192.0.2.1").Status.GetFailures() != 0 {
		t.Fatal("proxy credential failure consumed source failure budget")
	}
	if _, err := peer.Client.BeginSSHUpstreamRoute(t.Context(), &pb.BeginSSHUpstreamRouteRequest{Connection: ref}); err != nil {
		t.Fatal(err)
	}
	cfg.PipeCreateErrorCallback(m.FromAddr, errors.New("arbitrary client signature denial"))
	if snapshot(t, g, "192.0.2.1").Status.GetFailures() != 1 {
		t.Fatal("later client denial inherited backend exception")
	}
}
