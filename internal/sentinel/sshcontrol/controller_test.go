package sshcontrol

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/durationpb"
)

// controlClock is synchronized because generated clients invoke another goroutine.
type controlClock struct {
	mu sync.Mutex
	t  time.Time
}

// now supplies the same deterministic instant to admission and persistence.
func (c *controlClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }

// advance models elapsed jail windows without sleeping for production durations.
func (c *controlClock) advance(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.t = c.t.Add(d) }

// controlFixture owns a real private socket and the generated client.
type controlFixture struct {
	t      *testing.T
	clock  *controlClock
	cfg    Config
	server *Controller
	client pb.SentinelSSHUpstreamServiceClient
}

// newControlFixture uses explicit synthetic policy with a completed initial hold.
func newControlFixture(t *testing.T) *controlFixture {
	t.Helper()
	f := &controlFixture{t: t, clock: &controlClock{t: time.Unix(1000, 0)}}
	f.cfg = Config{Policy: &pb.SSHUpstreamPolicy{
		InitialDelay: durationpb.New(time.Second), MaxDelay: durationpb.New(8 * time.Second),
		Window: durationpb.New(time.Minute), SetupTimeout: durationpb.New(5 * time.Second),
		FailureBudget: 2, RiskPerAttempt: 1, MaxBackends: 8, MaxPending: 8, MaxConnections: 32, EgressGroup: "test-egress",
	}, StatePath: filepath.Join(t.TempDir(), "state", "risk.json"), Now: f.clock.now,
		Resolve: func(endpoint string) (string, error) {
			switch endpoint {
			case "127.0.0.1:22", "127.0.0.1:2222":
				return "backend-a", nil
			case "127.0.0.3:22":
				return "backend-b", nil
			default:
				return "", fmt.Errorf("endpoint is not in authoritative inventory")
			}
		}}
	var err error
	f.server, err = New(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.server.Close() })
	f.client = f.serve(f.server)
	f.clock.advance(time.Minute)
	return f
}

// serve exercises the generated client over an actual operator-private socket.
func (f *controlFixture) serve(c *Controller) pb.SentinelSSHUpstreamServiceClient {
	f.t.Helper()
	dir, err := os.MkdirTemp("", "sshctl-")
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "control.sock")
	stop, err := ListenControl(sock, c)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(stop)
	conn, err := grpc.NewClient("unix://"+sock, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = conn.Close() })
	return pb.NewSentinelSSHUpstreamServiceClient(conn)
}

// open binds the real metadata-shaped identity to this controller generation.
func (f *controlFixture) open(client pb.SentinelSSHUpstreamServiceClient, listener pb.SSHBanListener, id string) *pb.SSHUpstreamConnection {
	f.t.Helper()
	ref := &pb.SSHUpstreamConnection{Listener: listener, ConnectionId: id, RemoteAddr: "127.0.0.2:" + fmt.Sprint(20000+len(id))}
	r, err := client.OpenSSHUpstreamConnection(f.t.Context(), &pb.OpenSSHUpstreamConnectionRequest{Connection: ref})
	if err != nil {
		f.t.Fatal(err)
	}
	ref.ControllerGeneration = r.ControllerGeneration
	return ref
}

// route starts fresh provenance even if the same connection previously failed.
func (f *controlFixture) route(client pb.SentinelSSHUpstreamServiceClient, ref *pb.SSHUpstreamConnection) string {
	f.t.Helper()
	r, err := client.BeginSSHUpstreamRoute(f.t.Context(), &pb.BeginSSHUpstreamRouteRequest{Connection: ref})
	if err != nil {
		f.t.Fatal(err)
	}
	return r.RouteToken
}

// acquire submits the child-selected endpoint and requires a typed decision.
func (f *controlFixture) acquire(client pb.SentinelSSHUpstreamServiceClient, ref *pb.SSHUpstreamConnection, token, endpoint string) *pb.AcquireSSHUpstreamResponse {
	f.t.Helper()
	r, err := client.AcquireSSHUpstream(f.t.Context(), &pb.AcquireSSHUpstreamRequest{Connection: ref, RouteToken: token, AttemptId: "attempt-" + token, Endpoint: endpoint, ProxyCredential: true})
	if err != nil {
		f.t.Fatal(err)
	}
	return r
}

// finish requires acknowledgement of exactly the admitted route and lease.
func (f *controlFixture) finish(ref *pb.SSHUpstreamConnection, token string, lease *pb.AcquireSSHUpstreamResponse, outcome pb.SSHUpstreamOutcome) {
	f.t.Helper()
	r, err := f.client.CompleteSSHUpstream(f.t.Context(), &pb.CompleteSSHUpstreamRequest{Connection: ref, RouteToken: token, LeaseToken: lease.LeaseToken, Outcome: outcome})
	if err != nil || !r.GetAccepted() {
		f.t.Fatalf("outcome was not committed: %v", err)
	}
}

// count queries one real observer event without examining its error string.
func (f *controlFixture) count(ref *pb.SSHUpstreamConnection, kind pb.SSHUpstreamFailureKind) bool {
	f.t.Helper()
	r, err := f.client.ConsumeSSHUpstreamFailure(f.t.Context(), &pb.ConsumeSSHUpstreamFailureRequest{Connection: ref, Kind: kind})
	if err != nil {
		f.t.Fatal(err)
	}
	return r.CountSourceFailure
}

// TestControlSharedBudgetAndProvenance shares risk across two listener processes.
func TestControlSharedBudgetAndProvenance(t *testing.T) {
	f := newControlFixture(t)
	a := f.open(f.client, pb.SSHBanListener_SSH_BAN_LISTENER_MAIN, "main")
	b := f.open(f.client, pb.SSHBanListener_SSH_BAN_LISTENER_ANONYMOUS, "anonymous")
	if _, err := f.client.RegisterSSHAnonymousRoute(t.Context(), &pb.RegisterSSHAnonymousRouteRequest{Connection: b, BoxName: "box", Endpoint: "127.0.0.1:2222"}); err != nil {
		t.Fatal(err)
	}
	at, bt := f.route(f.client, a), f.route(f.client, b)
	al, bl := f.acquire(f.client, a, at, "127.0.0.1:22"), f.acquire(f.client, b, bt, "127.0.0.1:2222")
	if !al.Admitted || !bl.Admitted {
		t.Fatal("initial weighted reservations were not admitted")
	}
	c := f.open(f.client, pb.SSHBanListener_SSH_BAN_LISTENER_MAIN, "third")
	ct := f.route(f.client, c)
	if f.acquire(f.client, c, ct, "127.0.0.1:22").Admitted || f.count(c, pb.SSHUpstreamFailureKind_SSH_UPSTREAM_FAILURE_KIND_PIPE_CREATE) {
		t.Fatal("other listener bypassed budget or suppression punished source")
	}
	f.finish(a, at, al, pb.SSHUpstreamOutcome_SSH_UPSTREAM_OUTCOME_PROXY_AUTH_REJECTED)
	if f.count(a, pb.SSHUpstreamFailureKind_SSH_UPSTREAM_FAILURE_KIND_AUTH) || !f.count(a, pb.SSHUpstreamFailureKind_SSH_UPSTREAM_FAILURE_KIND_AUTH) {
		t.Fatal("confirmed backend auth exception must be consumed once")
	}
	f.finish(b, bt, bl, pb.SSHUpstreamOutcome_SSH_UPSTREAM_OUTCOME_SSH_READY)
	// An old ready setup cannot reopen a newer outage.
	at = f.route(f.client, a)
	if f.acquire(f.client, a, at, "127.0.0.1:22").Admitted {
		t.Fatal("old ready result cleared cooldown")
	}
	f.clock.advance(time.Second)
	at = f.route(f.client, a)
	al = f.acquire(f.client, a, at, "127.0.0.1:22")
	if !al.Admitted {
		t.Fatal("safe recovery probe was not admitted")
	}
	f.finish(a, at, al, pb.SSHUpstreamOutcome_SSH_UPSTREAM_OUTCOME_SSH_READY)
}

// TestControlLaterClientDenialDoesNotInheritException preserves genuine failures.
func TestControlLaterClientDenialDoesNotInheritException(t *testing.T) {
	f := newControlFixture(t)
	a := f.open(f.client, pb.SSHBanListener_SSH_BAN_LISTENER_MAIN, "retry")
	token := f.route(f.client, a)
	l := f.acquire(f.client, a, token, "127.0.0.1:22")
	f.finish(a, token, l, pb.SSHUpstreamOutcome_SSH_UPSTREAM_OUTCOME_TCP_REFUSED)
	_ = f.route(f.client, a) // next child rejects the key, so no backend is selected
	if !f.count(a, pb.SSHUpstreamFailureKind_SSH_UPSTREAM_FAILURE_KIND_PIPE_CREATE) {
		t.Fatal("later tenant denial inherited an unrelated backend exemption")
	}
}

// TestControlRestartRetainsPendingRiskAndRejectsOldGeneration restores conservatively.
func TestControlRestartRetainsPendingRiskAndRejectsOldGeneration(t *testing.T) {
	f := newControlFixture(t)
	a := f.open(f.client, pb.SSHBanListener_SSH_BAN_LISTENER_MAIN, "old")
	token := f.route(f.client, a)
	l := f.acquire(f.client, a, token, "127.0.0.1:22")
	if err := f.server.Close(); err != nil {
		t.Fatal(err)
	}
	replacement, err := New(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = replacement.Close() })
	client := f.serve(replacement)
	r, err := client.CompleteSSHUpstream(t.Context(), &pb.CompleteSSHUpstreamRequest{Connection: a, RouteToken: token, LeaseToken: l.LeaseToken, Outcome: pb.SSHUpstreamOutcome_SSH_UPSTREAM_OUTCOME_SSH_READY})
	if err == nil && r.GetAccepted() {
		t.Fatal("old controller acknowledgement reopened replacement")
	}
	b := f.open(client, pb.SSHBanListener_SSH_BAN_LISTENER_MAIN, "new")
	bt := f.route(client, b)
	if f.acquire(client, b, bt, "127.0.0.1:22").Admitted {
		t.Fatal("restart discarded a pending setup")
	}
}

// TestControlRejectsForgedTokensAndCorruptState denies untrusted connection state.
func TestControlRejectsForgedTokensAndCorruptState(t *testing.T) {
	f := newControlFixture(t)
	a := f.open(f.client, pb.SSHBanListener_SSH_BAN_LISTENER_MAIN, "identity")
	_ = f.route(f.client, a)
	if _, err := f.client.AcquireSSHUpstream(t.Context(), &pb.AcquireSSHUpstreamRequest{Connection: a, RouteToken: "forged", AttemptId: "forged", Endpoint: "127.0.0.1:22"}); err == nil {
		t.Fatal("forged route token was admitted")
	}
	if err := os.WriteFile(f.cfg.StatePath, []byte("broken checkpoint"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.server.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := New(f.cfg); err == nil {
		t.Fatal("corrupt state silently reset risk")
	}
}

// TestControlCheckpointHasOneOwner forbids parallel processes from resetting risk.
func TestControlCheckpointHasOneOwner(t *testing.T) {
	f := newControlFixture(t)
	other, err := New(f.cfg)
	if err == nil {
		_ = other.Close()
		t.Fatal("two controllers acquired the same durable risk checkpoint")
	}
}

// TestControlSuccessfulSessionsReleaseSetupCapacity keeps established sessions independent.
func TestControlSuccessfulSessionsReleaseSetupCapacity(t *testing.T) {
	f := newControlFixture(t)
	for i := range 40 {
		ref := f.open(f.client, pb.SSHBanListener_SSH_BAN_LISTENER_MAIN, fmt.Sprint("ready-", i))
		token := f.route(f.client, ref)
		lease := f.acquire(f.client, ref, token, "127.0.0.1:22")
		if !lease.Admitted {
			t.Fatal("successful sessions exhausted setup capacity")
		}
		f.finish(ref, token, lease, pb.SSHUpstreamOutcome_SSH_UPSTREAM_OUTCOME_SSH_READY)
	}
}

// TestControlReadyRejectsRemovedInventory cannot promote a stale selected route.
func TestControlReadyRejectsRemovedInventory(t *testing.T) {
	f := newControlFixture(t)
	ref := f.open(f.client, pb.SSHBanListener_SSH_BAN_LISTENER_MAIN, "removed")
	token := f.route(f.client, ref)
	l := f.acquire(f.client, ref, token, "127.0.0.1:22")
	f.server.mu.Lock()
	f.server.cfg.Resolve = func(string) (string, error) { return "", fmt.Errorf("removed route") }
	f.server.mu.Unlock()
	r, err := f.client.CompleteSSHUpstream(t.Context(), &pb.CompleteSSHUpstreamRequest{Connection: ref, RouteToken: token, LeaseToken: l.LeaseToken, Outcome: pb.SSHUpstreamOutcome_SSH_UPSTREAM_OUTCOME_SSH_READY})
	if err == nil && r.GetAccepted() {
		t.Fatal("removed inventory endpoint became an established session")
	}
}

// TestControlUnavailableTransportIsBounded keeps private RPC calls finite.
func TestControlUnavailableTransportIsBounded(t *testing.T) {
	f := newControlFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	_, err := f.client.BeginSSHUpstreamRoute(ctx, &pb.BeginSSHUpstreamRouteRequest{Connection: &pb.SSHUpstreamConnection{Listener: pb.SSHBanListener_SSH_BAN_LISTENER_MAIN, ConnectionId: "unknown", RemoteAddr: "127.0.0.1:2000", ControllerGeneration: "forged"}})
	if err == nil {
		t.Fatal("unregistered connection crossed the private contract")
	}
}
