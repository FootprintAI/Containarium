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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/durationpb"
)

// controlClock is synchronized because generated clients invoke another goroutine.
type controlClock struct {
	mu sync.Mutex
	t  time.Time
}

// TestControlExpiredLeaseStillChecksAuthority revalidates delayed ready reports.
func TestControlExpiredLeaseStillChecksAuthority(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		anonymous, forged, retained bool
	}{
		{name: "anonymous moved", anonymous: true}, {name: "main removed"},
		{name: "forged anonymous token", anonymous: true, forged: true},
		{name: "current anonymous authority", anonymous: true, retained: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newControlFixture(t)
			listener := pb.SSHBanListener_SSH_BAN_LISTENER_MAIN
			if tc.anonymous {
				listener = pb.SSHBanListener_SSH_BAN_LISTENER_ANONYMOUS
			}
			ref := f.open(f.client, listener, "delayed-ready")
			if tc.anonymous {
				if _, err := f.client.RegisterSSHAnonymousRoute(t.Context(), &pb.RegisterSSHAnonymousRouteRequest{Connection: ref, BoxName: "stable-box", Endpoint: "127.0.0.1:22"}); err != nil {
					t.Fatal(err)
				}
			}
			token := f.route(f.client, ref)
			lease := f.acquire(f.client, ref, token, "127.0.0.1:22")
			f.clock.advance(6 * time.Second)
			other := f.open(f.client, listener, "after-deadline") // reap the old lease
			if tc.anonymous && !tc.retained {
				if _, err := f.client.RegisterSSHAnonymousRoute(t.Context(), &pb.RegisterSSHAnonymousRouteRequest{Connection: other, BoxName: "stable-box", Endpoint: "127.0.0.1:2222"}); err != nil {
					t.Fatal(err)
				}
			} else if !tc.retained {
				f.server.mu.Lock()
				f.server.cfg.Resolve = func(string) (string, error) { return "", fmt.Errorf("removed route") }
				f.server.mu.Unlock()
			}
			if tc.forged {
				token = "forged-route"
			}
			r, err := f.client.CompleteSSHUpstream(t.Context(), &pb.CompleteSSHUpstreamRequest{Connection: ref, RouteToken: token, LeaseToken: lease.LeaseToken, Outcome: pb.SSHUpstreamOutcome_SSH_UPSTREAM_OUTCOME_SSH_READY})
			if tc.forged || tc.retained {
				if err != nil || r.GetAccepted() {
					t.Fatalf("ordinary stale request changed authority handling: %v", err)
				}
			} else if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("missing lease bypassed route revocation: %v", err)
			}
		})
	}
}

// TestControlRevocationSurvivesStorageFault keeps explicit authority denial typed.
func TestControlRevocationSurvivesStorageFault(t *testing.T) {
	f := newControlFixture(t)
	ref := f.open(f.client, pb.SSHBanListener_SSH_BAN_LISTENER_MAIN, "revoked-during-fault")
	token := f.route(f.client, ref)
	lease := f.acquire(f.client, ref, token, "127.0.0.1:22")
	dir := filepath.Dir(f.cfg.StatePath)
	if err := os.Rename(dir, dir+".offline"); err != nil {
		t.Fatal(err)
	}
	if err := f.server.Recover(); err == nil {
		t.Fatal("missing storage did not fault")
	}
	f.server.mu.Lock()
	f.server.cfg.Resolve = func(string) (string, error) { return "", fmt.Errorf("route removed") }
	f.server.mu.Unlock()
	_, err := f.client.CompleteSSHUpstream(t.Context(), &pb.CompleteSSHUpstreamRequest{Connection: ref, RouteToken: token, LeaseToken: lease.LeaseToken, Outcome: pb.SSHUpstreamOutcome_SSH_UPSTREAM_OUTCOME_SSH_READY})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("revocation hidden behind a storage failure: %v", err)
	}
}

// TestControlActiveRefusalsKeepBackoff never prunes an actively retried outage.
func TestControlActiveRefusalsKeepBackoff(t *testing.T) {
	f := newControlFixture(t)
	for i, delay := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second} {
		ref := f.open(f.client, pb.SSHBanListener_SSH_BAN_LISTENER_MAIN, fmt.Sprint("refusal-", i))
		token := f.route(f.client, ref)
		lease := f.acquire(f.client, ref, token, "127.0.0.1:22")
		if !lease.Admitted {
			t.Fatal("due probe was not admitted")
		}
		f.finish(ref, token, lease, pb.SSHUpstreamOutcome_SSH_UPSTREAM_OUTCOME_TCP_REFUSED)
		_ = f.count(ref, pb.SSHUpstreamFailureKind_SSH_UPSTREAM_FAILURE_KIND_PIPE_CREATE)
		other := f.open(f.client, pb.SSHBanListener_SSH_BAN_LISTENER_MAIN, fmt.Sprint("cooldown-", i))
		denied := f.acquire(f.client, other, f.route(f.client, other), "127.0.0.1:22")
		if denied.Admitted || denied.RetryAt.AsTime().Sub(f.clock.now()) != delay {
			t.Fatalf("retry %d lost exponential delay %s: %v", i, delay, denied)
		}
		_ = f.count(other, pb.SSHUpstreamFailureKind_SSH_UPSTREAM_FAILURE_KIND_PIPE_CREATE)
		f.clock.advance(delay)
	}
}

// TestControlFaultKeepsVerifiedSourceAccounting isolates storage from client policy.
func TestControlFaultKeepsVerifiedSourceAccounting(t *testing.T) {
	f := newControlFixture(t)
	client := f.open(f.client, pb.SSHBanListener_SSH_BAN_LISTENER_MAIN, "bad-client")
	_ = f.route(f.client, client)
	backend := f.open(f.client, pb.SSHBanListener_SSH_BAN_LISTENER_MAIN, "backend-failure")
	bt := f.route(f.client, backend)
	bl := f.acquire(f.client, backend, bt, "127.0.0.1:22")
	cause := f.open(f.client, pb.SSHBanListener_SSH_BAN_LISTENER_MAIN, "disk-fault")
	ct := f.route(f.client, cause)
	dir := filepath.Dir(f.cfg.StatePath)
	if err := os.Rename(dir, dir+".offline"); err != nil {
		t.Fatal(err)
	}
	if f.acquire(f.client, cause, ct, "127.0.0.1:22").Admitted {
		t.Fatal("unsaved admission")
	}
	if !f.count(client, pb.SSHUpstreamFailureKind_SSH_UPSTREAM_FAILURE_KIND_AUTH) {
		t.Fatal("storage fault exempted a genuine client denial")
	}
	_, _ = f.client.CompleteSSHUpstream(t.Context(), &pb.CompleteSSHUpstreamRequest{Connection: backend, RouteToken: bt, LeaseToken: bl.LeaseToken, Outcome: pb.SSHUpstreamOutcome_SSH_UPSTREAM_OUTCOME_PROXY_AUTH_REJECTED})
	if f.count(backend, pb.SSHUpstreamFailureKind_SSH_UPSTREAM_FAILURE_KIND_AUTH) {
		t.Fatal("confirmed backend outcome punished the client during storage fault")
	}
	if f.count(cause, pb.SSHUpstreamFailureKind_SSH_UPSTREAM_FAILURE_KIND_PIPE_CREATE) {
		t.Fatal("storage refusal punished the source")
	}
}

// TestControlStaleFailureHasNoExemption requires current provenance for a skip.
func TestControlStaleFailureHasNoExemption(t *testing.T) {
	f := newControlFixture(t)
	ref := f.open(f.client, pb.SSHBanListener_SSH_BAN_LISTENER_MAIN, "stale-source")
	ref.ControllerGeneration = "replaced-controller"
	if !f.count(ref, pb.SSHUpstreamFailureKind_SSH_UPSTREAM_FAILURE_KIND_AUTH) {
		t.Fatal("stale generation granted a source exemption")
	}
}

// TestControlAdmissionReasonIsTyped keeps denial decisions out of free text.
func TestControlAdmissionReasonIsTyped(t *testing.T) {
	field := (&pb.AcquireSSHUpstreamResponse{}).ProtoReflect().Descriptor().Fields().ByName("reason")
	if field.Kind() != protoreflect.EnumKind {
		t.Fatal("admission reason is not a protobuf enum")
	}
}

// TestControlConnectFailureRefundsRisk keeps pure TCP outages out of jail history.
func TestControlConnectFailureRefundsRisk(t *testing.T) {
	f := newControlFixture(t)
	for i := range 4 {
		ref := f.open(f.client, pb.SSHBanListener_SSH_BAN_LISTENER_MAIN, fmt.Sprint("timeout-", i))
		token := f.route(f.client, ref)
		lease := f.acquire(f.client, ref, token, "127.0.0.1:22")
		if !lease.Admitted {
			t.Fatalf("pure connect failure consumed jail risk on attempt %d: %v", i, lease)
		}
		f.finish(ref, token, lease, pb.SSHUpstreamOutcome_SSH_UPSTREAM_OUTCOME_CONNECT_FAILED)
		f.clock.advance(8 * time.Second)
	}
}

// TestControlFaultRecoveryRetainsUncommittedRisk never resets uncertain history.
func TestControlFaultRecoveryRetainsUncommittedRisk(t *testing.T) {
	f := newControlFixture(t)
	ref := f.open(f.client, pb.SSHBanListener_SSH_BAN_LISTENER_MAIN, "fault-retry")
	token := f.route(f.client, ref)
	dir := filepath.Dir(f.cfg.StatePath)
	if err := os.Rename(dir, dir+".offline"); err != nil {
		t.Fatal(err)
	}
	if f.acquire(f.client, ref, token, "127.0.0.1:22").Admitted {
		t.Fatal("unsaved lease admitted")
	}
	if err := os.Rename(dir+".offline", dir); err != nil {
		t.Fatal(err)
	}
	// A subsequent controller-owned durable retry must recover without resetting
	// the unacknowledged lease or permitting a second checkpoint owner.
	err := f.server.Recover()
	if err != nil {
		t.Fatal(err)
	}
	if f.server.Faulted() {
		t.Fatal("successful durable retry left a permanent fault")
	}
	other := f.open(f.client, pb.SSHBanListener_SSH_BAN_LISTENER_MAIN, "after-repair")
	ot := f.route(f.client, other)
	l := f.acquire(f.client, other, ot, "127.0.0.1:22")
	if !l.Admitted {
		t.Fatal("safe unit was unavailable after repair")
	}
	third := f.open(f.client, pb.SSHBanListener_SSH_BAN_LISTENER_MAIN, "risk-retained")
	if f.acquire(f.client, third, f.route(f.client, third), "127.0.0.1:22").Admitted {
		t.Fatal("repair discarded uncertain pending risk")
	}
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

// TestControlAnonymousMovePreservesRisk invalidates old routes without new budget.
func TestControlAnonymousMovePreservesRisk(t *testing.T) {
	f := newControlFixture(t)
	a := f.open(f.client, pb.SSHBanListener_SSH_BAN_LISTENER_ANONYMOUS, "old-anon")
	if _, err := f.client.RegisterSSHAnonymousRoute(t.Context(), &pb.RegisterSSHAnonymousRouteRequest{Connection: a, BoxName: "stable-box", Endpoint: "127.0.0.1:22"}); err != nil {
		t.Fatal(err)
	}
	at := f.route(f.client, a)
	al := f.acquire(f.client, a, at, "127.0.0.1:22")
	b := f.open(f.client, pb.SSHBanListener_SSH_BAN_LISTENER_ANONYMOUS, "moved-anon")
	if _, err := f.client.RegisterSSHAnonymousRoute(t.Context(), &pb.RegisterSSHAnonymousRouteRequest{Connection: b, BoxName: "stable-box", Endpoint: "127.0.0.1:2222"}); err != nil {
		t.Fatal(err)
	}
	result, err := f.client.CompleteSSHUpstream(t.Context(), &pb.CompleteSSHUpstreamRequest{Connection: a, RouteToken: at, LeaseToken: al.LeaseToken, Outcome: pb.SSHUpstreamOutcome_SSH_UPSTREAM_OUTCOME_SSH_READY})
	if err == nil && result.GetAccepted() {
		t.Fatal("old anonymous route became ready after Ensure moved it")
	}
	bt := f.route(f.client, b)
	if !f.acquire(f.client, b, bt, "127.0.0.1:2222").Admitted {
		t.Fatal("one remaining risk unit was lost")
	}
	c := f.open(f.client, pb.SSHBanListener_SSH_BAN_LISTENER_MAIN, "same-main")
	ct := f.route(f.client, c)
	if f.acquire(f.client, c, ct, "127.0.0.1:22").Admitted {
		t.Fatal("moving an anonymous route discarded its earlier risk")
	}
}

// TestControlDurabilityFailureDeniesWithoutSourcePenalty never grants unsaved risk.
func TestControlDurabilityFailureDeniesWithoutSourcePenalty(t *testing.T) {
	f := newControlFixture(t)
	ref := f.open(f.client, pb.SSHBanListener_SSH_BAN_LISTENER_MAIN, "durability")
	token := f.route(f.client, ref)
	dir := filepath.Dir(f.cfg.StatePath)
	if err := os.Rename(dir, dir+".offline"); err != nil {
		t.Fatal(err)
	}
	if f.acquire(f.client, ref, token, "127.0.0.1:22").Admitted {
		t.Fatal("uncommitted risk admitted a backend setup")
	}
	if !f.server.Faulted() {
		t.Fatal("durability failure had no operator health signal")
	}
	if f.count(ref, pb.SSHUpstreamFailureKind_SSH_UPSTREAM_FAILURE_KIND_PIPE_CREATE) {
		t.Fatal("checkpoint outage punished source")
	}
	if err := os.Rename(dir+".offline", dir); err != nil {
		t.Fatal(err)
	}
	if _, err := f.client.BeginSSHUpstreamRoute(t.Context(), &pb.BeginSSHUpstreamRouteRequest{Connection: ref}); err == nil {
		t.Fatal("poisoned controller resumed without restoring durable state")
	}
}

// TestControlRejectsUnregisteredGeneration refuses forged process authority.
func TestControlRejectsUnregisteredGeneration(t *testing.T) {
	f := newControlFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	_, err := f.client.BeginSSHUpstreamRoute(ctx, &pb.BeginSSHUpstreamRouteRequest{Connection: &pb.SSHUpstreamConnection{Listener: pb.SSHBanListener_SSH_BAN_LISTENER_MAIN, ConnectionId: "unknown", RemoteAddr: "127.0.0.1:2000", ControllerGeneration: "forged"}})
	if err == nil {
		t.Fatal("unregistered connection crossed the private contract")
	}
}

// TestControlIdleSourceCannotFillBothListeners reserves capacity for other sources.
func TestControlIdleSourceCannotFillBothListeners(t *testing.T) {
	f := newControlFixture(t)
	for i := range int(f.cfg.Policy.MaxConnections) + 2 {
		_, _ = f.client.OpenSSHUpstreamConnection(t.Context(), &pb.OpenSSHUpstreamConnectionRequest{Connection: &pb.SSHUpstreamConnection{Listener: pb.SSHBanListener_SSH_BAN_LISTENER_MAIN, ConnectionId: fmt.Sprint("idle-", i), RemoteAddr: fmt.Sprintf("192.0.2.1:%d", 10000+i)}})
	}
	_, err := f.client.OpenSSHUpstreamConnection(t.Context(), &pb.OpenSSHUpstreamConnectionRequest{Connection: &pb.SSHUpstreamConnection{Listener: pb.SSHBanListener_SSH_BAN_LISTENER_ANONYMOUS, ConnectionId: "legitimate", RemoteAddr: "192.0.2.2:20000"}})
	if err != nil {
		t.Fatalf("one idle source locked both listeners: %v", err)
	}
}

// TestControlUnavailableTransportIsBounded calls a genuinely absent private socket.
func TestControlUnavailableTransportIsBounded(t *testing.T) {
	peer, err := DialPeer(filepath.Join(t.TempDir(), "absent.sock"), pb.SSHBanListener_SSH_BAN_LISTENER_MAIN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	ctx, cancel := CallContext(t.Context())
	defer cancel()
	started := time.Now()
	_, err = peer.Open(ctx, "unavailable", "127.0.0.2:2222")
	if err == nil || time.Since(started) > 2*time.Second {
		t.Fatalf("unavailable transport was not bounded: %v", err)
	}
}

// TestControlAnonymousAddressReuseRetainsEndpointRisk avoids permanent box aliases.
func TestControlAnonymousAddressReuseRetainsEndpointRisk(t *testing.T) {
	f := newControlFixture(t)
	register := func(box, endpoint string) *pb.SSHUpstreamConnection {
		t.Helper()
		ref := f.open(f.client, pb.SSHBanListener_SSH_BAN_LISTENER_ANONYMOUS, fmt.Sprint(box, f.clock.now().UnixNano(), endpoint))
		if _, err := f.client.RegisterSSHAnonymousRoute(t.Context(), &pb.RegisterSSHAnonymousRouteRequest{Connection: ref, BoxName: box, Endpoint: endpoint}); err != nil {
			t.Fatalf("trusted address reuse was rejected for %s: %v", box, err)
		}
		return ref
	}
	first := register("key-k", "127.0.0.8:22")
	ft := f.route(f.client, first)
	f.finish(first, ft, f.acquire(f.client, first, ft, "127.0.0.8:22"), pb.SSHUpstreamOutcome_SSH_UPSTREAM_OUTCOME_PROXY_AUTH_REJECTED)
	f.clock.advance(8 * time.Second)
	_ = register("key-l", "127.0.0.8:22")
	_ = register("key-m", "127.0.0.9:22")
	moved := register("key-l", "127.0.0.9:22")
	mt := f.route(f.client, moved)
	ml := f.acquire(f.client, moved, mt, "127.0.0.9:22")
	if !ml.Admitted {
		t.Fatal("reused address permanently denied a moved box")
	}
	f.finish(moved, mt, ml, pb.SSHUpstreamOutcome_SSH_UPSTREAM_OUTCOME_SSH_READY)
	// The old physical endpoint still retains its failure; IP reuse cannot refund it.
	old := register("key-new", "127.0.0.8:22")
	ot := f.route(f.client, old)
	if !f.acquire(f.client, old, ot, "127.0.0.8:22").Admitted {
		t.Fatal("remaining safe unit lost")
	}
	last := register("key-last", "127.0.0.8:22")
	if f.acquire(f.client, last, f.route(f.client, last), "127.0.0.8:22").Admitted {
		t.Fatal("address reuse discarded old jail risk")
	}
	for i := range 40 {
		f.clock.advance(6 * time.Minute)
		ref := register(fmt.Sprint("churn-", i), fmt.Sprintf("127.0.1.%d:22", i+1))
		token := f.route(f.client, ref)
		lease := f.acquire(f.client, ref, token, fmt.Sprintf("127.0.1.%d:22", i+1))
		if !lease.Admitted {
			t.Fatalf("expired anonymous inventory exhausted capacity at %d", i)
		}
		f.finish(ref, token, lease, pb.SSHUpstreamOutcome_SSH_UPSTREAM_OUTCOME_SSH_READY)
	}
}
