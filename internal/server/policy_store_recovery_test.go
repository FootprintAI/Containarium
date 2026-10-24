//go:build !containarium_client

package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/footprintai/containarium/internal/guardrailpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #2483: with Postgres configured but unreachable at startup, both policy
// stores start fail-closed. The recovery loop retries the durable-store
// install every 5 s, doubling to a 60 s cap, one log line per interval, and
// swaps the Postgres store in when it succeeds. It never installs an
// in-memory store.

// retryClock hands the loop an already-fired timer and records each wait.
// stopAfter > 0 cancels the run on that wait, so the loop ends there.
type retryClock struct {
	mu        sync.Mutex
	waits     []time.Duration
	stopAfter int
	cancel    context.CancelFunc
}

func (c *retryClock) after(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.waits = append(c.waits, d)
	if c.stopAfter > 0 && len(c.waits) >= c.stopAfter {
		c.cancel()
		return make(chan time.Time) // never fires; ctx.Done wins
	}
	ch := make(chan time.Time, 1)
	ch <- time.Time{}
	return ch
}

func (c *retryClock) recorded() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.waits...)
}

type retryLogSink struct {
	mu    sync.Mutex
	lines []string
}

func (l *retryLogSink) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *retryLogSink) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.lines...)
}

// Durable stand-ins for the Postgres stores: distinct types, so the
// in-memory guard does not mistake them for the in-memory stores.
type fakeDurableGuardrailStore struct{ *guardrailpolicy.MemoryStore }

type fakeDurableCodeEgressStore struct {
	*MemCodingToolEgressPolicyStore
}

type recoveryFixture struct {
	gp     *GuardrailPolicyServer
	ce     *CodingToolEgressPolicyServer
	health *health.Server
	clock  *retryClock
	logs   *retryLogSink
	r      *policyStoreRecovery
	ctx    context.Context
}

func newRecoveryFixture(t *testing.T) *recoveryFixture {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	f := &recoveryFixture{
		gp:     NewGuardrailPolicyServer(guardrailPolicyStartupStore(true, nil)),
		ce:     startupServer(t),
		health: health.NewServer(),
		clock:  &retryClock{cancel: cancel},
		logs:   &retryLogSink{},
		ctx:    ctx,
	}
	f.r = newPolicyStoreRecovery(f.gp, f.ce, f.health, "postgres://unused")
	f.r.after = f.clock.after
	f.r.logf = f.logs.logf
	f.r.connect = func(context.Context) (*pgxpool.Pool, error) {
		return nil, errors.New("dial tcp: connection refused")
	}
	return f
}

func (f *recoveryFixture) status(t *testing.T, svc string) healthpb.HealthCheckResponse_ServingStatus {
	t.Helper()
	resp, err := f.health.Check(context.Background(), &healthpb.HealthCheckRequest{Service: svc})
	if err != nil {
		t.Fatalf("health.Check(%s): %v", svc, err)
	}
	return resp.GetStatus()
}

func (f *recoveryFixture) assertFailClosed(t *testing.T) {
	t.Helper()
	if f.gp.Durable() || f.ce.Durable() {
		t.Fatalf("Durable() guardrail=%v egress=%v, want both false", f.gp.Durable(), f.ce.Durable())
	}
	if _, err := f.gp.GetGuardrailPolicy(gpUserCtx(), &pb.GetGuardrailPolicyRequest{}); codeOf(err) != codes.Internal {
		t.Errorf("guardrail Get = %v, want fail-closed Internal", err)
	}
	if _, err := f.ce.GetCodingToolEgressPolicy(ceAdminCtx(), &pb.GetCodingToolEgressPolicyRequest{Tenant: "alice"}); codeOf(err) != codes.Unavailable {
		t.Errorf("egress Get = %v, want UNAVAILABLE", err)
	}
	for _, svc := range []string{pb.GuardrailPolicyService_ServiceDesc.ServiceName, pb.CodingToolEgressPolicyService_ServiceDesc.ServiceName} {
		if got := f.status(t, svc); got != healthpb.HealthCheckResponse_NOT_SERVING {
			t.Errorf("health(%s) = %v, want NOT_SERVING", svc, got)
		}
	}
}

func TestPolicyStoreRecovery_BackoffDoublesToCapWithOneLogPerInterval(t *testing.T) {
	f := newRecoveryFixture(t)
	f.clock.stopAfter = 7
	f.r.Run(f.ctx, nil)

	want := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second, 60 * time.Second, 60 * time.Second, 60 * time.Second}
	got := f.clock.recorded()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("waits = %v, want %v", got, want)
	}
	// Six attempts ran (the seventh wait was cancelled): one line each.
	logs := f.logs.all()
	if len(logs) != 6 {
		t.Fatalf("log lines = %d, want 6 (one per interval):\n%s", len(logs), strings.Join(logs, "\n"))
	}
	if !strings.Contains(logs[0], "connection refused") || !strings.Contains(logs[0], "10s") {
		t.Errorf("first log line = %q, want the error and the next interval (10s)", logs[0])
	}
	f.assertFailClosed(t)
}

func TestPolicyStoreRecovery_NeverInstallsInMemoryStore(t *testing.T) {
	f := newRecoveryFixture(t)
	f.clock.stopAfter = 4
	f.r.connect = func(context.Context) (*pgxpool.Pool, error) { return new(pgxpool.Pool), nil }
	// Openers that (wrongly) hand back the in-memory stores: the loop must
	// refuse them rather than swap in an empty store that answers "no
	// policy" / "unrestricted".
	f.r.openGuardrail = func(context.Context, *pgxpool.Pool) (guardrailpolicy.Store, error) {
		return guardrailpolicy.NewMemoryStore(), nil
	}
	f.r.openEgress = func(context.Context, *pgxpool.Pool) (CodingToolEgressPolicyStore, error) {
		return NewMemCodingToolEgressPolicyStore(), nil
	}
	f.r.Run(f.ctx, nil)

	if n := len(f.clock.recorded()); n != 4 {
		t.Fatalf("waits = %d, want 4 (the loop keeps retrying)", n)
	}
	f.assertFailClosed(t)
	if logs := f.logs.all(); len(logs) == 0 || !strings.Contains(logs[0], "in-memory") {
		t.Errorf("logs = %q, want the in-memory store refusal named", logs)
	}
}

func TestPolicyStoreRecovery_InstallsOnFirstAttemptAfterPostgresReturns(t *testing.T) {
	f := newRecoveryFixture(t)
	attempts := 0
	f.r.connect = func(context.Context) (*pgxpool.Pool, error) {
		attempts++
		if attempts < 3 {
			return nil, errors.New("dial tcp: connection refused")
		}
		return new(pgxpool.Pool), nil
	}
	f.r.openGuardrail = func(context.Context, *pgxpool.Pool) (guardrailpolicy.Store, error) {
		return fakeDurableGuardrailStore{guardrailpolicy.NewMemoryStore()}, nil
	}
	f.r.openEgress = func(context.Context, *pgxpool.Pool) (CodingToolEgressPolicyStore, error) {
		return fakeDurableCodeEgressStore{NewMemCodingToolEgressPolicyStore()}, nil
	}
	done := make(chan struct{})
	go func() { f.r.Run(f.ctx, nil); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after both stores were installed")
	}

	if n := len(f.clock.recorded()); n != 3 {
		t.Fatalf("waits = %d, want 3 (installed on the first attempt after Postgres returned)", n)
	}
	if !f.gp.Durable() || !f.ce.Durable() {
		t.Fatalf("Durable() guardrail=%v egress=%v, want both true", f.gp.Durable(), f.ce.Durable())
	}
	for _, svc := range []string{pb.GuardrailPolicyService_ServiceDesc.ServiceName, pb.CodingToolEgressPolicyService_ServiceDesc.ServiceName} {
		if got := f.status(t, svc); got != healthpb.HealthCheckResponse_SERVING {
			t.Errorf("health(%s) = %v, want SERVING", svc, got)
		}
	}
	if _, err := f.ce.GetCodingToolEgressPolicy(ceAdminCtx(), &pb.GetCodingToolEgressPolicyRequest{Tenant: "alice"}); err != nil {
		t.Errorf("egress Get after recovery = %v", err)
	}
}

// One store installing does not reinstall it while the other keeps
// retrying, and readiness is reported per service.
func TestPolicyStoreRecovery_PerStoreProgress(t *testing.T) {
	f := newRecoveryFixture(t)
	f.clock.stopAfter = 3
	f.r.connect = func(context.Context) (*pgxpool.Pool, error) { return new(pgxpool.Pool), nil }
	guardrailOpens := 0
	f.r.openGuardrail = func(context.Context, *pgxpool.Pool) (guardrailpolicy.Store, error) {
		guardrailOpens++
		return fakeDurableGuardrailStore{guardrailpolicy.NewMemoryStore()}, nil
	}
	f.r.openEgress = func(context.Context, *pgxpool.Pool) (CodingToolEgressPolicyStore, error) {
		return nil, errors.New("create table: permission denied")
	}
	f.r.Run(f.ctx, nil)

	if guardrailOpens != 1 {
		t.Errorf("guardrail opened %d times, want 1", guardrailOpens)
	}
	if got := f.status(t, pb.GuardrailPolicyService_ServiceDesc.ServiceName); got != healthpb.HealthCheckResponse_SERVING {
		t.Errorf("guardrail health = %v, want SERVING", got)
	}
	if got := f.status(t, pb.CodingToolEgressPolicyService_ServiceDesc.ServiceName); got != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Errorf("egress health = %v, want NOT_SERVING", got)
	}
}

// With no Postgres configured (or both stores installed at startup) there is
// nothing to retry: both report SERVING and Run returns without waiting.
func TestPolicyStoreRecovery_NothingToRecover(t *testing.T) {
	f := newRecoveryFixture(t)
	f.gp = NewGuardrailPolicyServer(guardrailPolicyStartupStore(false, nil))
	f.ce, _ = newTestCodeEgressServer()
	f.r = newPolicyStoreRecovery(f.gp, f.ce, f.health, "")
	f.r.after = f.clock.after
	f.r.logf = f.logs.logf
	f.r.Run(f.ctx, nil)
	if n := len(f.clock.recorded()); n != 0 {
		t.Fatalf("waits = %d, want 0", n)
	}
	for _, svc := range []string{pb.GuardrailPolicyService_ServiceDesc.ServiceName, pb.CodingToolEgressPolicyService_ServiceDesc.ServiceName} {
		if got := f.status(t, svc); got != healthpb.HealthCheckResponse_SERVING {
			t.Errorf("health(%s) = %v, want SERVING", svc, got)
		}
	}
}
