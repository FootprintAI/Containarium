//go:build integration

package server

import (
	"context"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	guardrailpolicypg "github.com/footprintai/containarium/internal/guardrailpolicy/pgstore"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #2483 against a real database: the daemon starts with Postgres down, both
// policy APIs fail closed, Postgres comes up, and on the next retry the
// Postgres stores are installed: the RPCs succeed and what they store is in
// the database, not in memory.
//
//	CONTAINARIUM_TEST_DSN=postgres://... go test -tags=integration ./internal/server/ -run PolicyStoreRecovery

// downDSN points at a port nothing listens on, so connecting is a real
// "connection refused".
func downDSN(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return "postgres://containarium:test@" + addr + "/containarium?sslmode=disable&connect_timeout=2"
}

func TestPolicyStoreRecovery_PostgresDownThenUp(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reset := testPool(t)
	freshCodeEgressSchema(t, reset)
	if _, err := reset.Exec(ctx, `DROP TABLE IF EXISTS guardrail_policy`); err != nil {
		t.Fatalf("reset guardrail_policy: %v", err)
	}

	// Startup as NewDualServer leaves it when the pool cannot be reached.
	gp := NewGuardrailPolicyServer(unavailableGuardrailPolicyStore{})
	gp.SetStore(guardrailPolicyStartupStore(true, nil))
	ce := NewCodingToolEgressPolicyServer(NewMemCodingToolEgressPolicyStore())
	ce.SetDurable(false)
	h := health.NewServer()

	var postgresUp atomic.Bool
	down, up := downDSN(t), os.Getenv("CONTAINARIUM_TEST_DSN")
	r := newPolicyStoreRecovery(gp, ce, h, up)
	var connects atomic.Int32
	r.connect = func(context.Context) (*pgxpool.Pool, error) {
		connects.Add(1)
		dsn := down
		if postgresUp.Load() {
			dsn = up
		}
		return connectToPostgres(dsn, 1, 0)
	}
	// Each wait is one retry interval. Bring Postgres "up" during the third.
	waits := make(chan time.Duration, 16)
	r.after = func(d time.Duration) <-chan time.Time {
		waits <- d
		if len(waits) == 3 {
			// Assert fail-closed while Postgres is still down.
			assertPolicyAPIsFailClosed(t, gp, ce, h)
			postgresUp.Store(true)
		}
		ch := make(chan time.Time, 1)
		ch <- time.Time{}
		return ch
	}

	done := make(chan struct{})
	go func() { r.Run(ctx, nil); close(done) }()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("recovery did not install the Postgres stores")
	}
	if n := len(waits); n != 3 {
		t.Fatalf("waited %d intervals, want 3: the stores must be installed on the first attempt after Postgres is up", n)
	}
	if c := connects.Load(); c != 3 {
		t.Fatalf("connect attempts = %d, want 3", c)
	}

	// Readiness clears.
	for _, svc := range []string{pb.GuardrailPolicyService_ServiceDesc.ServiceName, pb.CodingToolEgressPolicyService_ServiceDesc.ServiceName} {
		resp, err := h.Check(ctx, &healthpb.HealthCheckRequest{Service: svc})
		if err != nil || resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
			t.Fatalf("health(%s) = %v, %v; want SERVING", svc, resp.GetStatus(), err)
		}
	}

	// The RPCs succeed, and the stores they write are the durable ones: a
	// fresh pool and store over the same database (a restarted daemon) reads
	// the same policies back.
	setGP, err := gp.SetGuardrailPolicy(gpAdminCtx(), gpRequest(0, gpSigner(1)))
	if err != nil {
		t.Fatalf("guardrail Set after recovery: %v", err)
	}
	if _, err := ce.SetCodingToolEgressPolicy(ceAdminCtx(), setReq("alice", pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE, []string{"192.0.2.0/24"}, nil)); err != nil {
		t.Fatalf("egress Set after recovery: %v", err)
	}

	pool2, err := pgxpool.New(ctx, up)
	if err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	defer pool2.Close()
	gpStore, err := guardrailpolicypg.New(ctx, pool2)
	if err != nil {
		t.Fatalf("guardrail store over a fresh pool: %v", err)
	}
	got, err := gpStore.Get(ctx)
	if err != nil || got.GetRevision() != setGP.GetPolicy().GetRevision() {
		t.Fatalf("guardrail policy in Postgres = rev %d, %v; want rev %d", got.GetRevision(), err, setGP.GetPolicy().GetRevision())
	}
	ceStore, err := NewPostgresCodingToolEgressPolicyStore(ctx, pool2)
	if err != nil {
		t.Fatalf("egress store over a fresh pool: %v", err)
	}
	if p, err := ceStore.Get(ctx, "alice"); err != nil || len(p.GetEgressCidrs()) != 1 {
		t.Fatalf("egress policy in Postgres = %v, %v; want alice's policy", p, err)
	}

	// The deploy gate / model gateway read side follows the swap.
	if p, err := gp.Provider().Get(ctx); err != nil || p.GetRevision() != setGP.GetPolicy().GetRevision() {
		t.Fatalf("Provider().Get after recovery = %v, %v", p, err)
	}
}

func assertPolicyAPIsFailClosed(t *testing.T, gp *GuardrailPolicyServer, ce *CodingToolEgressPolicyServer, h *health.Server) {
	t.Helper()
	if _, err := gp.GetGuardrailPolicy(gpUserCtx(), &pb.GetGuardrailPolicyRequest{}); codeOf(err) != codes.Internal {
		t.Errorf("guardrail Get with Postgres down = %v, want fail-closed Internal", err)
	}
	if _, err := gp.SetGuardrailPolicy(gpAdminCtx(), gpRequest(0, gpSigner(1))); codeOf(err) != codes.Internal {
		t.Errorf("guardrail Set with Postgres down = %v, want fail-closed Internal", err)
	}
	if _, err := ce.GetCodingToolEgressPolicy(ceAdminCtx(), &pb.GetCodingToolEgressPolicyRequest{Tenant: "alice"}); codeOf(err) != codes.Unavailable {
		t.Errorf("egress Get with Postgres down = %v, want UNAVAILABLE", err)
	}
	for _, svc := range []string{pb.GuardrailPolicyService_ServiceDesc.ServiceName, pb.CodingToolEgressPolicyService_ServiceDesc.ServiceName} {
		resp, err := h.Check(context.Background(), &healthpb.HealthCheckRequest{Service: svc})
		if err != nil || resp.GetStatus() != healthpb.HealthCheckResponse_NOT_SERVING {
			t.Errorf("health(%s) with Postgres down = %v, %v; want NOT_SERVING", svc, resp.GetStatus(), err)
		}
	}
}
