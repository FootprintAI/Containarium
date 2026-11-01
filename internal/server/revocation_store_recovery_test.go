//go:build !containarium_client

package server

import (
	"context"
	"errors"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3328: the JWT revocation list as a late-install family on the #3326
// helper. TokensService is registered whether or not the store exists and
// answers UNAVAILABLE until it does; while it is absent tokens are still
// validated (#3335 Q8) and the degraded state is in readiness and the log;
// once Postgres answers the store installs with no restart and a token
// revoked before the window is rejected again.

const revocationTestSecret = "test-secret-for-revocation-recovery-0123456789"

type revocationRecoveryFixture struct {
	*storeRecoveryFixture
	tm      *auth.TokenManager
	svc     *revocationTokensService
	skills  *AgentSkillServer
	store   *fakeRevocationStore
	opens   int
	openErr error
}

func newRevocationRecoveryFixture(t *testing.T, pg *fakePostgres) *revocationRecoveryFixture {
	t.Helper()
	tm, err := auth.NewTokenManager(revocationTestSecret, "containarium-test")
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	f := &revocationRecoveryFixture{
		storeRecoveryFixture: newStoreRecoveryFixture(t, pg),
		tm:                   tm,
		svc:                  newRevocationTokensService(),
		skills:               &AgentSkillServer{},
		store:                newFakeRevocationStore(),
	}
	return f
}

func (f *revocationRecoveryFixture) consumers() revocationConsumers {
	return revocationConsumers{tokens: f.tm, service: f.svc, skillRuns: f.skills}
}

func (f *revocationRecoveryFixture) open(context.Context, *pgxpool.Pool) (auth.RevocationStore, error) {
	f.opens++
	if f.openErr != nil {
		err := f.openErr
		f.openErr = nil
		return nil, err
	}
	return f.store, nil
}

func adminTokensCtx() context.Context {
	return auth.ContextWithTestSubjectScopes(context.Background(),
		"ops", []string{auth.RoleAdmin}, []string{auth.ScopeTokensRead, auth.ScopeTokensWrite})
}

// callEveryTokensRPC invokes every method of TokensService through its
// generated handler with an empty request, so an RPC added to the proto
// later is covered without editing this test.
func callEveryTokensRPC(srv pb.TokensServiceServer) map[string]error {
	out := map[string]error{}
	for _, m := range pb.TokensService_ServiceDesc.Methods {
		_, err := m.Handler(srv, adminTokensCtx(), func(any) error { return nil }, nil)
		out[m.MethodName] = err
	}
	return out
}

// AC: Postgres down at start => readiness NOT_SERVING and every TokensService
// RPC answers UNAVAILABLE; a token validates and the degraded state is
// logged. Postgres answers => the store installs with no restart, readiness
// is SERVING, a token revoked earlier is rejected, and TokensService serves.
func TestRevocationRecovery_DegradedStartThenInstallsWithoutRestart(t *testing.T) {
	logs := captureStdLog(t)
	f := newRevocationRecoveryFixture(t, &fakePostgres{downFor: 1})

	tok, err := f.tm.GenerateToken("alice", []string{"user"}, time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	claims, err := f.tm.ValidateToken(tok)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	// Revoked in Postgres before the outage: the store that installs late
	// already holds the row.
	_ = f.store.Revoke(context.Background(), claims.ID, claims.ExpiresAt.Time, "revoked before the window")

	registerRevocationLateInstall(f.r, f.consumers(), f.open)

	if got := f.status(t, revocationStoreService); got != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("readiness %s before recovery = %v, want NOT_SERVING", revocationStoreService, got)
	}
	if _, ok := f.readiness.entries[revocationStoreService]; !ok {
		t.Fatalf("%s not published to the readiness registry", revocationStoreService)
	}
	for name, err := range callEveryTokensRPC(f.svc) {
		if status.Code(err) != codes.Unavailable {
			t.Errorf("TokensService.%s before recovery: code %v (%v), want UNAVAILABLE", name, status.Code(err), err)
		}
	}

	// Q8: while the store is absent the token is validated, not refused...
	for i := 0; i < 3; i++ {
		if _, err := f.tm.ValidateToken(tok); err != nil {
			t.Fatalf("ValidateToken while the store is absent: %v (want validated, #3335 Q8)", err)
		}
	}
	// ...and the degraded state is surfaced, once, not per request.
	if !logsContain(f.logs, "tokens are validated WITHOUT the revocation check") {
		t.Errorf("no degraded-state line from the family registration; logs: %q", f.logs.all())
	}
	if n := logs.count("tokens are validated WITHOUT the revocation check"); n != 1 {
		t.Errorf("token-manager degraded-state lines = %d, want 1 (once per state change)", n)
	}
	if f.skills.loadRevocations() != nil {
		t.Fatal("skill runs hold a revocation store before it installed")
	}

	f.runToCompletion(t, nil)

	if got := f.status(t, revocationStoreService); got != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("readiness %s after recovery = %v, want SERVING", revocationStoreService, got)
	}
	if _, err := f.tm.ValidateToken(tok); err == nil {
		t.Fatal("token revoked before the window was accepted after the store installed; want rejected without a restart")
	}
	resp, err := f.svc.ListRevokedTokens(adminTokensCtx(), &pb.ListRevokedTokensRequest{})
	if err != nil {
		t.Fatalf("ListRevokedTokens after recovery: %v", err)
	}
	if len(resp.GetRevocations()) != 1 {
		t.Fatalf("revocations listed = %d, want 1", len(resp.GetRevocations()))
	}
	// Revoked during the window's aftermath through the RPC: rejected too.
	other, _ := f.tm.GenerateToken("bob", []string{"user"}, time.Hour)
	otherClaims, _ := f.tm.ValidateToken(other)
	if _, err := f.svc.RevokeToken(adminTokensCtx(), &pb.RevokeTokenRequest{Jti: otherClaims.ID}); err != nil {
		t.Fatalf("RevokeToken after recovery: %v", err)
	}
	if _, err := f.tm.ValidateToken(other); err == nil {
		t.Fatal("token revoked through TokensService after recovery was accepted")
	}
	if f.skills.loadRevocations() == nil {
		t.Error("skill runs were not handed the late-installed revocation store")
	}
	if !logsContain(f.logs, "JWT revocation list enabled (installed in-process)") {
		t.Errorf("no install line; logs: %q", f.logs.all())
	}
}

// A failing open leaves the stand-in answering UNAVAILABLE and is retried.
func TestRevocationRecovery_FailedOpenIsRetried(t *testing.T) {
	f := newRevocationRecoveryFixture(t, &fakePostgres{})
	f.openErr = errors.New("create table jwt_revocations: permission denied")
	registerRevocationLateInstall(f.r, f.consumers(), f.open)

	f.runToCompletion(t, nil)

	if f.opens != 2 {
		t.Errorf("open ran %d times, want 2 (one failure, one success)", f.opens)
	}
	if got := f.status(t, revocationStoreService); got != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("readiness after retry = %v, want SERVING", got)
	}
}

// The startup path: Postgres answered, the store is installed at once and
// TokensService serves; the readiness entry is SERVING with nothing pending.
func TestRevocationRecovery_StartupInstall(t *testing.T) {
	f := newRevocationRecoveryFixture(t, &fakePostgres{})
	c := f.consumers()
	c.install(f.store)
	f.r.RegisterInstalled(storeFamily{Service: revocationStoreService, Display: revocationStoreDisplay})

	if f.r.pending() {
		t.Fatal("pending() = true after a startup install")
	}
	if got := f.status(t, revocationStoreService); got != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("readiness = %v, want SERVING", got)
	}
	if _, err := f.svc.ListRevokedTokens(adminTokensCtx(), &pb.ListRevokedTokensRequest{}); err != nil {
		t.Fatalf("ListRevokedTokens: %v", err)
	}
	tok, _ := f.tm.GenerateToken("alice", []string{"user"}, time.Hour)
	claims, _ := f.tm.ValidateToken(tok)
	_ = f.store.Revoke(context.Background(), claims.ID, claims.ExpiresAt.Time, "test")
	if _, err := f.tm.ValidateToken(tok); err == nil {
		t.Fatal("revoked token accepted after a startup install")
	}
}

// The skill-run revocation store is read on run exit while the late install
// may write it: run with -race.
func TestAgentSkillServer_RevocationStoreSwapIsRaceSafe(t *testing.T) {
	s := &AgentSkillServer{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			_ = s.loadRevocations()
			time.Sleep(10 * time.Microsecond)
		}
	}()
	for i := 0; i < 200; i++ {
		s.SetRevocationStore(newFakeRevocationStore())
		time.Sleep(10 * time.Microsecond)
	}
	<-done
	s.SetRevocationStore(nil)
	if s.loadRevocations() != nil {
		t.Fatal("SetRevocationStore(nil) left a non-nil revoker")
	}
}

func logsContain(l *retryLogSink, substr string) bool {
	for _, line := range l.all() {
		if strings.Contains(line, substr) {
			return true
		}
	}
	return false
}

// stdLogCapture is the standard logger's output for the test (the token
// manager logs through it).
type stdLogCapture struct {
	mu sync.Mutex
	b  strings.Builder
}

func (c *stdLogCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.b.Write(p)
}

func (c *stdLogCapture) count(substr string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Count(c.b.String(), substr)
}

func captureStdLog(t *testing.T) *stdLogCapture {
	t.Helper()
	c := &stdLogCapture{}
	prev := log.Writer()
	log.SetOutput(c)
	t.Cleanup(func() { log.SetOutput(prev) })
	return c
}
