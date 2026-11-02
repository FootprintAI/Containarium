//go:build !containarium_client

package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/secrets"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3327: the secrets store family on the late-install helper (#3326). With
// Postgres down at startup the secret RPCs answer UNAVAILABLE and the
// `containarium.secrets` readiness entry is NOT_SERVING; once Postgres
// answers the store installs in the running daemon, readiness turns SERVING
// and the RPCs work, with no restart. The late install runs the same
// fail-closed checks as boot: CONTAINARIUM_REQUIRE_ENVELOPE without a KMS
// backend refuses, and the store stays nil.

const secretsRecoveryTestUser = "secrets-recovery-test-user"

// assertSecretRPCsUnavailable calls every secret RPC that depends on the
// store, as a caller allowed to make it, and wants UNAVAILABLE from each.
func assertSecretRPCsUnavailable(t *testing.T, cs *ContainerServer) {
	t.Helper()
	write := kmsKeyTestCtx(secretsRecoveryTestUser, "admin", "secrets:write")
	read := kmsKeyTestCtx(secretsRecoveryTestUser, "admin", "secrets:read")
	u := secretsRecoveryTestUser
	calls := map[string]func() error{
		"SetSecret": func() error {
			_, err := cs.SetSecret(write, &pb.SetSecretRequest{Username: u, Name: "API_KEY", Value: "v"})
			return err
		},
		"GetSecret": func() error {
			_, err := cs.GetSecret(read, &pb.GetSecretRequest{Username: u, Name: "API_KEY"})
			return err
		},
		"ListSecrets": func() error {
			_, err := cs.ListSecrets(read, &pb.ListSecretsRequest{Username: u})
			return err
		},
		"DeleteSecret": func() error {
			_, err := cs.DeleteSecret(write, &pb.DeleteSecretRequest{Username: u, Name: "API_KEY"})
			return err
		},
		"RefreshSecrets": func() error {
			_, err := cs.RefreshSecrets(write, &pb.RefreshSecretsRequest{Username: u})
			return err
		},
		"SetTenantKMSKey": func() error {
			_, err := cs.SetTenantKMSKey(write, &pb.SetTenantKMSKeyRequest{Username: u})
			return err
		},
	}
	for name, call := range calls {
		if code := status.Code(call()); code != codes.Unavailable {
			t.Errorf("%s with no secrets store = %v, want Unavailable", name, code)
		}
	}
}

// AC1 + the install half of AC2, without a database: the family is
// NOT_SERVING and every secret RPC answers UNAVAILABLE while Postgres is
// down; the loop installs the store once Postgres answers, readiness turns
// SERVING, and the components wired at construction (notify, the model
// gateway's key verbs, backups) see the store through the live accessor.
// Readers run while the store is swapped in, so -race catches a raw field.
func TestSecretsRecovery_DegradedStartThenInstalledInProcess(t *testing.T) {
	f := newStoreRecoveryFixture(t, &fakePostgres{downFor: 2})
	cs := &ContainerServer{}
	durable := &secrets.Store{}
	var mu sync.Mutex
	var opened []*pgxpool.Pool
	f.r.Register(secretsStoreFamily(cs, func(_ context.Context, pool *pgxpool.Pool) (*secrets.Store, error) {
		mu.Lock()
		defer mu.Unlock()
		opened = append(opened, pool)
		return durable, nil
	}))

	// Wired at construction, as NewDualServer does, before the store exists.
	notifySrv := NewNotifyServer(nil, nil, nil, "", nil)
	notifySrv.secretsSource = cs.notifySecrets
	gatewaySrv := NewModelGatewayServer(nil, nil, nil, nil, "", 0)
	gatewaySrv.keysSource = func() GatewayKeyStore { return GatewayKeyStoreOf(cs) }

	if got := f.status(t, secretsStoreService); got != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("secrets readiness before recovery = %v, want NOT_SERVING", got)
	}
	assertSecretRPCsUnavailable(t, cs)
	if notifySrv.secretStore() != nil || gatewaySrv.keyStore() != nil || backupSecretsReader(cs) != nil {
		t.Fatal("a component sees a secrets store before one was installed")
	}
	if code := status.Code(func() error {
		_, err := gatewaySrv.SetTenantProviderKey(kmsKeyTestCtx("op", "admin", "gateway:admin"), &pb.SetTenantProviderKeyRequest{KeyOwner: "user:alice", ApiKey: "k"})
		return err
	}()); code != codes.Unavailable {
		t.Fatalf("SetTenantProviderKey with no secrets store = %v, want Unavailable", code)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = cs.loadSecretsStore()
				_ = backupSecretsReader(cs)
				_ = notifySrv.secretStore()
				_ = gatewaySrv.keyStore()
			}
		}()
	}
	f.runToCompletion(t, nil)
	close(stop)
	wg.Wait()

	if got := f.status(t, secretsStoreService); got != healthpb.HealthCheckResponse_SERVING {
		t.Errorf("secrets readiness after recovery = %v, want SERVING", got)
	}
	if got := cs.loadSecretsStore(); got != durable {
		t.Errorf("store after recovery = %p, want the installed store %p", got, durable)
	}
	mu.Lock()
	if len(opened) != 1 || opened[0] == nil {
		t.Errorf("store opened %d times over %v, want once over the shared pool", len(opened), opened)
	}
	mu.Unlock()
	if notifySrv.secretStore() == nil {
		t.Error("notify service still has no secrets store after the late install")
	}
	if gatewaySrv.keyStore() == nil {
		t.Error("model-gateway key verbs still have no secrets store after the late install")
	}
	if backupSecretsReader(cs) == nil {
		t.Error("backups still have no secrets store after the late install")
	}
	if f.r.pending() {
		t.Error("secrets family still pending after it installed")
	}
}

// The family's install leaves the stand-in in place when opening fails, so
// the RPCs keep answering UNAVAILABLE and the loop tries again.
func TestSecretsRecovery_FailedOpenKeepsStoreNil(t *testing.T) {
	cs := &ContainerServer{}
	fam := secretsStoreFamily(cs, func(context.Context, *pgxpool.Pool) (*secrets.Store, error) {
		return nil, errors.New("create table: boom")
	})
	if fam.Service != secretsStoreService || fam.Display == "" {
		t.Fatalf("family = %q / %q, want service %q with a display name", fam.Service, fam.Display, secretsStoreService)
	}
	if err := fam.Install(context.Background(), new(pgxpool.Pool)); err == nil {
		t.Fatal("Install returned nil although opening the store failed")
	}
	if cs.loadSecretsStore() != nil {
		t.Fatal("a failed install swapped a store in")
	}
	assertSecretRPCsUnavailable(t, cs)
}

// AC3: CONTAINARIUM_REQUIRE_ENVELOPE with no KMS backend. Postgres answers,
// but the late install refuses exactly as boot does: the store stays nil,
// every RPC keeps answering UNAVAILABLE, readiness stays NOT_SERVING, and
// the store is never opened over the pool. The KMS status that was blank
// while degraded is set by the attempt, and the master key is created at
// the same path boot uses.
func TestSecretsRecovery_RequireEnvelopeWithoutKMSRefusesLateInstall(t *testing.T) {
	t.Setenv("CONTAINARIUM_REQUIRE_ENVELOPE", "true")
	t.Setenv("CONTAINARIUM_KMS_BACKEND", "none")
	keyPath := filepath.Join(t.TempDir(), "secrets.key")

	f := newStoreRecoveryFixture(t, &fakePostgres{})
	f.clock.stopAfter = 4 // three attempts, then the test ends the loop
	cs := &ContainerServer{}
	kms := NewKmsServer(cs)
	f.r.Register(secretsStoreFamily(cs, func(ctx context.Context, pool *pgxpool.Pool) (*secrets.Store, error) {
		return openSecretsStore(ctx, pool, cs, keyPath)
	}))

	st, err := kms.GetKMSStatus(kmsAdminCtx(), &pb.GetKMSStatusRequest{})
	if err != nil {
		t.Fatalf("GetKMSStatus: %v", err)
	}
	if st.RequireEnvelope {
		t.Fatal("KMS status reports the envelope gate before any install attempt; the test setup is wrong")
	}

	f.r.Run(f.ctx, nil) // a zero pool: opening a store over it would fail loudly

	if cs.loadSecretsStore() != nil {
		t.Fatal("late install wired a secrets store with REQUIRE_ENVELOPE set and no KMS")
	}
	assertSecretRPCsUnavailable(t, cs)
	if got := f.status(t, secretsStoreService); got != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Errorf("secrets readiness after a refused install = %v, want NOT_SERVING", got)
	}
	if !f.r.pending() {
		t.Error("secrets family is not pending after a refused install")
	}
	var refused bool
	for _, l := range f.logs.all() {
		if strings.Contains(l, secretsStoreService) && strings.Contains(l, "CONTAINARIUM_REQUIRE_ENVELOPE") {
			refused = true
		}
	}
	if !refused {
		t.Errorf("no log line names the refusal; logs:\n%s", strings.Join(f.logs.all(), "\n"))
	}

	st, err = kms.GetKMSStatus(kmsAdminCtx(), &pb.GetKMSStatusRequest{})
	if err != nil {
		t.Fatalf("GetKMSStatus: %v", err)
	}
	if !st.RequireEnvelope || st.KmsConfigured || st.Backend != "none" {
		t.Errorf("KMS status after the attempt = %+v, want backend none, not configured, envelope required", st)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Errorf("master key not created at the boot path: %v", err)
	}
}

// AC2 against a real Postgres: down for two attempts, then up. The real
// boot open path (master key, KMS selection, the envelope gate, NewStore)
// runs over the helper's shared pool, and a set/get round trip through the
// RPCs works with no restart.
func TestSecretsRecovery_LateInstallRoundTrip(t *testing.T) {
	dsn := os.Getenv("CONTAINARIUM_TEST_DSN")
	if dsn == "" {
		t.Skip("set CONTAINARIUM_TEST_DSN to run this against Postgres")
	}
	t.Setenv("CONTAINARIUM_REQUIRE_ENVELOPE", "")
	t.Setenv("CONTAINARIUM_KMS_BACKEND", "inproc")
	keyPath := filepath.Join(t.TempDir(), "secrets.key")

	f := newStoreRecoveryFixture(t, &fakePostgres{})
	var mu sync.Mutex
	dials := 0
	f.r.connect = func(ctx context.Context) (*pgxpool.Pool, error) {
		mu.Lock()
		defer mu.Unlock()
		dials++
		if dials <= 2 {
			return nil, errors.New("dial tcp: connection refused")
		}
		pool, err := pgxpool.New(ctx, dsn)
		if err == nil {
			t.Cleanup(pool.Close)
		}
		return pool, err
	}
	cs := &ContainerServer{}
	f.r.Register(secretsStoreFamily(cs, func(ctx context.Context, pool *pgxpool.Pool) (*secrets.Store, error) {
		return openSecretsStore(ctx, pool, cs, keyPath)
	}))
	assertSecretRPCsUnavailable(t, cs)

	f.runToCompletion(t, nil)

	if got := f.status(t, secretsStoreService); got != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("secrets readiness after Postgres answered = %v, want SERVING", got)
	}
	const name = "LATE_INSTALL_ROUND_TRIP"
	write := kmsKeyTestCtx(secretsRecoveryTestUser, "admin", "secrets:write")
	read := kmsKeyTestCtx(secretsRecoveryTestUser, "admin", "secrets:read")
	t.Cleanup(func() {
		_, _ = cs.DeleteSecret(write, &pb.DeleteSecretRequest{Username: secretsRecoveryTestUser, Name: name})
	})
	if _, err := cs.SetSecret(write, &pb.SetSecretRequest{Username: secretsRecoveryTestUser, Name: name, Value: "late-value"}); err != nil {
		t.Fatalf("SetSecret after the late install: %v", err)
	}
	got, err := cs.GetSecret(read, &pb.GetSecretRequest{Username: secretsRecoveryTestUser, Name: name})
	if err != nil {
		t.Fatalf("GetSecret after the late install: %v", err)
	}
	if got.Value != "late-value" {
		t.Errorf("GetSecret value = %q, want the value just set", got.Value)
	}
	st, err := NewKmsServer(cs).GetKMSStatus(kmsAdminCtx(), &pb.GetKMSStatusRequest{})
	if err != nil {
		t.Fatalf("GetKMSStatus: %v", err)
	}
	if st.Backend != "inproc" || !st.KmsConfigured {
		t.Errorf("KMS status after the late install = %+v, want inproc, configured", st)
	}
}
