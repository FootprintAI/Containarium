package server

import (
	"context"
	"os"
	"testing"

	"github.com/footprintai/containarium/internal/tracker"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// mustTestTrackerStore returns a real tracker.Store against
// CONTAINARIUM_TEST_DSN, skipping the test if it isn't set — same
// convention as mustTestSecretsStore in secrets_kms_key_test.go.
func mustTestTrackerStore(t *testing.T) *tracker.Store {
	t.Helper()
	dsn := os.Getenv("CONTAINARIUM_TEST_DSN")
	if dsn == "" {
		t.Skip("set CONTAINARIUM_TEST_DSN to run this against Postgres")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect Postgres: %v", err)
	}
	t.Cleanup(pool.Close)
	store, err := tracker.NewStore(ctx, pool)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return store
}

func TestSetTrackerConnection_NoAuthContext(t *testing.T) {
	s := &ContainerServer{}
	_, err := s.SetTrackerConnection(context.Background(), &pb.SetTrackerConnectionRequest{
		Username: "alice", Name: "default",
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", status.Code(err))
	}
}

// TestSetTrackerConnection_TrackerWriteScopeInsufficient pins the
// deliberate separation from #1922's agent-facing scopes: a token
// carrying tracker:write (what an agent's run-scoped JWT gets for the
// issue/comment/claim verbs) must NOT be able to create or repoint a
// connection — that needs tracker:admin.
func TestSetTrackerConnection_TrackerWriteScopeInsufficient(t *testing.T) {
	s := &ContainerServer{}
	ctx := kmsKeyTestCtx("alice", "member", "tracker:write")
	_, err := s.SetTrackerConnection(ctx, &pb.SetTrackerConnectionRequest{
		Username: "alice", Name: "default",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", status.Code(err))
	}
}

// TestSetTrackerConnection_CrossTenantDenied needs a configured store —
// with a nil store, the handler's nil-store check (which runs before
// AuthorizeTenant, same ordering as SetSecret/GetSecret/etc.) would
// return Unavailable before authz is ever reached, testing the wrong
// thing.
func TestSetTrackerConnection_CrossTenantDenied(t *testing.T) {
	s := &ContainerServer{secretsStore: mustTestSecretsStore(t), trackerStore: mustTestTrackerStore(t)}
	ctx := kmsKeyTestCtx("tracker-rpc-cross-tenant-alice", "member", "tracker:admin")
	_, err := s.SetTrackerConnection(ctx, &pb.SetTrackerConnectionRequest{
		Username: "tracker-rpc-cross-tenant-bob", Name: "default",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied (alice acting on bob's tenant without admin role)", status.Code(err))
	}
}

func TestSetTrackerConnection_RejectsMissingSecret(t *testing.T) {
	secretsStore := mustTestSecretsStore(t)
	trackerStore := mustTestTrackerStore(t)
	s := &ContainerServer{secretsStore: secretsStore, trackerStore: trackerStore}
	const user = "tracker-rpc-missing-secret"

	ctx := kmsKeyTestCtx(user, "member", "tracker:admin")
	_, err := s.SetTrackerConnection(ctx, &pb.SetTrackerConnectionRequest{
		Username:         user,
		Name:             "default",
		Provider:         pb.TrackerProvider_TRACKER_PROVIDER_GITHUB,
		Project:          "acme/widgets",
		CredentialSecret: "DOES_NOT_EXIST",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument (credential_secret doesn't exist)", status.Code(err))
	}
}

func TestSetTrackerConnection_RejectsNonBrokerSecret(t *testing.T) {
	secretsStore := mustTestSecretsStore(t)
	trackerStore := mustTestTrackerStore(t)
	s := &ContainerServer{secretsStore: secretsStore, trackerStore: trackerStore}
	const user = "tracker-rpc-non-broker-secret"

	secretCtx := kmsKeyTestCtx(user, "member", "secrets:write")
	if _, err := s.SetSecret(secretCtx, &pb.SetSecretRequest{
		Username: user, Name: "GH_TOKEN", Value: "ghp_x",
		DeliveryMode: pb.SecretDelivery_SECRET_DELIVERY_ENV,
	}); err != nil {
		t.Fatalf("SetSecret (env mode): %v", err)
	}

	ctx := kmsKeyTestCtx(user, "member", "tracker:admin")
	_, err := s.SetTrackerConnection(ctx, &pb.SetTrackerConnectionRequest{
		Username:         user,
		Name:             "default",
		Provider:         pb.TrackerProvider_TRACKER_PROVIDER_GITHUB,
		Project:          "acme/widgets",
		CredentialSecret: "GH_TOKEN",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument (credential_secret is env-mode, not broker-only)", status.Code(err))
	}
}

// TestTrackerConnection_CRUDRoundTrip is the happy path end to end
// through the RPC layer: a broker-only secret, then Set / Get / List /
// Delete on the connection that references it.
func TestTrackerConnection_CRUDRoundTrip(t *testing.T) {
	secretsStore := mustTestSecretsStore(t)
	trackerStore := mustTestTrackerStore(t)
	s := &ContainerServer{secretsStore: secretsStore, trackerStore: trackerStore}
	const user = "tracker-rpc-crud"

	secretCtx := kmsKeyTestCtx(user, "member", "secrets:write")
	if _, err := s.SetSecret(secretCtx, &pb.SetSecretRequest{
		Username: user, Name: "GH_TOKEN", Value: "ghp_x",
		DeliveryMode: pb.SecretDelivery_SECRET_DELIVERY_BROKER_ONLY,
	}); err != nil {
		t.Fatalf("SetSecret (broker-only): %v", err)
	}

	adminCtx := kmsKeyTestCtx(user, "member", "tracker:admin")
	setResp, err := s.SetTrackerConnection(adminCtx, &pb.SetTrackerConnectionRequest{
		Username:         user,
		Name:             "default",
		Provider:         pb.TrackerProvider_TRACKER_PROVIDER_GITHUB,
		Project:          "acme/widgets",
		CredentialSecret: "GH_TOKEN",
	})
	if err != nil {
		t.Fatalf("SetTrackerConnection: %v", err)
	}
	if setResp.Connection == nil || setResp.Connection.CredentialSecret != "GH_TOKEN" {
		t.Fatalf("SetTrackerConnection response = %+v, want CredentialSecret=GH_TOKEN", setResp.Connection)
	}

	getResp, err := s.GetTrackerConnection(adminCtx, &pb.GetTrackerConnectionRequest{Username: user, Name: "default"})
	if err != nil {
		t.Fatalf("GetTrackerConnection: %v", err)
	}
	if getResp.Connection.Project != "acme/widgets" {
		t.Errorf("GetTrackerConnection project = %q, want acme/widgets", getResp.Connection.Project)
	}

	listResp, err := s.ListTrackerConnections(adminCtx, &pb.ListTrackerConnectionsRequest{Username: user})
	if err != nil {
		t.Fatalf("ListTrackerConnections: %v", err)
	}
	if len(listResp.Connections) != 1 || listResp.Connections[0].Name != "default" {
		t.Fatalf("ListTrackerConnections = %+v, want exactly one connection named default", listResp.Connections)
	}

	if _, err := s.DeleteTrackerConnection(adminCtx, &pb.DeleteTrackerConnectionRequest{Username: user, Name: "default"}); err != nil {
		t.Fatalf("DeleteTrackerConnection: %v", err)
	}
	if _, err := s.GetTrackerConnection(adminCtx, &pb.GetTrackerConnectionRequest{Username: user, Name: "default"}); status.Code(err) != codes.NotFound {
		t.Fatalf("GetTrackerConnection after delete code = %v, want NotFound", status.Code(err))
	}
}
