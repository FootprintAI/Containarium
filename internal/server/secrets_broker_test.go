package server

import (
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// TestGetSecretRPC_BrokerRow_EmptyValueEvenWithSecretsRead pins the
// server-level half of the write-only guarantee: a caller holding
// secrets:read on its own tenant — the ordinary shape for an agent's
// JWT — gets metadata but no value back for a broker-only secret. The
// store-level half (Store.Get returning ErrBrokerOnly) is covered in
// internal/secrets; this test is what proves the RPC handler doesn't
// undo that by mapping the error to something that leaks the value.
func TestGetSecretRPC_BrokerRow_EmptyValueEvenWithSecretsRead(t *testing.T) {
	store := mustTestSecretsStore(t)
	s := &ContainerServer{secretsStore: store}
	const user = "broker-rpc-test-user"

	setCtx := kmsKeyTestCtx(user, "member", "secrets:write")
	if _, err := s.SetSecret(setCtx, &pb.SetSecretRequest{
		Username:     user,
		Name:         "GH_TOKEN",
		Value:        "ghp_secret",
		DeliveryMode: pb.SecretDelivery_SECRET_DELIVERY_BROKER_ONLY,
	}); err != nil {
		t.Fatalf("SetSecret(broker-only): %v", err)
	}

	getCtx := kmsKeyTestCtx(user, "member", "secrets:read")
	resp, err := s.GetSecret(getCtx, &pb.GetSecretRequest{Username: user, Name: "GH_TOKEN"})
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if resp.Value != "" {
		t.Errorf("GetSecret returned a value for a broker-only secret to a secrets:read caller: %q", resp.Value)
	}
	if resp.Secret == nil || resp.Secret.DeliveryMode != pb.SecretDelivery_SECRET_DELIVERY_BROKER_ONLY {
		t.Errorf("GetSecret metadata = %+v, want DeliveryMode=BROKER_ONLY", resp.Secret)
	}

	// ListSecrets shows the row with its mode, still no value (ListSecrets
	// never returns values for any mode — unaffected by this change, but
	// worth pinning here since it's the other read path onto the same row).
	listResp, err := s.ListSecrets(getCtx, &pb.ListSecretsRequest{Username: user})
	if err != nil {
		t.Fatalf("ListSecrets: %v", err)
	}
	found := false
	for _, m := range listResp.Secrets {
		if m.Name == "GH_TOKEN" {
			found = true
			if m.DeliveryMode != pb.SecretDelivery_SECRET_DELIVERY_BROKER_ONLY {
				t.Errorf("ListSecrets GH_TOKEN DeliveryMode = %v, want BROKER_ONLY", m.DeliveryMode)
			}
		}
	}
	if !found {
		t.Error("ListSecrets did not include the broker-only secret")
	}
}

// TestSetSecretRPC_BrokerToDeliveringMode_Rejected pins the RPC-level
// mapping of the store's one-way guard to FAILED_PRECONDITION.
func TestSetSecretRPC_BrokerToDeliveringMode_Rejected(t *testing.T) {
	store := mustTestSecretsStore(t)
	s := &ContainerServer{secretsStore: store}
	const user = "broker-rpc-test-immutable"

	ctx := kmsKeyTestCtx(user, "member", "secrets:write")
	if _, err := s.SetSecret(ctx, &pb.SetSecretRequest{
		Username:     user,
		Name:         "GH_TOKEN",
		Value:        "ghp_secret",
		DeliveryMode: pb.SecretDelivery_SECRET_DELIVERY_BROKER_ONLY,
	}); err != nil {
		t.Fatalf("SetSecret(broker-only): %v", err)
	}

	_, err := s.SetSecret(ctx, &pb.SetSecretRequest{
		Username:     user,
		Name:         "GH_TOKEN",
		Value:        "ghp_new",
		DeliveryMode: pb.SecretDelivery_SECRET_DELIVERY_ENV,
	})
	if err == nil {
		t.Fatal("SetSecret(broker -> env) succeeded, want FailedPrecondition")
	}
}
