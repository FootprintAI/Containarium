package server

import (
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/modelgateway"
	"github.com/footprintai/containarium/internal/secrets"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The reserved `__gateway/` namespace must stay invisible on the TENANT secrets
// API (#1726 acceptance criterion; the store-level guard landed with #1725).
//
// #1725 proved the guard at the store boundary (ErrReservedNamespace on Set /
// Get / List / Delete / LoadAllForUserWithDelivery / BrokerCredential). These
// tests prove it at the RPC boundary, which is the surface a tenant can actually
// reach — an RPC forwards a caller-supplied username straight into the store, so
// "the store refuses it" is only useful if the refusal survives the handler.
//
// The store is a ZERO-VALUE *secrets.Store on purpose: it holds no pool, so
// anything that reached Postgres would panic. An orderly error is therefore
// itself the proof that the guard ran before any database access.
func TestSecretsRPCs_ReservedGatewayNamespaceIsInvisible(t *testing.T) {
	s := &ContainerServer{secretsStore: &secrets.Store{}}
	// An ADMIN caller with the wildcard scope — the most privileged shape the
	// tenant API has. If even this cannot reach the namespace, no tenant can.
	ctx := ctxWithScopes("operator", true, auth.ScopeWildcard)

	reserved := "__gateway/" + modelgateway.OrgKeyOwner("acme")

	t.Run("ListSecrets", func(t *testing.T) {
		resp, err := s.ListSecrets(ctx, &pb.ListSecretsRequest{Username: reserved})
		if err == nil {
			t.Fatalf("ListSecrets(%q) succeeded and returned %d secrets; the namespace must not be listable", reserved, len(resp.GetSecrets()))
		}
		if got := status.Code(err); got != codes.NotFound {
			t.Errorf("code = %v (%v), want NotFound — to the tenant API the reserved namespace is not a tenant", got, err)
		}
	})

	t.Run("GetSecret", func(t *testing.T) {
		if _, err := s.GetSecret(ctx, &pb.GetSecretRequest{Username: reserved, Name: "KAFEIDO"}); status.Code(err) != codes.NotFound {
			t.Errorf("code = %v, want NotFound", status.Code(err))
		}
	})

	t.Run("SetSecret", func(t *testing.T) {
		if _, err := s.SetSecret(ctx, &pb.SetSecretRequest{Username: reserved, Name: "KAFEIDO", Value: "sk-hostile"}); status.Code(err) != codes.NotFound {
			t.Errorf("code = %v, want NotFound", status.Code(err))
		}
	})

	t.Run("DeleteSecret", func(t *testing.T) {
		if _, err := s.DeleteSecret(ctx, &pb.DeleteSecretRequest{Username: reserved, Name: "KAFEIDO"}); status.Code(err) != codes.NotFound {
			t.Errorf("code = %v, want NotFound", status.Code(err))
		}
	})
}

// A tenant username can never collide with the namespace, because the prefix
// contains a '/' and a tenant username cannot. This pins that the discriminator
// is the separator and not a denylist someone has to remember to update.
func TestSecretsRPCs_ReservedNamespaceIsUnreachableByAnyTenantUsername(t *testing.T) {
	for _, candidate := range []string{
		"__gateway",   // the prefix without its separator: a legal username shape
		"gateway",     //
		"__gatewayx",  //
		"_gateway",    //
		"__GATEWAY/x", // case must not open a side door either
	} {
		if secrets.IsGatewayKeyNamespace(candidate) {
			t.Errorf("IsGatewayKeyNamespace(%q) = true; only names carrying the %q prefix are reserved", candidate, "__gateway/")
		}
	}
	if !secrets.IsGatewayKeyNamespace("__gateway/user:alice") {
		t.Error("the reserved prefix is not recognised")
	}
}
