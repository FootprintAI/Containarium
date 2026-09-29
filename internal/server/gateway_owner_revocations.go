package server

import (
	"log"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/modelgateway"
)

// The durable store satisfies the gateway's read half at compile time. Its
// write half (RevokeOwner, which RevokeByKeyOwner type-asserts for) is an
// unexported interface in modelgateway, so it is pinned by the tests instead:
// DeleteTenantProviderKey must report tokens_revoked=true on a
// Postgres-backed daemon.
var _ modelgateway.OwnerRevocationChecker = (*auth.PgOwnerRevocationStore)(nil)

// gatewayOwnerRevocations picks the model gateway's owner-revocation store
// (the "customer removed their key" kill-switch, #1725/#2111).
//
// With Postgres, the durable store: an owner cutoff survives a daemon restart,
// so a token minted before its owner's key was removed cannot resolve through
// the daemon-global key once the daemon comes back.
//
// Without Postgres (pg == nil), the in-memory store, with a warning. Chosen
// through an explicit nil check rather than assigning pg directly: a nil
// *auth.PgOwnerRevocationStore placed in an interface field is a NON-nil
// interface holding a nil pointer, so the gateway's `OwnerRevocations == nil`
// guard would not fire and every keyed model call would dereference nil — the
// same hazard, same shape, as the gateway's jti revocation wiring.
func gatewayOwnerRevocations(pg *auth.PgOwnerRevocationStore) modelgateway.OwnerRevocationChecker {
	if pg != nil {
		return pg
	}
	log.Printf("Warning: model-gateway owner revocations are in-memory (no Postgres) — a daemon restart forgets them, so a token minted before its owner's key was removed can resolve through the daemon-global key again after a restart")
	return modelgateway.NewMemOwnerRevocations()
}
