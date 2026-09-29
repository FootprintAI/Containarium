package server

import (
	"context"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/modelgateway"
)

// gatewayOwnerRevocations is the daemon's choice of owner-revocation store
// (#2111). Both branches matter:
//
//   - With Postgres it must hand the gateway the durable store, or a restart
//     forgets every owner cutoff.
//   - Without Postgres the store pointer is nil, and a nil
//     *auth.PgOwnerRevocationStore placed straight into the interface field
//     would be a NON-nil interface holding a nil pointer: the gateway's
//     `OwnerRevocations == nil` guard would not fire and every keyed model call
//     would dereference nil. It must fall back to the in-memory store instead.
func TestGatewayOwnerRevocations_WiringChoice(t *testing.T) {
	durable := &auth.PgOwnerRevocationStore{}

	tests := []struct {
		name        string
		pg          *auth.PgOwnerRevocationStore
		wantDurable bool
	}{
		{name: "postgres available: the durable store", pg: durable, wantDurable: true},
		{name: "no postgres: in-memory, never a nil pointer in the interface", pg: nil, wantDurable: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := gatewayOwnerRevocations(tc.pg)
			if got == nil {
				t.Fatal("no owner-revocation store at all — RevokeByKeyOwner would always refuse")
			}
			pg, isPg := got.(*auth.PgOwnerRevocationStore)
			if tc.wantDurable {
				if !isPg || pg != durable {
					t.Fatalf("got %T, want the durable *auth.PgOwnerRevocationStore", got)
				}
				return
			}
			if isPg {
				t.Fatalf("got %T (nil=%v) — a nil pointer in an interface is a non-nil interface", got, pg == nil)
			}
			// The fallback still has to record revocations, or
			// DeleteTenantProviderKey would report tokens_revoked=false on a
			// standalone daemon that can in fact revoke for its lifetime.
			gw := modelgateway.New(modelgateway.Config{Secret: []byte("s"), OwnerRevocations: got})
			if err := gw.RevokeByKeyOwner(context.Background(), "user:alice", "test"); err != nil {
				t.Fatalf("RevokeByKeyOwner on the fallback store: %v", err)
			}
			cutoff, err := got.RevokedBefore(context.Background(), "user:alice")
			if err != nil || cutoff.IsZero() || cutoff.After(time.Now()) {
				t.Errorf("fallback cutoff = %v, %v; want a recorded past instant", cutoff, err)
			}
		})
	}
}
