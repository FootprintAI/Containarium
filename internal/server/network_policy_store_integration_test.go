//go:build integration

package server

import (
	"context"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// egress_mode survives the Postgres store: Set → Get/List read it back, a
// policy that never set it reads back UNSPECIFIED ("follow mode"), and a deny
// rule mutation leaves it untouched.
//
//	CONTAINARIUM_TEST_DSN=postgres://... go test -tags=integration ./internal/server/ -run NetworkPolicyStore_PostgresEgressMode
func TestNetworkPolicyStore_PostgresEgressMode(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS network_policies`); err != nil {
		t.Fatalf("reset network_policies: %v", err)
	}
	s, err := NewPostgresNetworkPolicyStore(ctx, pool)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	enforce := pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE
	logOnly := pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY
	if err := s.Set(ctx, &pb.NetworkPolicy{Tenant: "alice", Mode: enforce, EgressMode: logOnly}); err != nil {
		t.Fatalf("Set alice: %v", err)
	}
	if err := s.Set(ctx, &pb.NetworkPolicy{Tenant: "bob", Mode: enforce}); err != nil {
		t.Fatalf("Set bob: %v", err)
	}

	got, err := s.Get(ctx, "alice")
	if err != nil || got.GetEgressMode() != logOnly || got.GetMode() != enforce {
		t.Fatalf("Get alice = %v, %v; want mode=ENFORCE egress_mode=LOG_ONLY", got, err)
	}
	got, err = s.Get(ctx, "bob")
	if err != nil || got.GetEgressMode() != pb.NetworkPolicyMode_NETWORK_POLICY_MODE_UNSPECIFIED {
		t.Fatalf("Get bob = %v, %v; want egress_mode UNSPECIFIED", got, err)
	}
	list, err := s.List(ctx)
	if err != nil || len(list) != 2 || list[0].GetEgressMode() != logOnly {
		t.Fatalf("List = %v, %v", list, err)
	}
	mut, err := s.MutateDenyRules(ctx, "alice", func(r []*pb.NetworkPolicyDenyRule) ([]*pb.NetworkPolicyDenyRule, error) {
		return append(r, &pb.NetworkPolicyDenyRule{Cidr: "192.0.2.1/32"}), nil
	})
	if err != nil || mut.GetEgressMode() != logOnly {
		t.Fatalf("MutateDenyRules = %v, %v; want egress_mode kept", mut, err)
	}
}
