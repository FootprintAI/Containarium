//go:build integration

package server

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// The Postgres CodingToolEgressPolicyStore (#2378) against a real database:
//
//	CONTAINARIUM_TEST_DSN=postgres://... go test -tags=integration ./internal/server/

func freshCodeEgressSchema(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	for _, q := range []string{
		`DROP TABLE IF EXISTS coding_tool_egress_policies`,
		`DROP SEQUENCE IF EXISTS coding_tool_egress_policy_revision_seq`,
	} {
		if _, err := pool.Exec(context.Background(), q); err != nil {
			t.Fatalf("reset schema (%s): %v", q, err)
		}
	}
}

func TestCodingToolEgressPolicyStore_PostgresContract(t *testing.T) {
	pool := testPool(t)
	freshCodeEgressSchema(t, pool)
	s, err := NewPostgresCodingToolEgressPolicyStore(context.Background(), pool)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	codeEgressStoreContract(t, s)
}

// A restarted daemon (new pool, new store over the same database) reads the
// policy back unchanged, and the next revision is still above the old one.
func TestCodingToolEgressPolicyStore_PostgresSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	freshCodeEgressSchema(t, pool)
	s1, err := NewPostgresCodingToolEgressPolicyStore(ctx, pool)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	before, _, err := s1.Set(ctx, &pb.CodingToolEgressPolicy{
		Tenant: "alice", Mode: pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE,
		EgressCidrs: []string{"192.0.2.0/24", "2001:db8::/32"}, EgressDomains: []string{"api.example.com"},
	}, "admin-user")
	if err != nil {
		t.Fatalf("Set: %v", err)
	}

	pool2, err := pgxpool.New(ctx, os.Getenv("CONTAINARIUM_TEST_DSN"))
	if err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	defer pool2.Close()
	s2, err := NewPostgresCodingToolEgressPolicyStore(ctx, pool2)
	if err != nil {
		t.Fatalf("store after reconnect: %v", err)
	}
	got, err := s2.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("Get after restart: %v", err)
	}
	if got.GetRevision() != before.GetRevision() || got.GetMode() != before.GetMode() ||
		len(got.GetEgressCidrs()) != 2 || got.GetEgressDomains()[0] != "api.example.com" ||
		got.GetUpdatedBy() != "admin-user" || got.GetUpdatedAt() == nil {
		t.Fatalf("policy changed across a restart: before %+v, after %+v", before, got)
	}
	next, prev, err := s2.Set(ctx, &pb.CodingToolEgressPolicy{Tenant: "alice"}, "admin-user")
	if err != nil {
		t.Fatalf("Set after restart: %v", err)
	}
	if prev != before.GetRevision() || next.GetRevision() <= before.GetRevision() {
		t.Fatalf("after restart: prev=%d revision=%d, want prev=%d and a higher revision", prev, next.GetRevision(), before.GetRevision())
	}
}
