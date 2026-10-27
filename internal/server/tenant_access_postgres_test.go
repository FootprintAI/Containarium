package server

import (
	"context"
	"errors"
	"fmt"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
	"os"
	"sync"
	"testing"
	"time"
)

func TestTenantAccessPostgresAtomicityPreservationAndConcurrency(t *testing.T) {
	dsn := os.Getenv("CONTAINARIUM_TEST_DSN")
	if dsn == "" {
		t.Skip("set CONTAINARIUM_TEST_DSN to run this against Postgres (the store-integration lane does)")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := fmt.Sprintf("tenant_access_test_%d", time.Now().UnixNano())
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = admin.Exec(ctx, "DROP SCHEMA "+quoted+" CASCADE") }()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	store, err := NewPostgresNetworkPolicyStore(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	old := richAccessPolicy("testing")
	if err := store.Set(ctx, old); err != nil {
		t.Fatal(err)
	}
	if _, err := store.MutateDenyRules(ctx, "testing", func([]*pb.NetworkPolicyDenyRule) ([]*pb.NetworkPolicyDenyRule, error) { return old.DenyRules, nil }); err != nil {
		t.Fatal(err)
	}
	before, _ := store.Get(ctx, "testing")
	changed, err := store.PatchTenantAccess(ctx, []*pb.TenantAccessChange{{Destination: "allinone", AddSources: []string{"testing"}, ExpectedRevision: "absent"}, {Destination: "testing", AddSources: []string{"allinone"}, ExpectedRevision: PolicyRevision(before)}})
	if err != nil || len(changed) != 2 {
		t.Fatalf("atomic two-way mutation: %v", err)
	}
	after, _ := store.Get(ctx, "testing")
	without := proto.Clone(after).(*pb.NetworkPolicy)
	without.AllowFromTenants = nil
	if !proto.Equal(without, before) {
		t.Fatal("Postgres ingress UPDATE lost other policy fields")
	}
	_, err = store.PatchTenantAccess(ctx, []*pb.TenantAccessChange{{Destination: "new-empty", AddSources: []string{"testing"}, ExpectedRevision: "absent"}, {Destination: "testing", RemoveSources: []string{"allinone"}, ExpectedRevision: PolicyRevision(before)}})
	if !errors.Is(err, ErrTenantAccessConflict) {
		t.Fatal("stale preview did not conflict")
	}
	if _, err := store.Get(ctx, "new-empty"); !errors.Is(err, ErrNetworkPolicyNotFound) {
		t.Fatal("failed batch left an inserted row")
	}
	rev := PolicyRevision(after)
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, src := range []string{"first", "second"} {
		wg.Add(1)
		go func(src string) {
			defer wg.Done()
			_, err := store.PatchTenantAccess(ctx, []*pb.TenantAccessChange{{Destination: "testing", AddSources: []string{src}, ExpectedRevision: rev}})
			errs <- err
		}(src)
	}
	wg.Wait()
	close(errs)
	success, conflict := 0, 0
	for err := range errs {
		if err == nil {
			success++
		} else if errors.Is(err, ErrTenantAccessConflict) {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatal("Postgres CAS lost a concurrent edit")
	}
}
