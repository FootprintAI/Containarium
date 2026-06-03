package server

import (
	"context"
	"sync"
	"testing"
)

func TestMemTenantRegistry_StableAndDistinct(t *testing.T) {
	r := NewMemTenantRegistry()
	ctx := context.Background()

	alice1, err := r.ID(ctx, "alice")
	if err != nil {
		t.Fatalf("ID(alice): %v", err)
	}
	bob, err := r.ID(ctx, "bob")
	if err != nil {
		t.Fatalf("ID(bob): %v", err)
	}
	alice2, err := r.ID(ctx, "alice")
	if err != nil {
		t.Fatalf("ID(alice) again: %v", err)
	}

	if alice1 == 0 || bob == 0 {
		t.Errorf("IDs must be non-zero (0 is reserved): alice=%d bob=%d", alice1, bob)
	}
	if alice1 != alice2 {
		t.Errorf("ID must be stable for the same tenant: %d != %d", alice1, alice2)
	}
	if alice1 == bob {
		t.Errorf("distinct tenants must get distinct IDs: alice=bob=%d", alice1)
	}
}

func TestMemTenantRegistry_Concurrent(t *testing.T) {
	r := NewMemTenantRegistry()
	ctx := context.Background()

	var wg sync.WaitGroup
	var mu sync.Mutex
	got := make(map[string]uint32)
	for _, name := range []string{"a", "b", "c", "a", "b", "c", "a"} {
		wg.Add(1)
		go func(n string) {
			defer wg.Done()
			id, err := r.ID(ctx, n)
			if err != nil {
				t.Errorf("ID(%s): %v", n, err)
				return
			}
			mu.Lock()
			if prev, ok := got[n]; ok && prev != id {
				t.Errorf("tenant %q got two IDs: %d and %d", n, prev, id)
			}
			got[n] = id
			mu.Unlock()
		}(name)
	}
	wg.Wait()

	// Three distinct tenants → three distinct IDs.
	seen := map[uint32]bool{}
	for _, id := range got {
		seen[id] = true
	}
	if len(seen) != 3 {
		t.Errorf("expected 3 distinct IDs, got %d: %v", len(seen), got)
	}
}
