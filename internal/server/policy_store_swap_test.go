package server

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/footprintai/containarium/internal/guardrailpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #2483: the durable store can now be installed after the server is serving
// (the recovery retry), so the swap has to reach every reader, including the
// Provider() the deploy gate and model gateway captured at startup.

func TestGuardrailPolicyProvider_FollowsDurableInstall(t *testing.T) {
	s := NewGuardrailPolicyServer(guardrailPolicyStartupStore(true, nil))
	provider := s.Provider() // captured at startup, as the gate and gateway do
	if s.Durable() {
		t.Fatal("Durable() = true on the fail-closed stand-in")
	}
	if _, err := provider.Get(context.Background()); err == nil || errors.Is(err, guardrailpolicy.ErrNotConfigured) {
		t.Fatalf("provider.Get before install = %v, want a fail-closed error", err)
	}

	if err := s.InstallDurableStore(func() (guardrailpolicy.Store, error) {
		return nil, errors.New("connection refused")
	}); err == nil {
		t.Fatal("InstallDurableStore: want the opener's error")
	}
	if s.Durable() {
		t.Fatal("Durable() = true after a failed install")
	}

	durable := guardrailpolicy.NewMemoryStore() // stands in for the Postgres store
	if _, err := durable.Set(context.Background(), gpRequest(0, gpSigner(1)).GetPolicy(), []*pb.GuardrailTrustedSigner{gpSigner(1)}, "admin"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := s.InstallDurableStore(func() (guardrailpolicy.Store, error) { return durable, nil }); err != nil {
		t.Fatalf("InstallDurableStore: %v", err)
	}
	if !s.Durable() {
		t.Fatal("Durable() = false after install")
	}
	got, err := provider.Get(context.Background())
	if err != nil {
		t.Fatalf("startup-captured provider.Get after install = %v, want the durable store's policy", err)
	}
	if got.GetRevision() != 1 {
		t.Fatalf("provider.Get revision = %d, want 1 (the durable store's policy)", got.GetRevision())
	}
	resp, err := s.GetGuardrailPolicy(gpUserCtx(), &pb.GetGuardrailPolicyRequest{})
	if err != nil || !resp.GetConfigured() {
		t.Fatalf("Get after install = %v, %v; want the durable policy", resp, err)
	}
}

func TestCodeEgressPolicy_DurableFollowsInstall(t *testing.T) {
	s := startupServer(t)
	if s.Durable() {
		t.Fatal("Durable() = true on the stand-in")
	}
	if err := s.InstallDurableStore(func() (CodingToolEgressPolicyStore, error) {
		return NewMemCodingToolEgressPolicyStore(), nil
	}); err != nil {
		t.Fatalf("InstallDurableStore: %v", err)
	}
	if !s.Durable() {
		t.Fatal("Durable() = false after install")
	}
}

// The swap happens while RPCs are in flight; run with -race.
func TestPolicyStoreSwap_ConcurrentWithReads(t *testing.T) {
	gp := NewGuardrailPolicyServer(guardrailPolicyStartupStore(true, nil))
	ce := startupServer(t)
	provider := gp.Provider()
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, _ = provider.Get(context.Background())
				_, _ = ce.GetCodingToolEgressPolicy(ceAdminCtx(), &pb.GetCodingToolEgressPolicyRequest{Tenant: "alice"})
			}
		}()
	}
	if err := gp.InstallDurableStore(func() (guardrailpolicy.Store, error) { return guardrailpolicy.NewMemoryStore(), nil }); err != nil {
		t.Errorf("guardrail install: %v", err)
	}
	if err := ce.InstallDurableStore(func() (CodingToolEgressPolicyStore, error) { return NewMemCodingToolEgressPolicyStore(), nil }); err != nil {
		t.Errorf("egress install: %v", err)
	}
	close(stop)
	wg.Wait()
}
