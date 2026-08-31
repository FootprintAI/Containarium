package secrets

import (
	"context"
	"errors"
	"testing"

	"github.com/footprintai/containarium/internal/safecast"
	corecrypto "github.com/footprintai/containarium/pkg/core/secrets"
)

// #1630 — per-tenant KEK dispatch. These tests avoid Postgres entirely
// (same discipline as envelope_dispatch_test.go): they construct a
// *Store literal directly and exercise resolveEncryptKMS /
// resolveDecryptKMS / kekClient, which are pure in-memory + factory
// logic. SetTenantKMSKey / ClearTenantKMSKey / rewrapTenant need a real
// Postgres (they call List/Get/Set) — those live in
// tenant_kms_integration_test.go, gated on CONTAINARIUM_TEST_DSN like
// the rest of the Postgres-backed suite.

// fakeTenantKMS is a KMSClient double whose kek_id is settable per
// instance, so tests can prove "this exact client" was chosen rather
// than merely "a client was chosen." Wrap/Unwrap are otherwise
// pass-through (XOR with a per-instance byte) — enough to prove a
// value only round-trips through the SAME instance, catching a
// resolver that returns the wrong client for decrypt.
type fakeTenantKMS struct {
	kekID   string
	tweak   byte
	wrapErr error
}

func (f *fakeTenantKMS) Wrap(_ context.Context, dek []byte) ([]byte, string, error) {
	if f.wrapErr != nil {
		return nil, "", f.wrapErr
	}
	out := make([]byte, len(dek))
	for i, b := range dek {
		out[i] = b ^ f.tweak
	}
	return out, f.kekID, nil
}

func (f *fakeTenantKMS) Unwrap(_ context.Context, wrapped []byte, kekID string) ([]byte, error) {
	if kekID != f.kekID {
		return nil, errors.New("fakeTenantKMS: kek_id mismatch — wrong client selected")
	}
	out := make([]byte, len(wrapped))
	for i, b := range wrapped {
		out[i] = b ^ f.tweak
	}
	return out, nil
}

func newFakeFactory(t *testing.T, built map[string]int) TenantKMSFactory {
	t.Helper()
	return func(keyResourceName string) (corecrypto.KMSClient, error) {
		if keyResourceName == "bad-key" {
			return nil, errors.New("fake: malformed key")
		}
		built[keyResourceName]++
		// Deterministic per-key tweak byte so different keys are
		// distinguishable but the same key always builds an
		// equivalent (thought not necessarily identical, since the
		// cache should prevent rebuilding) client.
		return &fakeTenantKMS{kekID: corecrypto.GCPKEKPrefix + keyResourceName, tweak: safecast.U8(len(keyResourceName))}, nil
	}
}

func TestResolveEncryptKMS_NoFactory_UsesSharedDefault(t *testing.T) {
	shared := &fakeTenantKMS{kekID: "shared"}
	s := &Store{kms: shared}
	got, err := s.resolveEncryptKMS("alice")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if got != shared {
		t.Fatal("expected the shared client when no tenant factory is configured")
	}
}

func TestResolveEncryptKMS_NoOverride_UsesSharedDefault(t *testing.T) {
	shared := &fakeTenantKMS{kekID: "shared"}
	built := map[string]int{}
	s := &Store{
		kms:              shared,
		tenantKMSFactory: newFakeFactory(t, built),
		tenantKEK:        map[string]string{},
		kekClients:       map[string]corecrypto.KMSClient{},
	}
	got, err := s.resolveEncryptKMS("alice")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if got != shared {
		t.Fatal("alice has no override — must resolve to the shared client")
	}
	if len(built) != 0 {
		t.Fatal("must not build a tenant client when there's no override to serve")
	}
}

func TestResolveEncryptKMS_WithOverride_BuildsAndCachesTenantClient(t *testing.T) {
	shared := &fakeTenantKMS{kekID: "shared"}
	built := map[string]int{}
	s := &Store{
		kms:              shared,
		tenantKMSFactory: newFakeFactory(t, built),
		tenantKEK:        map[string]string{"alice": "tenant-key-a"},
		kekClients:       map[string]corecrypto.KMSClient{},
	}
	got, err := s.resolveEncryptKMS("alice")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if got == shared {
		t.Fatal("alice has an override — must NOT resolve to the shared client")
	}
	if built["tenant-key-a"] != 1 {
		t.Fatalf("expected the factory called once for tenant-key-a; got %d", built["tenant-key-a"])
	}

	// Bob has no override and must be unaffected by alice's.
	bobClient, err := s.resolveEncryptKMS("bob")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if bobClient != shared {
		t.Fatal("bob has no override — must resolve to the shared client, independent of alice's")
	}

	// A second resolve for alice must reuse the cached client, not
	// rebuild it.
	again, err := s.resolveEncryptKMS("alice")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if again != got {
		t.Fatal("expected the SAME cached client instance on a second resolve")
	}
	if built["tenant-key-a"] != 1 {
		t.Fatalf("expected the factory still called exactly once; got %d calls", built["tenant-key-a"])
	}
}

func TestResolveEncryptKMS_FactoryErrorPropagates(t *testing.T) {
	built := map[string]int{}
	s := &Store{
		tenantKMSFactory: newFakeFactory(t, built),
		tenantKEK:        map[string]string{"alice": "bad-key"},
		kekClients:       map[string]corecrypto.KMSClient{},
	}
	if _, err := s.resolveEncryptKMS("alice"); err == nil {
		t.Fatal("expected the factory's error to propagate")
	}
}

func TestResolveDecryptKMS_GCPRowRoutesByKeyNameNotByCurrentOverride(t *testing.T) {
	// The load-bearing property from the design doc: decrypt is
	// resolved from the ROW's own kek_id, never from "whatever the
	// tenant's override currently is." Simulate the exact scenario
	// that would break a naive "resolve by current override" design:
	// alice's override has already moved to key B, but a row still
	// carries key A's kek_id — it must still decrypt correctly.
	built := map[string]int{}
	s := &Store{
		kms:              &fakeTenantKMS{kekID: "shared"},
		tenantKMSFactory: newFakeFactory(t, built),
		tenantKEK:        map[string]string{"alice": "key-b"}, // current override says B
		kekClients:       map[string]corecrypto.KMSClient{},
	}

	// Row was wrapped under key A (kek_id = "gcp:key-a") — resolve
	// must build/return A's client, not B's, regardless of alice's
	// current override.
	client, err := s.resolveDecryptKMS(corecrypto.GCPKEKPrefix + "key-a")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	fk, ok := client.(*fakeTenantKMS)
	if !ok || fk.kekID != corecrypto.GCPKEKPrefix+"key-a" {
		t.Fatalf("resolved client kek_id = %v; want %s", client, corecrypto.GCPKEKPrefix+"key-a")
	}
}

func TestResolveDecryptKMS_NonGCPKekIDFallsBackToShared(t *testing.T) {
	shared := &fakeTenantKMS{kekID: "inproc:master"}
	built := map[string]int{}
	s := &Store{
		kms:              shared,
		tenantKMSFactory: newFakeFactory(t, built),
		kekClients:       map[string]corecrypto.KMSClient{},
	}
	got, err := s.resolveDecryptKMS("inproc:master")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if got != shared {
		t.Fatal("a non-gcp-prefixed kek_id must fall back to the shared client")
	}
	if len(built) != 0 {
		t.Fatal("must not consult the tenant factory for a non-gcp row")
	}
}

func TestResolveDecryptKMS_NoFactoryConfigured_AlwaysSharedClient(t *testing.T) {
	shared := &fakeTenantKMS{kekID: "gcp:whatever"}
	s := &Store{kms: shared}
	got, err := s.resolveDecryptKMS("gcp:some-other-key")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if got != shared {
		t.Fatal("with no tenant factory configured, every row must resolve to the shared client (today's behavior, unchanged)")
	}
}

func TestKEKClient_CachesAcrossCallsForTheSameKey(t *testing.T) {
	built := map[string]int{}
	s := &Store{
		tenantKMSFactory: newFakeFactory(t, built),
		kekClients:       map[string]corecrypto.KMSClient{},
	}
	a, err := s.kekClient("key-x")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	b, err := s.kekClient("key-x")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if a != b {
		t.Fatal("expected the cached instance on the second call")
	}
	if built["key-x"] != 1 {
		t.Fatalf("factory should be called exactly once; got %d", built["key-x"])
	}
}
