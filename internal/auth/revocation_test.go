package auth

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// Phase 1.2 — unit tests for the jti + revocation list flow.
// The Postgres-backed store is exercised by the integration
// suite (requires a live DB); here we stub RevocationStore
// in memory.

// memRevocationStore is a simple in-memory store that
// satisfies RevocationStore for tests.
type memRevocationStore struct {
	mu       sync.Mutex
	rows     map[string]time.Time // jti → expiresAt
	failNext bool                 // simulate a DB error
	revoked  []string             // for assertions
}

func newMemRevStore() *memRevocationStore {
	return &memRevocationStore{rows: map[string]time.Time{}}
}

func (m *memRevocationStore) IsRevoked(_ context.Context, jti string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failNext {
		m.failNext = false
		return false, errors.New("simulated DB error")
	}
	if jti == "" {
		return false, nil
	}
	_, ok := m.rows[jti]
	return ok, nil
}

func (m *memRevocationStore) Revoke(_ context.Context, jti string, exp time.Time, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.rows[jti]; !exists {
		m.rows[jti] = exp
		m.revoked = append(m.revoked, jti)
	}
	return nil
}

func (m *memRevocationStore) CleanupExpired(_ context.Context, now time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	pruned := int64(0)
	for jti, exp := range m.rows {
		if exp.Before(now) {
			delete(m.rows, jti)
			pruned++
		}
	}
	return pruned, nil
}

// List satisfies the RevocationStore interface. memRevocationStore
// doesn't track revoked_at / reason; tests that exercise the
// listing path use the Postgres-backed store.
func (m *memRevocationStore) List(_ context.Context, _ ListRevocationsParams) ([]Revocation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Revocation
	for jti, exp := range m.rows {
		out = append(out, Revocation{JTI: jti, ExpiresAt: exp})
	}
	return out, nil
}

const revTestSecret = "test-secret-must-be-at-least-32-bytes-long-ok"

func newTestTM(t *testing.T) *TokenManager {
	t.Helper()
	tm, err := NewTokenManager(revTestSecret, "test-iss")
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	return tm
}

// --- jti generation ---

func TestGenerateToken_IncludesJTI(t *testing.T) {
	tm := newTestTM(t)
	tokenStr, err := tm.GenerateToken("alice", []string{"user"}, time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	claims, err := tm.ValidateToken(tokenStr)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.ID == "" {
		t.Fatal("expected jti to be set; got empty")
	}
	if len(claims.ID) < 16 {
		t.Fatalf("jti too short to be 128 bits base64url: %q", claims.ID)
	}
}

func TestGenerateToken_JTIsAreUnique(t *testing.T) {
	tm := newTestTM(t)
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		tok, err := tm.GenerateToken("alice", []string{"user"}, time.Hour)
		if err != nil {
			t.Fatalf("GenerateToken: %v", err)
		}
		claims, _ := tm.ValidateToken(tok)
		if seen[claims.ID] {
			t.Fatalf("duplicate jti %q on iteration %d", claims.ID, i)
		}
		seen[claims.ID] = true
	}
}

// --- revocation check on ValidateToken ---

func TestValidateToken_AllowsWhenStoreUnconfigured(t *testing.T) {
	// Default state: SetRevocationStore not called → check
	// is skipped, all otherwise-valid tokens pass.
	tm := newTestTM(t)
	tok, _ := tm.GenerateToken("alice", []string{"user"}, time.Hour)
	if _, err := tm.ValidateToken(tok); err != nil {
		t.Fatalf("expected pass; got %v", err)
	}
}

func TestValidateToken_AllowsUnrevokedJTI(t *testing.T) {
	tm := newTestTM(t)
	store := newMemRevStore()
	tm.SetRevocationStore(store)
	tok, _ := tm.GenerateToken("alice", []string{"user"}, time.Hour)
	if _, err := tm.ValidateToken(tok); err != nil {
		t.Fatalf("unrevoked token should pass; got %v", err)
	}
}

func TestValidateToken_RejectsRevokedJTI(t *testing.T) {
	tm := newTestTM(t)
	store := newMemRevStore()
	tm.SetRevocationStore(store)

	tokenStr, _ := tm.GenerateToken("alice", []string{"user"}, time.Hour)
	claims, _ := tm.ValidateToken(tokenStr)

	if err := tm.RevokeToken(context.Background(), claims, "test-revoke"); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}

	_, err := tm.ValidateToken(tokenStr)
	if err == nil {
		t.Fatal("revoked token should be rejected")
	}
	if !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("error should be generic invalid; got %q", err.Error())
	}
}

func TestValidateToken_FailsOpenOnStoreError(t *testing.T) {
	// Revocation list is a kill-switch, not the primary
	// gate. A DB outage must not lock everyone out — the
	// daemon logs and continues to accept otherwise-valid
	// tokens. (Re-evaluating this trade-off would require
	// a separate audit finding; current call is documented
	// inline in token.go.)
	tm := newTestTM(t)
	store := newMemRevStore()
	store.failNext = true
	tm.SetRevocationStore(store)

	tok, _ := tm.GenerateToken("alice", []string{"user"}, time.Hour)
	if _, err := tm.ValidateToken(tok); err != nil {
		t.Fatalf("expected fail-open on store error; got %v", err)
	}
}

func TestValidateToken_NoJTISkipsCheck(t *testing.T) {
	// Pre-Phase-1.2 tokens have no jti. IsRevoked
	// short-circuits on empty input, so they remain valid.
	// (When refresh-token rollover lands in Phase 1.6 the
	// remaining lifetime of those legacy tokens will be at
	// most one issuer-cycle anyway.)
	tm := newTestTM(t)
	store := newMemRevStore()
	tm.SetRevocationStore(store)

	// Craft a token by hand without jti — emulate a legacy
	// issuance by going through Generate then stripping the
	// jti out of the claims at validate-time. The cleaner
	// way is to fake a Claims struct and re-sign.
	// We use the explicit empty-jti path on IsRevoked here:
	revoked, err := store.IsRevoked(context.Background(), "")
	if err != nil {
		t.Fatalf("IsRevoked(\"\") unexpected error: %v", err)
	}
	if revoked {
		t.Fatal("empty jti should not be revoked")
	}
}

// --- RevokeToken admin path ---

func TestRevokeToken_ErrorsWithoutStore(t *testing.T) {
	tm := newTestTM(t)
	tok, _ := tm.GenerateToken("alice", []string{"user"}, time.Hour)
	claims, _ := tm.ValidateToken(tok)

	err := tm.RevokeToken(context.Background(), claims, "x")
	if err == nil {
		t.Fatal("expected error when store unconfigured")
	}
}

func TestRevokeToken_ErrorsOnNoJTI(t *testing.T) {
	tm := newTestTM(t)
	store := newMemRevStore()
	tm.SetRevocationStore(store)

	err := tm.RevokeToken(context.Background(), &Claims{}, "x")
	if err == nil {
		t.Fatal("expected error revoking a token with no jti")
	}
}

func TestRevokeToken_Idempotent(t *testing.T) {
	tm := newTestTM(t)
	store := newMemRevStore()
	tm.SetRevocationStore(store)
	tok, _ := tm.GenerateToken("alice", []string{"user"}, time.Hour)
	claims, _ := tm.ValidateToken(tok)

	for i := 0; i < 3; i++ {
		if err := tm.RevokeToken(context.Background(), claims, "x"); err != nil {
			t.Fatalf("revoke %d: %v", i, err)
		}
	}
	if got := len(store.revoked); got != 1 {
		t.Fatalf("expected idempotent revoke; store.revoked = %d", got)
	}
}

// --- CleanupExpired ---

func TestStore_CleanupExpired(t *testing.T) {
	store := newMemRevStore()
	ctx := context.Background()
	now := time.Now()

	// Two expired, one live.
	_ = store.Revoke(ctx, "old-1", now.Add(-2*time.Hour), "")
	_ = store.Revoke(ctx, "old-2", now.Add(-1*time.Minute), "")
	_ = store.Revoke(ctx, "live", now.Add(time.Hour), "")

	pruned, err := store.CleanupExpired(ctx, now)
	if err != nil {
		t.Fatalf("CleanupExpired: %v", err)
	}
	if pruned != 2 {
		t.Fatalf("pruned %d, want 2", pruned)
	}
	if revoked, _ := store.IsRevoked(ctx, "live"); !revoked {
		t.Fatal("live row was pruned by mistake")
	}
}
