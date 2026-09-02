package auth

import (
	"testing"
	"time"
)

func newTestTokenManager(t *testing.T) *TokenManager {
	t.Helper()
	tm, err := NewTokenManager("test-secret-must-be-at-least-32-bytes-long-ok", "test-issuer")
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	return tm
}

func TestActDepth(t *testing.T) {
	cases := []struct {
		name string
		a    *Actor
		want int
	}{
		{"nil", nil, 0},
		{"single", &Actor{Subject: "human"}, 1},
		{"nested two", &Actor{Subject: "agent-relay", Act: &Actor{Subject: "human"}}, 2},
		{
			"nested three",
			&Actor{Subject: "agent-c", Act: &Actor{Subject: "agent-b", Act: &Actor{Subject: "human"}}},
			3,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := actDepth(tc.a); got != tc.want {
				t.Errorf("actDepth(%+v) = %d, want %d", tc.a, got, tc.want)
			}
		})
	}
}

func chainOfDepth(n int) *Actor {
	var a *Actor
	for i := 0; i < n; i++ {
		a = &Actor{Subject: "actor", Act: a}
	}
	return a
}

func TestValidateActDepth(t *testing.T) {
	if err := validateActDepth(nil); err != nil {
		t.Errorf("nil act should always pass, got %v", err)
	}
	if err := validateActDepth(chainOfDepth(MaxActDepth)); err != nil {
		t.Errorf("chain at exactly MaxActDepth should pass, got %v", err)
	}
	if err := validateActDepth(chainOfDepth(MaxActDepth + 1)); err == nil {
		t.Error("chain exceeding MaxActDepth should be rejected")
	}
}

// TestGenerateDelegatedToken_RoundTrip covers a nested (two-hop) chain
// surviving mint -> sign -> parse -> validate intact.
func TestGenerateDelegatedToken_RoundTrip(t *testing.T) {
	tm := newTestTokenManager(t)
	act := &Actor{Subject: "agent-relay-agent", Act: &Actor{Subject: "alice"}}

	tok, err := tm.GenerateDelegatedToken("agent-hello-agent", nil, time.Hour, act)
	if err != nil {
		t.Fatalf("GenerateDelegatedToken: %v", err)
	}
	claims, err := tm.ValidateToken(tok)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.Act == nil {
		t.Fatal("claims.Act = nil, want the minted chain")
	}
	if claims.Act.Subject != "agent-relay-agent" {
		t.Errorf("claims.Act.Subject = %q, want agent-relay-agent", claims.Act.Subject)
	}
	if claims.Act.Act == nil || claims.Act.Act.Subject != "alice" {
		t.Errorf("claims.Act.Act = %+v, want {Subject: alice}", claims.Act.Act)
	}
}

// TestGenerateToken_LeavesActUnset is the backward-compat AC: absence of a
// delegation claim remains valid and reports as unattributed — every
// pre-1677 token, and every token minted via the ordinary GenerateToken/
// GenerateAccessToken/GenerateRefreshToken paths that don't pass one.
func TestGenerateToken_LeavesActUnset(t *testing.T) {
	tm := newTestTokenManager(t)
	tok, err := tm.GenerateToken("alice", []string{"user"}, time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	claims, err := tm.ValidateToken(tok)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.Act != nil {
		t.Errorf("claims.Act = %+v, want nil for a token minted without delegation", claims.Act)
	}
}

// TestGenerateDelegatedToken_RejectsOverDeepChain is the mint-time half of
// the depth-bound AC.
func TestGenerateDelegatedToken_RejectsOverDeepChain(t *testing.T) {
	tm := newTestTokenManager(t)
	_, err := tm.GenerateDelegatedToken("agent-x", nil, time.Hour, chainOfDepth(MaxActDepth+1))
	if err == nil {
		t.Fatal("expected GenerateDelegatedToken to refuse an over-deep chain")
	}
}

// TestValidateToken_RejectsOverDeepChain is the validate-time half —
// defense in depth against a token minted by some future/other path that
// forgets the mint-time check. Constructs the over-deep token directly
// (bypassing GenerateDelegatedToken's own guard) to simulate that case.
func TestValidateToken_RejectsOverDeepChain(t *testing.T) {
	tm := newTestTokenManager(t)
	tok, err := tm.generate("agent-x", nil, nil, "", time.Hour, chainOfDepth(MaxActDepth+1))
	if err != nil {
		t.Fatalf("setup: generate: %v", err)
	}
	if _, err := tm.ValidateToken(tok); err == nil {
		t.Fatal("expected ValidateToken to reject an over-deep delegation chain")
	}
}
