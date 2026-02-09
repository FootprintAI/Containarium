package auth

import (
	"os"
	"testing"
	"time"
)

func TestNewTokenManager(t *testing.T) {
	tm := NewTokenManager("test-secret", "test-issuer")

	if tm == nil {
		t.Fatal("NewTokenManager returned nil")
	}

	if tm.maxTokenExpiry != DefaultMaxTokenExpiry {
		t.Errorf("expected maxTokenExpiry to be %v, got %v", DefaultMaxTokenExpiry, tm.maxTokenExpiry)
	}
}

func TestNewTokenManager_WithEnvOverride(t *testing.T) {
	// Set environment variable to 48 hours
	os.Setenv("CONTAINARIUM_MAX_TOKEN_EXPIRY_HOURS", "48")
	defer os.Unsetenv("CONTAINARIUM_MAX_TOKEN_EXPIRY_HOURS")

	tm := NewTokenManager("test-secret", "test-issuer")

	expected := 48 * time.Hour
	if tm.maxTokenExpiry != expected {
		t.Errorf("expected maxTokenExpiry to be %v, got %v", expected, tm.maxTokenExpiry)
	}
}

func TestGenerateToken_EnforcesMaxExpiry(t *testing.T) {
	tm := NewTokenManager("test-secret", "test-issuer")

	tests := []struct {
		name           string
		requestedExpiry time.Duration
		expectClamped  bool
	}{
		{
			name:           "zero expiry should be clamped to max",
			requestedExpiry: 0,
			expectClamped:  true,
		},
		{
			name:           "negative expiry should be clamped to max",
			requestedExpiry: -1 * time.Hour,
			expectClamped:  true,
		},
		{
			name:           "expiry exceeding max should be clamped",
			requestedExpiry: 365 * 24 * time.Hour, // 1 year
			expectClamped:  true,
		},
		{
			name:           "valid expiry within max should be allowed",
			requestedExpiry: 24 * time.Hour,
			expectClamped:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenStr, err := tm.GenerateToken("testuser", []string{"admin"}, tt.requestedExpiry)
			if err != nil {
				t.Fatalf("GenerateToken failed: %v", err)
			}

			// Validate the token and check expiry
			claims, err := tm.ValidateToken(tokenStr)
			if err != nil {
				t.Fatalf("ValidateToken failed: %v", err)
			}

			// Token should always have an expiry (no nil ExpiresAt)
			if claims.ExpiresAt == nil {
				t.Error("SECURITY: Token has no expiry set - this should never happen")
			}

			// Calculate actual expiry duration
			actualExpiry := time.Until(claims.ExpiresAt.Time)

			if tt.expectClamped {
				// Should be close to max expiry (within a few seconds for test execution time)
				expectedMax := tm.maxTokenExpiry
				tolerance := 5 * time.Second
				if actualExpiry > expectedMax+tolerance || actualExpiry < expectedMax-tolerance {
					t.Errorf("expected expiry close to %v, got %v", expectedMax, actualExpiry)
				}
			} else {
				// Should be close to requested expiry
				tolerance := 5 * time.Second
				if actualExpiry > tt.requestedExpiry+tolerance || actualExpiry < tt.requestedExpiry-tolerance {
					t.Errorf("expected expiry close to %v, got %v", tt.requestedExpiry, actualExpiry)
				}
			}
		})
	}
}

func TestGenerateToken_NoNonExpiringTokens(t *testing.T) {
	// This is a critical security test - ensure we never create tokens without expiry
	tm := NewTokenManager("test-secret", "test-issuer")

	// Try various ways to create a "non-expiring" token
	testCases := []time.Duration{
		0,
		-1,
		-1 * time.Hour,
		-24 * time.Hour,
	}

	for _, expiry := range testCases {
		tokenStr, err := tm.GenerateToken("testuser", []string{"admin"}, expiry)
		if err != nil {
			t.Fatalf("GenerateToken failed for expiry %v: %v", expiry, err)
		}

		claims, err := tm.ValidateToken(tokenStr)
		if err != nil {
			t.Fatalf("ValidateToken failed: %v", err)
		}

		if claims.ExpiresAt == nil {
			t.Errorf("SECURITY VIOLATION: Token with requested expiry %v has no expiry set", expiry)
		}
	}
}

func TestValidateToken_RejectsExpiredTokens(t *testing.T) {
	tm := NewTokenManager("test-secret", "test-issuer")

	// Generate a token with very short expiry
	tokenStr, err := tm.GenerateToken("testuser", []string{"admin"}, 1*time.Millisecond)
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	// Wait for it to expire
	time.Sleep(10 * time.Millisecond)

	// Should fail validation
	_, err = tm.ValidateToken(tokenStr)
	if err == nil {
		t.Error("ValidateToken should reject expired tokens")
	}
}

func TestValidateToken_RejectsInvalidTokens(t *testing.T) {
	tm := NewTokenManager("test-secret", "test-issuer")

	invalidTokens := []struct {
		name  string
		token string
	}{
		{"empty token", ""},
		{"garbage", "not-a-token"},
		{"malformed JWT", "eyJhbGciOiJIUzI1NiJ9.garbage.garbage"},
	}

	for _, tt := range invalidTokens {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tm.ValidateToken(tt.token)
			if err == nil {
				t.Errorf("ValidateToken should reject %s", tt.name)
			}
		})
	}
}

func TestValidateToken_RejectsWrongSecret(t *testing.T) {
	tm1 := NewTokenManager("secret-1", "test-issuer")
	tm2 := NewTokenManager("secret-2", "test-issuer")

	// Generate token with tm1
	tokenStr, err := tm1.GenerateToken("testuser", []string{"admin"}, 1*time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	// Try to validate with tm2 (different secret)
	_, err = tm2.ValidateToken(tokenStr)
	if err == nil {
		t.Error("ValidateToken should reject tokens signed with different secret")
	}
}

func TestTokenClaims(t *testing.T) {
	tm := NewTokenManager("test-secret", "test-issuer")

	username := "testuser"
	roles := []string{"admin", "user"}

	tokenStr, err := tm.GenerateToken(username, roles, 1*time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	claims, err := tm.ValidateToken(tokenStr)
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}

	if claims.Username != username {
		t.Errorf("expected username %s, got %s", username, claims.Username)
	}

	if len(claims.Roles) != len(roles) {
		t.Errorf("expected %d roles, got %d", len(roles), len(claims.Roles))
	}

	for i, role := range roles {
		if claims.Roles[i] != role {
			t.Errorf("expected role %s at index %d, got %s", role, i, claims.Roles[i])
		}
	}

	if claims.Issuer != "test-issuer" {
		t.Errorf("expected issuer 'test-issuer', got %s", claims.Issuer)
	}
}
