package auth

import (
	"regexp"
	"strings"
	"testing"
)

const testDeriveSecret = "a-test-jwt-signing-key-of-sufficient-length-0123456789"

func newDeriveManager(t *testing.T, key string) *TokenManager {
	t.Helper()
	tm, err := NewTokenManager(key, "containarium-test")
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	return tm
}

// A derived secret must be stable for one (purpose, id) — the daemon
// recomputes it after a restart rather than storing it — and must differ for
// every other input, including inputs that concatenate to the same string.
// That last property is what stops one box's secret from opening another's
// door, which is the whole point of #2125's per-box credential.
func TestDeriveSharedSecret_StableAndSeparated(t *testing.T) {
	tm := newDeriveManager(t, testDeriveSecret)

	got := tm.DeriveSharedSecret("containarium/a2a-box/v1", "hello-agent")
	if again := tm.DeriveSharedSecret("containarium/a2a-box/v1", "hello-agent"); again != got {
		t.Errorf("derivation is not deterministic: %q then %q", got, again)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(got) {
		t.Errorf("derived secret = %q, want 64 hex characters", got)
	}
	if strings.Contains(got, testDeriveSecret) {
		t.Error("derived secret contains the signing key")
	}

	distinct := map[string]string{
		"other box":            tm.DeriveSharedSecret("containarium/a2a-box/v1", "relay-agent"),
		"other purpose":        tm.DeriveSharedSecret("containarium/other/v1", "hello-agent"),
		"purpose/id ambiguity": tm.DeriveSharedSecret("containarium/a2a-box/v1hello", "-agent"),
		"other signing key":    newDeriveManager(t, testDeriveSecret+"-rotated").DeriveSharedSecret("containarium/a2a-box/v1", "hello-agent"),
	}
	for name, other := range distinct {
		if other == got {
			t.Errorf("%s derives the same secret %q", name, got)
		}
	}
}

// Empty inputs derive nothing rather than deriving a shared constant every
// caller would accept: callers treat "" as "no credential" and fail closed.
func TestDeriveSharedSecret_EmptyInputsDeriveNothing(t *testing.T) {
	tm := newDeriveManager(t, testDeriveSecret)
	for name, got := range map[string]string{
		"no purpose":  tm.DeriveSharedSecret("", "hello-agent"),
		"no id":       tm.DeriveSharedSecret("containarium/a2a-box/v1", ""),
		"nil manager": (*TokenManager)(nil).DeriveSharedSecret("containarium/a2a-box/v1", "hello-agent"),
	} {
		if got != "" {
			t.Errorf("%s: derived %q, want an empty secret", name, got)
		}
	}
}
