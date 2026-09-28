package secrets

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// The status verb on the ModelGatewayService (#1726) returns a fingerprint and
// nothing else key-derived. These tests pin the fingerprint's shape, because it
// is the one value the API is allowed to hand back and "how much of the key does
// it reveal" is the whole question.

func TestGatewayKeyFingerprint_IsTruncatedSHA256(t *testing.T) {
	const key = "sk-live-not-a-real-key"
	sum := sha256.Sum256([]byte(key))
	want := hex.EncodeToString(sum[:])[:gatewayKeyFingerprintHexLen]

	got := GatewayKeyFingerprint(key)
	if got != want {
		t.Errorf("GatewayKeyFingerprint = %q, want %q", got, want)
	}
	if len(got) != gatewayKeyFingerprintHexLen {
		t.Errorf("fingerprint length = %d, want %d", len(got), gatewayKeyFingerprintHexLen)
	}
}

func TestGatewayKeyFingerprint_RevealsNoKeyMaterial(t *testing.T) {
	const key = "sk-live-0123456789abcdef"
	fp := GatewayKeyFingerprint(key)
	// A fingerprint that contained a substring of the key would be a leak
	// dressed up as a checksum. Walk every window of the key long enough to be
	// meaningful and assert none of it survives into the fingerprint.
	for n := 4; n <= len(key); n++ {
		for i := 0; i+n <= len(key); i++ {
			if window := key[i : i+n]; len(window) >= 4 && contains(fp, window) {
				t.Fatalf("fingerprint %q contains key substring %q", fp, window)
			}
		}
	}
}

func TestGatewayKeyFingerprint_DiffersPerKeyAndIsStable(t *testing.T) {
	a := GatewayKeyFingerprint("sk-a")
	b := GatewayKeyFingerprint("sk-b")
	if a == b {
		t.Error("different keys produced the same fingerprint")
	}
	if a != GatewayKeyFingerprint("sk-a") {
		t.Error("fingerprint is not stable for the same key")
	}
}

func TestGatewayKeyFingerprint_EmptyKeyHasNoFingerprint(t *testing.T) {
	if got := GatewayKeyFingerprint(""); got != "" {
		t.Errorf("GatewayKeyFingerprint(\"\") = %q, want \"\" (an unset key has no fingerprint to show)", got)
	}
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
