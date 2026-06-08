package server

import (
	"strings"
	"sync"
	"testing"
)

// Phase 3.1 follow-up — image-digest-pinning tests.

// resetDigestOnce flips imageDigestOnce back to its zero
// state so each test can drive a fresh env-var read. Tests
// run sequentially via t.Setenv inside this package, so
// no concurrent-init race.
func resetDigestOnce(t *testing.T) {
	t.Helper()
	imageDigestOnce = sync.Once{}
	imageDigestReq = false
}

func TestExtractImageDigest(t *testing.T) {
	cases := map[string]struct {
		want   string
		wantOK bool
	}{
		"ubuntu:22.04@sha256:abc":             {"sha256:abc", true},
		"ubuntu:22.04":                        {"", false},
		"":                                    {"", false},
		"images:ubuntu/22.04@sha256:deadbeef": {"sha256:deadbeef", true},
		// Multi-@ is unusual but the last `@` wins (matches
		// OCI reference semantics for digest pinning).
		"a@b@sha256:xyz": {"sha256:xyz", true},
	}
	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			got, ok := extractImageDigest(in)
			if got != want.want || ok != want.wantOK {
				t.Fatalf("extractImageDigest(%q) = (%q,%v); want (%q,%v)",
					in, got, ok, want.want, want.wantOK)
			}
		})
	}
}

// Valid digest passes regardless of env value (the env
// only gates the requirement; never the format).
func TestValidateImageDigest_DisabledByDefault(t *testing.T) {
	resetDigestOnce(t)
	t.Setenv(requireImageDigestEnv, "")
	// No digest at all — accepted because enforcement off.
	if err := validateImageDigest("ubuntu:22.04"); err != nil {
		t.Fatalf("unenforced: should pass; got %v", err)
	}
}

func TestValidateImageDigest_EnforcedRejectsBareTag(t *testing.T) {
	resetDigestOnce(t)
	t.Setenv(requireImageDigestEnv, "true")

	err := validateImageDigest("ubuntu:22.04")
	if err == nil {
		t.Fatal("bare tag should be rejected when enforcement is on")
	}
	if !strings.Contains(err.Error(), "missing a digest") {
		t.Fatalf("error should mention missing digest; got %v", err)
	}
}

func TestValidateImageDigest_EnforcedAcceptsValidDigest(t *testing.T) {
	resetDigestOnce(t)
	t.Setenv(requireImageDigestEnv, "true")

	good := "ubuntu:22.04@sha256:" + strings.Repeat("a", 64)
	if err := validateImageDigest(good); err != nil {
		t.Fatalf("valid digest: %v", err)
	}
}

func TestValidateImageDigest_RejectsTooShortDigest(t *testing.T) {
	resetDigestOnce(t)
	t.Setenv(requireImageDigestEnv, "true")

	short := "ubuntu:22.04@sha256:abc"
	err := validateImageDigest(short)
	if err == nil {
		t.Fatal("short digest should be rejected")
	}
	if !strings.Contains(err.Error(), "64 lowercase hex") {
		t.Fatalf("error should explain expected shape; got %v", err)
	}
}

func TestValidateImageDigest_RejectsUppercaseHex(t *testing.T) {
	// OCI digests are spec'd as lowercase; uppercase tokens
	// are technically a different reference and reject is
	// the safer call.
	resetDigestOnce(t)
	t.Setenv(requireImageDigestEnv, "true")

	mixed := "ubuntu:22.04@sha256:" + strings.Repeat("A", 64)
	if err := validateImageDigest(mixed); err == nil {
		t.Fatal("uppercase hex should be rejected")
	}
}

func TestValidateImageDigest_RejectsWrongAlgo(t *testing.T) {
	resetDigestOnce(t)
	t.Setenv(requireImageDigestEnv, "true")

	// sha512 is fine in OCI but we accept only sha256 to
	// avoid the algorithm-confusion surface that bit JWTs
	// (the daemon validates one shape end-to-end).
	wrong := "ubuntu:22.04@sha512:" + strings.Repeat("a", 128)
	if err := validateImageDigest(wrong); err == nil {
		t.Fatal("sha512 digest should be rejected (sha256-only policy)")
	}
}

func TestValidateImageDigest_EnforcedAllowsEmptyImage(t *testing.T) {
	// Empty req.Image means "use the daemon's default".
	// The default substitution happens later in the
	// pipeline; gating it here would block tenants who
	// rely on the os_type-driven default.
	resetDigestOnce(t)
	t.Setenv(requireImageDigestEnv, "true")

	if err := validateImageDigest(""); err != nil {
		t.Fatalf("empty image with enforcement on should pass; got %v", err)
	}
}

func TestValidateImageDigest_UnrecognizedEnvLeavesOff(t *testing.T) {
	resetDigestOnce(t)
	t.Setenv(requireImageDigestEnv, "maybe")

	// Should not enforce — fail-open on bad config so a
	// typo doesn't silently lock out every tenant.
	if err := validateImageDigest("ubuntu:22.04"); err != nil {
		t.Fatalf("unrecognized env should leave enforcement off; got %v", err)
	}
}
