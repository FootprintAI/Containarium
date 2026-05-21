package server

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"
)

// Phase 3.1 follow-up — image digest pinning (audit
// B-HIGH-1, supply-chain hardening half).
//
// The allowlist (image_allowlist.go) keeps the daemon from
// pulling images from arbitrary registries. Digest pinning
// adds a second axis: even within an allowed registry, the
// operator forces every CreateContainer request to name
// the EXACT image bytes — not "latest", not a tag that
// could be re-pushed.
//
// Wire shape: operator sets
//
//   CONTAINARIUM_REQUIRE_IMAGE_DIGEST=true
//
// and from that point on the daemon refuses any image
// reference that doesn't carry `@sha256:<64-hex>`. The
// daemon doesn't verify the digest against the registry's
// content (that requires Incus-side support and is the
// "real" half of digest pinning, tracked separately) — but
// it does force the operator to write a specific digest
// down. The supply-chain attacker who hopes a tagged image
// will quietly be re-pulled with malicious bytes is denied
// the ambiguity they need.
//
// Default is off — turning enforcement on is a flag flip,
// not a code change.

const requireImageDigestEnv = "CONTAINARIUM_REQUIRE_IMAGE_DIGEST"

var (
	imageDigestOnce sync.Once
	imageDigestReq  bool

	// sha256Pattern matches a single base64-encoded SHA-256
	// hex digest as it appears in an OCI image reference:
	// 64 lowercase hex chars after a literal `sha256:`.
	sha256Pattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
)

func loadDigestRequired() bool {
	imageDigestOnce.Do(func() {
		raw := strings.TrimSpace(os.Getenv(requireImageDigestEnv))
		if raw == "" {
			imageDigestReq = false
			return
		}
		switch strings.ToLower(raw) {
		case "1", "true", "yes", "on":
			imageDigestReq = true
			log.Printf("[image-digest] required: every CreateContainer must name a `@sha256:<64hex>` digest (audit B-HIGH-1 follow-up)")
		default:
			imageDigestReq = false
			log.Printf("WARNING: %s=%q is unrecognized (expected 1/true/yes/on); digest pinning STAYS OFF", requireImageDigestEnv, raw)
		}
	})
	return imageDigestReq
}

// validateImageDigest returns nil if the image reference
// carries a syntactically valid `@sha256:<64hex>` digest
// suffix, or if digest enforcement is disabled. Returns a
// descriptive error otherwise — caller maps to
// InvalidArgument.
//
// Empty image is allowed when enforcement is on: the
// daemon substitutes a known default later, and the
// allowlist check already runs against the empty input
// separately. Operators who want to forbid the default-
// substitution path should set --os-type=... at the
// callsite, not gate it here.
func validateImageDigest(image string) error {
	if !loadDigestRequired() {
		return nil
	}
	if image == "" {
		return nil
	}
	digest, ok := extractImageDigest(image)
	if !ok {
		return fmt.Errorf("image %q is missing a digest; %s=true requires every image reference to end with `@sha256:<64-lowercase-hex>` so the exact image bytes are pinned", image, requireImageDigestEnv)
	}
	if !sha256Pattern.MatchString(digest) {
		return fmt.Errorf("image %q has an invalid digest %q; expected `sha256:` + 64 lowercase hex chars", image, digest)
	}
	return nil
}

// extractImageDigest splits an OCI image reference at the
// `@` separator and returns the digest part. Returns
// (digest, true) when an `@` is present; (empty, false)
// otherwise. Does NOT validate the digest format — call
// sha256Pattern.MatchString on the result.
func extractImageDigest(image string) (string, bool) {
	i := strings.LastIndex(image, "@")
	if i < 0 {
		return "", false
	}
	return image[i+1:], true
}
