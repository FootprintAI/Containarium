package server

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// Phase 3.1 Phase-B — registry-side image digest
// verification. Audit B-HIGH-1 (deeper half). Pairs with
// the operator-enforced @sha256: syntax check in
// image_digest.go.
//
// When CONTAINARIUM_VERIFY_IMAGE_DIGEST=true is set, every
// CreateContainer request that carries a `@sha256:...`
// reference is checked against the registry's published
// digests for that alias. A miss → FailedPrecondition. A
// match → pull proceeds normally.
//
// See docs/security/IMAGE-DIGEST-VERIFY-DESIGN.md for the
// full design.
//
// What this catches:
//   - Allowlisted-registry MITM serving different bytes.
//   - Bytes-vs-declared-digest divergence.
//   - Stale operator pin (the registry has rotated the
//     image and the operator's digest no longer resolves).
//
// What this does NOT catch:
//   - Cache tampering between pull and start. Phase C
//     covers that with a post-pull local-store fingerprint
//     check.
//   - Registry-account compromise where the attacker has
//     pushed bytes AND can update the index to match. Only
//     out-of-band digest custody (release notes / signed
//     records) catches that.
//
// Default is OFF. Operators opt in once they've seeded
// known-good digests for their pinned images.

const verifyImageDigestEnv = "CONTAINARIUM_VERIFY_IMAGE_DIGEST"

var (
	verifyDigestOnce sync.Once
	verifyDigestOn   bool

	// Resolver cached at first use so each CreateContainer
	// reuses the same http.Client (TLS handshake pool stays
	// warm). Caching of the index itself is a Phase B+
	// follow-up — premature caching hides correctness
	// bugs.
	verifyResolverOnce sync.Once
	verifyResolver     *incus.StreamsResolver
)

func loadDigestVerificationOn() bool {
	verifyDigestOnce.Do(func() {
		raw := strings.TrimSpace(os.Getenv(verifyImageDigestEnv))
		if raw == "" {
			verifyDigestOn = false
			return
		}
		switch strings.ToLower(raw) {
		case "1", "true", "yes", "on":
			verifyDigestOn = true
			log.Printf("[image-digest] registry verification ENABLED: every `@sha256:` digest is checked against the registry's published index before pull (audit B-HIGH-1 Phase B)")
			// Sanity check the operator's two-gate
			// configuration. VERIFY only kicks in for
			// requests that carry `@sha256:` — without
			// REQUIRE, undigested requests bypass the
			// gate entirely. Operators who enabled VERIFY
			// thinking they'd covered both surfaces get a
			// startup warning rather than silently-
			// degraded protection. The configuration is
			// still ALLOWED (an operator may legitimately
			// want "verify when pinned, but pinning is
			// optional"), just loudly flagged.
			if !loadDigestRequired() {
				log.Printf("WARNING: %s=true but %s is OFF; undigested CreateContainer requests will SKIP verification. Set %s=true to make pinning mandatory.",
					verifyImageDigestEnv, requireImageDigestEnv, requireImageDigestEnv)
			}
		default:
			verifyDigestOn = false
			log.Printf("WARNING: %s=%q is unrecognized (expected 1/true/yes/on); registry verification STAYS OFF", verifyImageDigestEnv, raw)
		}
	})
	return verifyDigestOn
}

func resolver() *incus.StreamsResolver {
	verifyResolverOnce.Do(func() {
		// 10s matches the design doc; covers a slow
		// simplestreams index without keeping the
		// CreateContainer call hung indefinitely on a
		// dead registry.
		verifyResolver = incus.NewStreamsResolver(10 * time.Second)
	})
	return verifyResolver
}

// verifyImageDigestAgainstRegistry is the Phase B gate.
// Returns nil when:
//   - verification is OFF (env unset / false), OR
//   - the image string has no `@sha256:` suffix (the
//     syntax gate in validateImageDigest will have
//     rejected if Phase 2 enforcement was on; otherwise
//     the operator chose not to pin and we don't override
//     that), OR
//   - the image string has no resolvable server (local
//     alias, no registry to query), OR
//   - the operator-supplied digest appears in the set
//     published by the registry for that alias.
//
// Returns a non-nil error when the digest is present, the
// server is resolvable, and the registry's published set
// does NOT contain the requested digest (or the resolver
// fails outright).
func verifyImageDigestAgainstRegistry(ctx context.Context, image string) error {
	if !loadDigestVerificationOn() {
		return nil
	}
	digest, ok := extractImageDigest(image)
	if !ok {
		// No digest supplied → nothing to verify. The
		// syntax-required env handles "must have digest";
		// this env handles "the digest you supplied
		// matches the registry."
		return nil
	}
	server, alias := splitServerAlias(image)
	if server == "" {
		// Local alias — there's no registry to query.
		// Skip with a debug log; legitimate use-case for
		// the inproc test images Containarium pre-populates.
		log.Printf("[image-digest] image %q has no resolvable registry server; skipping registry verification", image)
		return nil
	}

	published, err := resolver().ResolveImageDigests(ctx, server, alias)
	if err != nil {
		return fmt.Errorf("registry digest verification: fetch %s index for %q: %w", server, alias, err)
	}
	if len(published) == 0 {
		return fmt.Errorf("registry digest verification: alias %q not found in %s/streams/v1/images.json (typo? recently-removed product? stale registry?)", alias, server)
	}
	if !incus.DigestMatchesSet(digest, published) {
		return fmt.Errorf("registry digest verification: image %q declares %s but the registry at %s publishes a different set of digests for alias %q (allowlisted-registry MITM, stale operator pin, or bytes-vs-declared-digest divergence — refusing pull)",
			image, digest, server, alias)
	}
	return nil
}

// verifyImageDigestPostPull is the Phase C defense-in-
// depth check (audit B-HIGH-1, deeper still). After the
// container has been created, read the Incus-computed
// fingerprint of the image actually used and assert it
// matches the digest the operator declared.
//
// Catches:
//   - Local image-store tampering between the registry
//     pull and the container start (an attacker who can
//     write to Incus's image cache).
//   - Pre-pull-verifier index out-of-sync with the actual
//     pull (e.g., a TTL window where the index was
//     refreshed but a parallel pull caught the old bytes).
//
// Skip semantics match Phase B:
//   - Verification off → nil.
//   - No `@sha256:` suffix → nil.
//   - Image is a local alias (Incus might not have a
//     fingerprint) → nil with a debug log.
//
// On mismatch, the caller is expected to delete the
// just-created container — leaving it running would
// preserve the attacker's payload. Container deletion is
// caller-side so this helper stays read-only.
//
// The local fingerprint is one specific SHA-256 (the
// archive Incus pulled). The operator's digest can match
// any of the index's published item digests; if the
// fingerprint isn't directly equal to the operator's
// digest, we re-resolve through the registry index and
// check membership — that covers the case where the
// operator picked the rootfs digest but Incus stored the
// combined-archive fingerprint.
func verifyImageDigestPostPull(ctx context.Context, image, containerName string, fpReader interface {
	GetContainerImageFingerprint(string) (string, error)
}) error {
	if !loadDigestVerificationOn() {
		return nil
	}
	declared, ok := extractImageDigest(image)
	if !ok {
		return nil
	}
	server, alias := splitServerAlias(image)
	if server == "" {
		log.Printf("[image-digest] post-pull verification skipped for %q (local alias)", image)
		return nil
	}

	fingerprint, err := fpReader.GetContainerImageFingerprint(containerName)
	if err != nil {
		return fmt.Errorf("post-pull digest verification: read fingerprint for %q: %w", containerName, err)
	}
	if fingerprint == "" {
		// Incus didn't record a base image — atypical but
		// possible if the create path bypassed simplestreams
		// (e.g., a copy-from-snapshot path). Surface as a
		// log line but don't fail; nothing to compare
		// against.
		log.Printf("[image-digest] post-pull verification: container %q has no volatile.base_image; skipping", containerName)
		return nil
	}

	// Fast path: Incus fingerprint matches the declared
	// digest directly.
	if incus.DigestMatchesSet(declared, []string{fingerprint}) {
		return nil
	}

	// Slow path: re-resolve through the registry index.
	// The operator's digest might match a different item
	// type than the one Incus chose to store. Both must
	// appear in the SAME product's index entry — if they
	// do, that's a legitimate "two faces of the same
	// image" match.
	published, err := resolver().ResolveImageDigests(ctx, server, alias)
	if err != nil {
		return fmt.Errorf("post-pull digest verification: re-resolve %s/%s: %w", server, alias, err)
	}
	declaredMatches := incus.DigestMatchesSet(declared, published)
	fingerprintMatches := incus.DigestMatchesSet(fingerprint, published)
	if declaredMatches && fingerprintMatches {
		// Both are valid items for the same alias —
		// "two faces of the same image." Accept.
		return nil
	}
	return fmt.Errorf("post-pull digest verification: container %q was created from fingerprint %s, but operator declared %s and the registry's current index for alias %q does not co-publish both digests (local-cache tampering, index race, or stale operator pin)",
		containerName, fingerprint, declared, alias)
}

// splitServerAlias maps an image reference to its
// (server URL, alias) tuple based on the same prefix
// mapping `pkg/core/incus.parseImageSource` uses. We
// keep this small helper local — the mapping is policy
// (which 3rd-party registries we trust), and policy
// belongs in the server layer, not the generic incus
// client.
//
// Returns ("", "") when the image is a local alias (no
// colon, no slash) — verification skips those.
func splitServerAlias(image string) (server, alias string) {
	// Strip the @sha256:... suffix before parsing so the
	// digest doesn't contaminate the alias.
	if at := strings.LastIndex(image, "@"); at >= 0 {
		image = image[:at]
	}
	image = strings.TrimSpace(image)
	if image == "" {
		return "", ""
	}
	if strings.Contains(image, ":") {
		parts := strings.SplitN(image, ":", 2)
		remote, rest := parts[0], parts[1]
		switch remote {
		case "images":
			return "https://images.linuxcontainers.org", rest
		case "ubuntu":
			return "https://cloud-images.ubuntu.com/releases", rest
		case "ubuntu-daily":
			return "https://cloud-images.ubuntu.com/daily", rest
		default:
			// Unknown remote prefix — treat as local
			// alias and skip verification.
			return "", ""
		}
	}
	if strings.Contains(image, "/") {
		// Bare "ubuntu/24.04" defaults to the
		// linuxcontainers.org remote, matching
		// parseImageSource's behavior.
		return "https://images.linuxcontainers.org", image
	}
	// Bare token like "ubuntu" — local alias; nothing to
	// verify against.
	return "", ""
}
