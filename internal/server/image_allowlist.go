package server

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
)

// Image-registry allowlist for CreateContainer (audit B-HIGH-1).
//
// `req.Image` flows unmodified to the Incus runtime, which will
// pull whatever URL or remote: prefix it sees. Without a guard,
// a caller can:
//
//   - Pull from a typosquatted Linux Containers mirror that
//     swaps in malicious base images.
//   - Use a `https://internal-service.example/...` URL as an
//     SSRF probe (the daemon's network position lets it reach
//     internal services the caller can't).
//   - Pull oversized junk to exhaust the host's disk.
//
// CONTAINARIUM_ALLOWED_IMAGE_REGISTRIES is a comma-separated list
// of registry prefixes the daemon will accept. Examples:
//
//   ubuntu,images,incus              # the three Linux Containers remotes
//   ubuntu,docker:registry.example   # only ubuntu + one private registry
//
// Empty value means "accept anything" — pre-Phase-3 behavior. The
// daemon logs a WARNING at startup so operators see the gap.
//
// Bare image names like "ubuntu/22.04" with no `:` are treated as
// implicitly belonging to the default "ubuntu" remote in Incus,
// so they pass when "ubuntu" is in the allowlist.

const allowedImageRegistriesEnv = "CONTAINARIUM_ALLOWED_IMAGE_REGISTRIES"

var (
	imageAllowlistOnce sync.Once
	imageAllowlist     []string
	imageAllowlistAll  bool
)

func loadImageAllowlist() ([]string, bool) {
	imageAllowlistOnce.Do(func() {
		raw := os.Getenv(allowedImageRegistriesEnv)
		if raw == "" {
			imageAllowlistAll = true
			log.Printf("WARNING: %s is unset — CreateContainer accepts any image URL (audit B-HIGH-1 still open)", allowedImageRegistriesEnv)
			return
		}
		for _, p := range strings.Split(raw, ",") {
			if p = strings.TrimSpace(p); p != "" {
				imageAllowlist = append(imageAllowlist, p)
			}
		}
		log.Printf("[image-allowlist] CreateContainer restricted to registries: %v", imageAllowlist)
	})
	return imageAllowlist, imageAllowlistAll
}

// validateImageRegistry returns nil if `image` matches the
// allowlist or no allowlist is configured. Returns a descriptive
// error otherwise — caller maps it to InvalidArgument.
func validateImageRegistry(image string) error {
	allowlist, allowAll := loadImageAllowlist()
	if allowAll {
		return nil
	}
	if image == "" {
		// Empty image is allowed — the manager substitutes a
		// default based on OSType. Allowlist check doesn't apply
		// because nothing was requested.
		return nil
	}

	// Extract the registry prefix: everything before the first `:`
	// for `prefix:tag`, or for a URL the scheme+host.
	prefix := imageRegistryPrefix(image)
	for _, allowed := range allowlist {
		if prefix == allowed || strings.HasPrefix(prefix, allowed) {
			return nil
		}
	}
	return fmt.Errorf("image %q is not in the allowed-registries list %v; ask an operator to add the registry to %s", image, allowlist, allowedImageRegistriesEnv)
}

// imageRegistryPrefix returns the registry-identifying prefix
// used to match against the allowlist. For Incus-style remotes
// like "ubuntu:22.04" it's "ubuntu". For full URLs it's
// "scheme://host". For bare names with no colon and no `/`
// (e.g. "ubuntu", "22.04") it's "ubuntu" — Incus's default
// remote for un-prefixed images. For path-style references
// ("images/ubuntu/22.04") it's the empty string, which the
// allowlist treats as a non-match → reject.
func imageRegistryPrefix(image string) string {
	if image == "" {
		return ""
	}
	// Full URL — scheme://host/path
	if i := strings.Index(image, "://"); i >= 0 {
		rest := image[i+3:]
		if j := strings.IndexAny(rest, "/?"); j >= 0 {
			return image[:i+3+j]
		}
		return image
	}
	// Incus-style `remote:name`
	if i := strings.Index(image, ":"); i >= 0 {
		return image[:i]
	}
	// No remote prefix — treat as the default "ubuntu" remote.
	// Operators who want to reject these should leave "ubuntu"
	// out of the allowlist; users will need to be explicit.
	// A `/` indicates a path-style reference (e.g.
	// "images/ubuntu/22.04") that doesn't match any single
	// remote — return empty to force rejection.
	if !strings.Contains(image, "/") {
		return "ubuntu"
	}
	return ""
}
