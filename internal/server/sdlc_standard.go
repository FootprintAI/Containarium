package server

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/footprintai/containarium/pkg/core/sdlcskills"
	"github.com/footprintai/containarium/pkg/core/skills"
)

// sdlcBundleEnv names the pinned sdlc-skills.tar.gz (the release asset the
// boxes install) for the daemon to compose hosted skill prompts from (#2488).
const sdlcBundleEnv = "CONTAINARIUM_SDLC_SKILLS_BUNDLE"

// sdlcTrustedKeysEnv names a PEM file of public keys to trust INSTEAD of the
// ones built into this binary when verifying a signed skills release, for an
// operator who signs their own (the daemon-side twin of the installer's
// SDLC_SKILLS_TRUSTED_KEYS_FILE).
const sdlcTrustedKeysEnv = "CONTAINARIUM_SDLC_SKILLS_TRUSTED_KEYS_FILE"

// sdlcTrustedKeys returns the keys a signed skills release is verified with.
func sdlcTrustedKeys() (sdlcskills.Keyring, error) {
	path := strings.TrimSpace(os.Getenv(sdlcTrustedKeysEnv))
	if path == "" {
		return sdlcskills.TrustedKeys()
	}
	data, err := os.ReadFile(path) // #nosec G304 -- operator-configured key file
	if err != nil {
		return nil, fmt.Errorf("%s: %w", sdlcTrustedKeysEnv, err)
	}
	keys, err := sdlcskills.ParseKeyring(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", sdlcTrustedKeysEnv, err)
	}
	return keys, nil
}

// loadSDLCBundle is the production loader. A bundle with a manifest beside
// it (sdlc-skills.manifest, with its .sig) is a signed skills release and is
// verified by signature (docs/design/sdlc-skills-option-b.md); it is never
// retried against the lock. Otherwise the bundle is this release's asset and
// is verified against the pin compiled into this binary.
func loadSDLCBundle(path string) (skills.StandardProvider, error) {
	if _, err := os.Stat(filepath.Join(filepath.Dir(path), sdlcskills.ManifestName)); err == nil {
		keys, err := sdlcTrustedKeys()
		if err != nil {
			return nil, err
		}
		b, _, err := sdlcskills.LoadSignedBundleFile(path, keys)
		if err != nil {
			return nil, err
		}
		return b, nil
	}
	b, err := sdlcskills.LoadBundle(path)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// applyPinnedStandard composes, for each skill that declares a standard, the
// pinned engineering section into its prompt, when bundlePath is set and the
// bundle verifies. It never fails the daemon: every failure leaves the inline
// prompts as written and returns a one-line reason to log. An empty bundlePath
// is the normal "not configured" case and returns "".
func applyPinnedStandard(m *skills.Manager, bundlePath string, load func(string) (skills.StandardProvider, error)) string {
	if strings.TrimSpace(bundlePath) == "" {
		return ""
	}
	p, err := load(bundlePath)
	if err != nil {
		return fmt.Sprintf("[agent-skill] %s=%s not applied (%v); hosted skills keep their inline prompt", sdlcBundleEnv, bundlePath, err)
	}
	applied, missing := m.ApplyStandard(p)
	switch {
	case len(missing) > 0:
		return fmt.Sprintf("[agent-skill] pinned standard %s: applied to %v; section missing for %v, which keep their inline prompt", p.Pin(), applied, missing)
	case len(applied) == 0:
		return fmt.Sprintf("[agent-skill] pinned standard %s verified, but no skill declares one", p.Pin())
	default:
		return fmt.Sprintf("[agent-skill] pinned standard %s applied to %v", p.Pin(), applied)
	}
}
