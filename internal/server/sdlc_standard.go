package server

import (
	"fmt"
	"strings"

	"github.com/footprintai/containarium/pkg/core/sdlcskills"
	"github.com/footprintai/containarium/pkg/core/skills"
)

// sdlcBundleEnv names the pinned sdlc-skills.tar.gz (the release asset the
// boxes install) for the daemon to compose hosted skill prompts from (#2488).
const sdlcBundleEnv = "CONTAINARIUM_SDLC_SKILLS_BUNDLE"

// loadSDLCBundle is the production loader: the bundle verified against the pin
// compiled into this binary.
func loadSDLCBundle(path string) (skills.StandardProvider, error) {
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
