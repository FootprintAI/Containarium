//go:build !windows

package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Restart-backoff guards for the three unit templates (#1152).
//
// The incident: a production backend crash-looped 1655 times in ~4 hours —
// one restart every ~7 seconds — until an operator noticed the host's CPU
// was pinned. `StartLimitIntervalSec=0` disables systemd's rate limiting
// entirely, and with a flat `RestartSec=5s` a persistent start failure
// retries forever at full speed.
//
// The collateral damage was worse than the CPU: each cycle rewrote the
// bundled monitoring stack's config, so alertmanager and vmalert were
// restarted every 7 seconds for 4 hours. Alerting could not have fired
// during the incident — including on the incident itself.
//
// The fix keeps infinite retry (that part was deliberate: a pool member
// that stays dead is worse than one that retries) and adds geometric
// backoff, so the two properties stop being conflated.

// unitSources returns each unit template with a label. The daemon
// template is a package const; the sibling shipped as a plain file and
// the sentinel's inline template are read from source, because nothing
// else in the build would notice them regressing.
func unitSources(t *testing.T) map[string]string {
	t.Helper()

	read := func(parts ...string) string {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(parts...))
		if err != nil {
			t.Fatalf("read %v: %v", parts, err)
		}
		return string(raw)
	}

	return map[string]string{
		"daemon (systemdServiceTemplate)":       systemdServiceTemplate,
		"daemon (scripts/containarium.service)": read("..", "..", "scripts", "containarium.service"),
		"sentinel (sentinel_service.go)":        read("sentinel_service.go"),
	}
}

// Every unit must bound its retry rate. Without these, a persistent
// failure retries 12 times a minute forever.
func TestUnitsHaveRestartBackoff(t *testing.T) {
	for name, unit := range unitSources(t) {
		t.Run(name, func(t *testing.T) {
			for _, directive := range []string{"RestartSteps=", "RestartMaxDelaySec="} {
				if !strings.Contains(unit, directive) {
					t.Errorf("%s is missing %s — a persistent start failure would retry at a flat "+
						"interval forever, which is #1152 (1655 restarts in 4 hours)", name, directive)
				}
			}
			// The floor must survive too: without RestartSec the
			// geometric series has nothing to start from.
			if !strings.Contains(unit, "RestartSec=") {
				t.Errorf("%s lost RestartSec", name)
			}
		})
	}
}

// Infinite retry must be preserved. This is the half of the original
// design that was correct and is easy to "fix" by mistake: a
// StartLimitBurst that gives up leaves a pool member silently dead,
// which is worse than one retrying slowly.
func TestUnitsStillRetryForever(t *testing.T) {
	for name, unit := range unitSources(t) {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(unit, "StartLimitIntervalSec=0") {
				t.Errorf("%s no longer disables the start rate limit: a unit that gives up leaves "+
					"a pool member dead until someone notices, which is what the 0 was for", name)
			}
			// systemd's rate limiter is what makes a unit enter
			// "failed" and stop retrying. Reintroducing a burst limit
			// alongside the backoff would undo that deliberately-kept
			// property.
			if strings.Contains(unit, "StartLimitBurst=") {
				t.Errorf("%s sets StartLimitBurst — combined with a start limit that would make the "+
					"unit give up permanently; backoff is the mechanism here, not a cap", name)
			}
		})
	}
}

// The backoff has to actually widen: a max delay at or below the initial
// delay is the flat-retry behaviour with extra words.
func TestBackoffCeilingIsAboveTheFloor(t *testing.T) {
	for name, unit := range unitSources(t) {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(unit, "RestartSec=5s") {
				t.Errorf("%s: expected a 5s floor", name)
			}
			if !strings.Contains(unit, "RestartMaxDelaySec=5min") {
				t.Errorf("%s: expected a 5min ceiling, well above the 5s floor", name)
			}
			// RestartSteps interpolates between them; 1 step would be
			// a single jump rather than a ramp, defeating the "a
			// transient hiccup still recovers in seconds" property.
			if strings.Contains(unit, "RestartSteps=1\n") || strings.Contains(unit, "RestartSteps=0") {
				t.Errorf("%s: RestartSteps must ramp, so an early transient failure still retries fast", name)
			}
		})
	}
}
