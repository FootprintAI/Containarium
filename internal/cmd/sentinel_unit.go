//go:build !windows

package cmd

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Sentinel unit memory bounds (#1350).
//
// #1349 leaked ~18 MB/day until the sentinel held 565 MB anon-RSS on a 1 GB
// host. Nothing bounded it, so the KERNEL resolved it — 36 minutes into a
// full-host stall (73.91% iowait, load 32.46, 12 tasks blocked in D), long
// after the box had stopped serving usefully. `Restart=always` did its job and
// the sentinel came back; what was missing was anything that acts on memory
// pressure BEFORE the host is thrashing.
//
// MemoryHigh is the directive that changes the outcome. Past it, reclaim
// pressure is applied inside the sentinel's own cgroup rather than by global
// reclaim evicting the host's page cache — the failure stays local and the box
// stays responsive. MemoryMax is the hard stop; paired with Restart=always it
// costs a restart measured in seconds instead of a 36-minute apex outage. The
// kernel's OOM killer picked `containarium` last time because it was the
// biggest process, which was luck rather than policy: sshpiperd invoked the
// killer, and SSH could as easily have been the casualty.
//
// Defaults are PERCENTAGES so one value works across the 1 GB (e2-micro) and
// 2 GB (e2-small, per #770) sentinel hosts without per-host tuning. They are
// overridable because BYOC and larger sentinels exist.

const (
	// defaultSentinelMemoryHigh throttles at ~358 MB on a 1 GB host — roughly
	// 4x the 82 MB cold start observed while diagnosing #1349, so a busy
	// sentinel is not throttled in normal operation.
	defaultSentinelMemoryHigh = "35%"

	// defaultSentinelMemoryMax caps at ~512 MB on a 1 GB host, deliberately
	// BELOW the 565 MB the #1349 leak reached — a ceiling above that would
	// never have fired and would be decoration.
	defaultSentinelMemoryMax = "50%"
)

// sentinelUnitConfig is everything that varies in the generated unit.
type sentinelUnitConfig struct {
	SpotVM     string
	Zone       string
	Project    string
	MemoryHigh string
	MemoryMax  string
}

// systemdMemoryPattern matches the value forms systemd accepts for
// MemoryHigh=/MemoryMax=: a percentage, or a byte count with an optional
// binary suffix. Note "M" not "MB" — systemd rejects the latter.
var systemdMemoryPattern = regexp.MustCompile(`^(\d+)(%|K|M|G|T|)$`)

// validateSystemdMemoryValue rejects anything systemd would refuse, so a typo
// surfaces at install time rather than as a unit that will not start.
func validateSystemdMemoryValue(v string) error {
	if v == "" {
		return fmt.Errorf("empty memory value")
	}
	if v == "infinity" {
		return nil
	}
	m := systemdMemoryPattern.FindStringSubmatch(v)
	if m == nil {
		return fmt.Errorf("invalid memory value %q: want a percentage (\"35%%\"), a size (\"512M\", \"1G\"), or \"infinity\"", v)
	}
	if m[2] == "%" {
		pct, err := strconv.Atoi(m[1])
		if err != nil {
			return fmt.Errorf("invalid memory value %q", v)
		}
		if pct < 1 || pct > 100 {
			return fmt.Errorf("memory percentage %q must be between 1%% and 100%%", v)
		}
	}
	return nil
}

// percentValue returns the numeric part of a percentage value, erroring if v
// is not one.
func percentValue(v string) (int, error) {
	m := systemdMemoryPattern.FindStringSubmatch(v)
	if m == nil || m[2] != "%" {
		return 0, fmt.Errorf("%q is not a percentage", v)
	}
	return strconv.Atoi(m[1])
}

// comparableBytes converts an absolute systemd size to bytes. Returns ok=false
// for percentages and "infinity", which cannot be compared without knowing the
// host's physical memory.
func comparableBytes(v string) (uint64, bool) {
	m := systemdMemoryPattern.FindStringSubmatch(v)
	if m == nil || m[2] == "%" {
		return 0, false
	}
	n, err := strconv.ParseUint(m[1], 10, 64)
	if err != nil {
		return 0, false
	}
	switch m[2] {
	case "K":
		return n * 1024, true
	case "M":
		return n * 1024 * 1024, true
	case "G":
		return n * 1024 * 1024 * 1024, true
	case "T":
		return n * 1024 * 1024 * 1024 * 1024, true
	default:
		return n, true
	}
}

// validateMemoryBounds checks that the throttle sits below the hard cap.
//
// A MemoryHigh at or above MemoryMax is the no-throttle behaviour with extra
// words: the cgroup reaches the hard cap without ever having been reclaimed
// under pressure first, which is precisely the #1349 shape this is meant to
// prevent. Mixed forms (a percentage against an absolute size) cannot be
// ordered without knowing physical RAM, so they pass rather than being guessed
// at — systemd will still enforce whichever binds first.
func validateMemoryBounds(high, max string) error {
	if hp, herr := percentValue(high); herr == nil {
		if mp, merr := percentValue(max); merr == nil {
			if hp >= mp {
				return fmt.Errorf("MemoryHigh (%s) must be below MemoryMax (%s), otherwise the cgroup "+
					"hits the hard cap without ever being reclaimed under pressure first", high, max)
			}
		}
		return nil
	}
	hb, hok := comparableBytes(high)
	mb, mok := comparableBytes(max)
	if hok && mok && hb >= mb {
		return fmt.Errorf("MemoryHigh (%s) must be below MemoryMax (%s), otherwise the cgroup "+
			"hits the hard cap without ever being reclaimed under pressure first", high, max)
	}
	return nil
}

// buildSentinelUnit renders the systemd unit. Pure and separate from the
// install path so the directives are testable without root, systemd, or a
// filesystem — the install command only writes what this returns.
func buildSentinelUnit(cfg sentinelUnitConfig) (string, error) {
	if strings.TrimSpace(cfg.SpotVM) == "" || strings.TrimSpace(cfg.Zone) == "" || strings.TrimSpace(cfg.Project) == "" {
		return "", fmt.Errorf("--spot-vm, --zone, and --project are required")
	}
	if err := validateSystemdMemoryValue(cfg.MemoryHigh); err != nil {
		return "", fmt.Errorf("--memory-high: %w", err)
	}
	if err := validateSystemdMemoryValue(cfg.MemoryMax); err != nil {
		return "", fmt.Errorf("--memory-max: %w", err)
	}
	if err := validateMemoryBounds(cfg.MemoryHigh, cfg.MemoryMax); err != nil {
		return "", err
	}

	return fmt.Sprintf(`[Unit]
Description=Containarium Sentinel (HA Proxy)
Documentation=https://github.com/footprintai/Containarium
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/usr/local/bin/containarium sentinel \
  --spot-vm %s \
  --zone %s \
  --project %s
Restart=always
# Keep retrying forever (StartLimitIntervalSec=0 above), but not at full
# speed. A persistent start failure used to retry every 5s indefinitely:
# one production host crash-looped 1655 times in ~4 hours, pinning a core
# and — because each cycle rewrites the bundled monitoring config —
# restarting alertmanager and vmalert every 7 seconds, so alerting could
# not have fired during the incident, including on the incident itself
# (#1152).
#
# "Never give up" and "retry at full speed" are separable. RestartSteps
# interpolates the delay geometrically from RestartSec to
# RestartMaxDelaySec, so a transient incus hiccup at boot still recovers
# in seconds while a persistent failure settles to one attempt every 5
# minutes. That same 4-hour outage would cost ~50 attempts, not 1655.
#
# Requires systemd 254+. The documented host floor is Ubuntu 24.04 LTS
# ("or later", README), which ships 255. On an older host systemd warns
# and continues, degrading to the previous fixed-interval behaviour
# rather than failing to start — so this cannot brick a host that
# predates the directives.
RestartSec=5s
RestartSteps=6
RestartMaxDelaySec=5min
User=root
Group=root

# Memory bounds (#1350). #1349 leaked ~18 MB/day until this process held
# 565 MB on a 1 GB host; with nothing bounding it, the kernel's OOM killer
# resolved it 36 minutes into a full-host stall (73.91%% iowait, load
# 32.46) rather than systemd restarting one process in seconds.
#
# MemoryHigh is the directive that changes the outcome: past it, reclaim
# pressure applies inside THIS cgroup instead of global reclaim evicting
# the whole host's page cache, so the failure stays local and the box
# keeps serving. MemoryMax is the hard stop, and with Restart=always
# above it costs a restart rather than an outage.
#
# Percentages so one value fits both the 1 GB (e2-micro) and 2 GB
# (e2-small, #770) sentinel hosts. Defaults are ~358 MB / ~512 MB on a
# 1 GB host: roughly 4x the observed 82 MB cold start, and deliberately
# below the 565 MB the leak actually reached — a cap above that would
# never have fired. Override with --memory-high / --memory-max on
# "containarium sentinel service install" for a larger host.
MemoryAccounting=yes
MemoryHigh=%s
MemoryMax=%s
# Explicit rather than inherited, so the interaction with Restart=always
# is readable here: on an OOM kill systemd stops the unit, and
# Restart=always brings it straight back.
OOMPolicy=stop

StandardOutput=journal
StandardError=journal
SyslogIdentifier=containarium-sentinel

LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`, cfg.SpotVM, cfg.Zone, cfg.Project, cfg.MemoryHigh, cfg.MemoryMax), nil
}
