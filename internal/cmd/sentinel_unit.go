//go:build !windows

package cmd

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Sentinel unit memory bounds (#1350, corrected by #1454).
//
// #1349 bursts ~330 MB in ~35 min on backend loss until the sentinel held
// 565 MB anon-RSS on a 1 GB host. Nothing bounded it, so the KERNEL resolved
// it — 36 minutes into a full-host stall (73.91% iowait, load 32.46, 12 tasks
// blocked in D), long after the box had stopped serving usefully.
// `Restart=always` did its job and the sentinel came back.
//
// MemoryMax is the hard stop; paired with Restart=always it costs a restart
// measured in seconds instead of a 36-minute apex outage. That half was right.
//
// MemoryHigh BELOW MemoryMax was not. #1454: a soft cap only helps if reclaim
// can make progress, and progress needs something reclaimable — page cache, or
// anon plus swap. These hosts have NO swap, and the #1349 burst is
// anon-dominated, so file cache is squeezed to ~0 within minutes and reclaim
// has nothing left to do. The cgroup then parks between MemoryHigh and
// MemoryMax and is throttled indefinitely: it never reaches the hard cap, so
// Restart=always never fires, and systemd reports active(running) throughout.
//
// Measured during the #1454 outage: memory.events high=556267 with max=0 and
// oom_kill=0, PSI full avg300=86.10 (86% of wall-clock with every task in the
// cgroup frozen), anon 271 MB against file 0.36 MB, and pgscan 79.4M against
// pgsteal 2.4M — a 3% reclaim success rate, i.e. futile scanning. ~90 minutes
// of total edge outage, ended by manual intervention, where the OOM-and-restart
// path it replaced self-recovered in seconds.
//
// So the dead band is the bug, and the old 35%/50% defaults had one: a ~154 MB
// window (~358 MB to ~512 MB on a 1 GB host) in which any burst that comes to
// rest is stuck. Note that neither burst measured so far lands there — 271 MB
// sits below it and 565 MB above it — so the shipped defaults are a LATENT
// stall window, not the cause of the #1454 outage; that host carried a tighter
// operator drop-in (256M/384M) and the burst came to rest inside its band. The
// window is still indefensible: nothing chooses where a burst stops, and the
// only reason to keep a band is a reclaim path that these hosts do not have.
//
// Defaulting MemoryHigh to MemoryMax removes the window — the cgroup is still
// reclaimed locally at the threshold rather than by global reclaim evicting the
// host's page cache, and memory.events "high" still increments as an early
// signal, but a burst that cannot be reclaimed now proceeds to the cap and is
// restarted instead of hanging.
//
// A gap remains legitimate where reclaim CAN make progress, so it is allowed
// on hosts that have swap and rejected on hosts that do not.
//
// Defaults are PERCENTAGES so one value works across the 1 GB (e2-micro) and
// 2 GB (e2-small, per #770) sentinel hosts without per-host tuning. They are
// overridable because BYOC and larger sentinels exist.

const (
	// defaultSentinelMemoryHigh deliberately EQUALS defaultSentinelMemoryMax.
	// Any lower value opens the #1454 throttle band, in which a swapless host
	// stalls forever instead of restarting. Reclaim still runs at the
	// threshold; what is removed is the window to get stuck in.
	defaultSentinelMemoryHigh = "50%"

	// defaultSentinelMemoryMax caps at ~512 MB on a 1 GB host, deliberately
	// BELOW the 565 MB the #1349 burst reached — a ceiling above that would
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

	// HostHasSwap reports whether the target host can page anonymous memory
	// out. It decides whether a MemoryHigh below MemoryMax is a safety valve
	// or the #1454 livelock, so it is passed in rather than read here: this
	// file stays pure and testable without /proc, and the install path is the
	// only thing that touches the host.
	HostHasSwap bool
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

// validateMemoryBounds enforces the #1454 rule: a throttle band below the hard
// cap is only safe where reclaim can make progress.
//
// MemoryHigh ABOVE MemoryMax is rejected outright — MemoryMax binds first, so
// the throttle it advertises can never engage, and a unit that documents a
// limit that cannot fire is worse than one that omits it.
//
// MemoryHigh BELOW MemoryMax is rejected on a host with no swap. There, an
// anon-dominated cgroup has nothing to reclaim once page cache is gone, so the
// band is not a safety valve but a trap the process cannot leave and cannot
// die in (#1454: PSI full 86%, pgsteal/pgscan 3%, ~90 min outage). With swap,
// the same band is fine: reclaim can page anon out and the throttle does what
// it was meant to do.
//
// MemoryHigh EQUAL to MemoryMax is always allowed and is the default. Reclaim
// still runs at the threshold and memory.events `high` still increments as an
// early signal; there is simply no window to get stuck in.
//
// Mixed forms (a percentage against an absolute size) cannot be ordered without
// knowing physical RAM, so they pass rather than being guessed at — systemd
// will still enforce whichever binds first.
func validateMemoryBounds(high, max string, hostHasSwap bool) error {
	cmp, ok := compareMemoryValues(high, max)
	if !ok {
		return nil
	}
	if cmp > 0 {
		return fmt.Errorf("MemoryHigh (%s) must not be above MemoryMax (%s): MemoryMax binds first, "+
			"so the throttle could never engage", high, max)
	}
	if cmp < 0 && !hostHasSwap {
		return fmt.Errorf("MemoryHigh (%s) must not be below MemoryMax (%s) on a host with no swap: "+
			"an anon-dominated cgroup has nothing left to reclaim once page cache is gone, so it "+
			"stalls between the two limits instead of reaching the cap — it never gets restarted "+
			"and systemd still reports it active (#1454). Set --memory-high equal to --memory-max, "+
			"or enable swap on the host", high, max)
	}
	return nil
}

// compareMemoryValues orders two systemd memory values, reporting ok=false when
// they are not comparable (mixed percentage/absolute forms, or "infinity").
func compareMemoryValues(a, b string) (int, bool) {
	if ap, aerr := percentValue(a); aerr == nil {
		bp, berr := percentValue(b)
		if berr != nil {
			return 0, false
		}
		return ap - bp, true
	}
	ab, aok := comparableBytes(a)
	bb, bok := comparableBytes(b)
	if !aok || !bok {
		return 0, false
	}
	switch {
	case ab > bb:
		return 1, true
	case ab < bb:
		return -1, true
	default:
		return 0, true
	}
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
	if err := validateMemoryBounds(cfg.MemoryHigh, cfg.MemoryMax, cfg.HostHasSwap); err != nil {
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

# Memory bounds (#1350, corrected by #1454). #1349 bursts ~330 MB in
# ~35 min on backend loss; this process reached 565 MB on a 1 GB host and,
# with nothing bounding it, the kernel's OOM killer resolved it 36 minutes
# into a full-host stall (73.91%% iowait, load 32.46) rather than systemd
# restarting one process in seconds. MemoryMax plus Restart=always above
# is what turns that into a restart.
#
# MemoryHigh EQUALS MemoryMax on purpose. A soft cap below the hard cap
# only helps if reclaim can make progress, and that needs page cache or
# swap. These hosts have no swap and the burst is anon-dominated, so file
# cache is gone within minutes and reclaim has nothing to do: the cgroup
# parks between the two limits and is throttled indefinitely. It never
# reaches the cap, so Restart=always never fires and systemd keeps
# reporting active(running). #1454 measured that as memory.events
# high=556267 with oom_kill=0, PSI full avg300=86%%, and pgsteal/pgscan of
# 3%% — ~90 minutes of total edge outage, worse than the OOM kill it
# replaced. Equal values keep local reclaim and the memory.events "high"
# early-warning counter while removing the window to get stuck in.
#
# Percentages so one value fits both the 1 GB (e2-micro) and 2 GB
# (e2-small, #770) sentinel hosts. Default is ~512 MB on a 1 GB host:
# well above the observed 82 MB cold start, and deliberately below the
# 565 MB the burst actually reached — a cap above that would never have
# fired. Override with --memory-high / --memory-max on
# "containarium sentinel service install" for a larger host; a
# --memory-high below --memory-max is refused unless the host has swap.
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
