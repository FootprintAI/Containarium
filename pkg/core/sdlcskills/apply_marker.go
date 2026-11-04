package sdlcskills

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// The skill-set apply marker (#3529). ApplyBoxSkillSets changes the box
// owner's ~/.claude/skills in place, which takes as long as the bundle
// download. A run started through the daemon is refused meanwhile by the
// daemon's own gate (#3510); a run started over SSH (`containarium code run`,
// the MCP code_run tool) never reaches the daemon, so the apply also holds
// this marker in the box owner's tree, and the SSH run path reads it before
// launching and refuses while it is held. Both sides run as the box owner, so
// no daemon call is needed on the run path.
//
// The marker is a lease, so a crashed apply cannot hold it forever: the apply
// writes it with an expiry ApplyMarkerLease ahead and renews it while it is
// still running, and removes it when it returns (including on a failure or a
// panic). A marker whose expiry has passed was left by an apply that is no
// longer renewing it (the daemon died mid-apply, or the box rebooted), so the
// run path treats it as stale: it removes it, says so, and starts the run. All
// times are the box's own clock (`date +%s` on the box), on both sides.

// ApplyMarkerFile is the marker's name, beside the skills it guards
// (relative to ~/.claude/skills).
const ApplyMarkerFile = ".sdlc-skill-sets.applying"

// ApplyMarkerVersion is the marker's format version.
const ApplyMarkerVersion = 1

// ApplyMarkerLease is how long a marker holds without being renewed. The
// apply renews it every ApplyMarkerLease/3, so only an apply that stopped
// running lets it lapse; the lease is how long such a crash can still refuse
// runs.
const ApplyMarkerLease = 10 * time.Minute

// applyMarkerSkew is how far past a full lease from now a marker's expiry may
// lie and still be believed. No writer sets more than a lease ahead, so a
// later expiry means the box clock moved back since it was written.
const applyMarkerSkew = time.Minute

// ApplyMarker is the marker's content.
type ApplyMarker struct {
	Version int `json:"version"`
	// StartedAt is when the apply took the marker, unix seconds (box clock).
	StartedAt int64 `json:"started_at"`
	// ExpiresAt is when the marker lapses unless renewed, unix seconds (box
	// clock).
	ExpiresAt int64 `json:"expires_at"`
}

const applyMarkerPath = `"$HOME/.claude/skills/` + ApplyMarkerFile + `"`

// ApplyMarkerWriteScript writes the marker atomically as the box user, with
// an expiry lease ahead of the box's clock, and prints the start time it
// recorded and how many directory levels it had to create for it (0; 1 for
// ~/.claude/skills; 2 for ~/.claude too), which ApplyMarkerRemoveScript
// removes again so an apply that changes nothing leaves no trace. startedAt 0
// takes a new marker (the start is now); a renewal passes the start the first
// write printed.
func ApplyMarkerWriteScript(startedAt int64, lease time.Duration) string {
	start := `"$now"`
	if startedAt > 0 {
		start = strconv.FormatInt(startedAt, 10)
	}
	return `set -e
d="$HOME/.claude/skills"
made=0
[ -d "$d" ] || made=1
[ -d "$HOME/.claude" ] || made=2
mkdir -p "$d"
now="$(date +%s)"
start=` + start + `
printf '{"version":` + strconv.Itoa(ApplyMarkerVersion) + `,"started_at":%s,"expires_at":%s}\n' "$start" "$((now + ` + strconv.FormatInt(int64(lease/time.Second), 10) + `))" > ` + applyMarkerPath + `.tmp
mv -f ` + applyMarkerPath + `.tmp ` + applyMarkerPath + `
echo "$start $made"
`
}

// ApplyMarkerRemoveScript removes the marker as the box user, and the
// directory levels its first write created (ApplyMarkerTaken.CreatedLevels)
// while they are empty: a directory the install filled is left alone.
func ApplyMarkerRemoveScript(createdLevels int) string {
	script := `rm -f ` + applyMarkerPath + ` ` + applyMarkerPath + ".tmp\n"
	if createdLevels >= 1 {
		script += `rmdir "$HOME/.claude/skills" 2>/dev/null || true` + "\n"
	}
	if createdLevels >= 2 {
		script += `rmdir "$HOME/.claude" 2>/dev/null || true` + "\n"
	}
	return script
}

// ApplyMarkerTaken is what ApplyMarkerWriteScript printed.
type ApplyMarkerTaken struct {
	// StartedAt is the start time recorded, unix seconds (box clock).
	StartedAt int64
	// CreatedLevels is how many directory levels the write created.
	CreatedLevels int
}

// ParseApplyMarkerTaken reads ApplyMarkerWriteScript's output.
func ParseApplyMarkerTaken(out string) (ApplyMarkerTaken, error) {
	bad := fmt.Errorf("apply marker: unexpected write output %q", strings.TrimSpace(out))
	fields := strings.Fields(out)
	if len(fields) != 2 {
		return ApplyMarkerTaken{}, bad
	}
	start, err1 := strconv.ParseInt(fields[0], 10, 64)
	levels, err2 := strconv.Atoi(fields[1])
	if err1 != nil || err2 != nil || start <= 0 || levels < 0 || levels > 2 {
		return ApplyMarkerTaken{}, bad
	}
	return ApplyMarkerTaken{StartedAt: start, CreatedLevels: levels}, nil
}

// ApplyMarkerCheckScript prints, as the box user, the box clock on the first
// line and the marker's content (nothing when there is none) after it.
func ApplyMarkerCheckScript() string {
	return `date +%s
cat ` + applyMarkerPath + ` 2>/dev/null
exit 0
`
}

// ApplyMarkerStatus is what a check found.
type ApplyMarkerStatus int

const (
	// ApplyMarkerAbsent: no apply holds the marker; a run may start.
	ApplyMarkerAbsent ApplyMarkerStatus = iota
	// ApplyMarkerHeld: an apply is changing the skills; a run is refused.
	ApplyMarkerHeld
	// ApplyMarkerStale: a marker no running apply holds (its lease lapsed, or
	// it cannot be read or dated); it is removed and the run starts.
	ApplyMarkerStale
)

// ApplyMarkerCheck is the outcome of reading ApplyMarkerCheckScript's output.
type ApplyMarkerCheck struct {
	Status ApplyMarkerStatus
	// Marker is the marker read (zero when absent or unreadable).
	Marker ApplyMarker
	// Now is the box clock, unix seconds.
	Now int64
	// Raw is the marker's content as read, trimmed: what a stale removal
	// compares against so it never removes a marker a new apply just wrote.
	Raw string
	// Why says, for a stale marker, why it is not believed.
	Why string
}

// ParseApplyMarkerCheck classifies ApplyMarkerCheckScript's output. The box
// user writes the marker, so it is data: one that is not the expected JSON or
// carries no expiry is stale (unreadable), never held forever.
func ParseApplyMarkerCheck(out string) (ApplyMarkerCheck, error) {
	first, rest, _ := strings.Cut(strings.TrimLeft(out, "\n"), "\n")
	now, err := strconv.ParseInt(strings.TrimSpace(first), 10, 64)
	if err != nil {
		return ApplyMarkerCheck{}, fmt.Errorf("apply marker check: unexpected box clock %q", strings.TrimSpace(first))
	}
	c := ApplyMarkerCheck{Now: now, Raw: strings.TrimSpace(rest)}
	if c.Raw == "" {
		c.Status = ApplyMarkerAbsent
		return c, nil
	}
	var m ApplyMarker
	if err := json.Unmarshal([]byte(c.Raw), &m); err != nil || m.ExpiresAt <= 0 {
		c.Status, c.Why = ApplyMarkerStale, "it cannot be read"
		return c, nil
	}
	c.Marker = m
	switch {
	case m.ExpiresAt <= now:
		c.Status, c.Why = ApplyMarkerStale, fmt.Sprintf("its lease lapsed %s ago, so the apply that wrote it is no longer running", time.Duration(now-m.ExpiresAt)*time.Second)
	case m.ExpiresAt > now+int64((ApplyMarkerLease+applyMarkerSkew)/time.Second):
		c.Status, c.Why = ApplyMarkerStale, "its expiry is further ahead than any apply sets (the box clock moved back)"
	default:
		c.Status = ApplyMarkerHeld
	}
	return c, nil
}

// ApplyMarkerClearStaleScript removes the marker as the box user only while
// it still holds raw, so a marker a new apply wrote since the check survives.
func ApplyMarkerClearStaleScript(raw string) string {
	return `f=` + applyMarkerPath + `
[ "$(cat "$f" 2>/dev/null)" = ` + shellQuote(raw) + ` ] && rm -f "$f"
exit 0
`
}

// shellQuote single-quotes s for sh.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
