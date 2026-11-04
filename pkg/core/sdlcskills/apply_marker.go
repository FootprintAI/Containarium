package sdlcskills

import (
	"encoding/json"
	"fmt"
	"regexp"
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
//
// Whatever the box user left at the marker path is replaced, so the marker
// held is the one runs read (#3540): the temporary file is removed first (a
// symlink there is removed, never written through), a directory at the
// marker path is removed, and the rename never moves into a directory (-T),
// so a symlink to one is replaced as a link. Nothing is removed but those two
// exact paths, and rm neither follows a symlink nor crosses a mount. A path
// that cannot be replaced fails the write, with rm's or mv's own error.
func ApplyMarkerWriteScript(startedAt int64, lease time.Duration) string {
	start := `"$now"`
	if startedAt > 0 {
		start = strconv.FormatInt(startedAt, 10)
	}
	return `set -e
d="$HOME/.claude/skills"
f=` + applyMarkerPath + `
made=0
[ -d "$d" ] || made=1
[ -d "$HOME/.claude" ] || made=2
mkdir -p "$d"
rm -rf --one-file-system "$f.tmp"
now="$(date +%s)"
start=` + start + `
printf '{"version":` + strconv.Itoa(ApplyMarkerVersion) + `,"started_at":%s,"expires_at":%s}\n' "$start" "$((now + ` + strconv.FormatInt(int64(lease/time.Second), 10) + `))" > "$f.tmp"
if [ -d "$f" ] && [ ! -L "$f" ]; then rm -rf --one-file-system "$f"; fi
mv -fT "$f.tmp" "$f"
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

// ApplyMarkerReadLimit bounds how much of the marker a check reads. An apply
// writes well under 100 bytes; a larger file is not one an apply wrote, so it
// is stale (and removed) rather than read in full.
const ApplyMarkerReadLimit = 4096

// applyMarkerIDFormat is the stat format of a marker path's identity,
// inode:ctime:size, of the path itself (a symlink is not followed). Every
// write replaces the file by rename, so a marker an apply writes after a
// check never has the identity the check saw. The time is the change time,
// which the box user cannot set (#3540: an mtime is theirs to set, before
// 1970 or past 2038, and stat then prints it negative); it can still print
// negative on a box whose clock is, so the pattern allows a sign there.
const applyMarkerIDFormat = `%i:%Z:%s`

// applyMarkerIDPattern is an identity as the check prints it. The identity is
// put into the clear's script, so nothing but digits, the two colons and a
// sign on the time gets through.
var applyMarkerIDPattern = regexp.MustCompile(`^[0-9]+:-?[0-9]+:[0-9]+$`)

// ApplyMarkerCheckScript prints, as the box user, the box clock on the first
// line; then "absent" when there is no marker, "unreadable <id>" when there is
// one the user cannot read as a regular file (a directory, a symlink to
// anything but a readable file, a FIFO), or "present <id>"; and for a present
// marker, at most ApplyMarkerReadLimit+1 bytes of it after that. <id> is the
// path's identity (applyMarkerIDFormat), what ApplyMarkerClearStaleScript
// compares before it removes anything.
func ApplyMarkerCheckScript() string {
	return `f=` + applyMarkerPath + `
date +%s
if [ ! -e "$f" ] && [ ! -L "$f" ]; then echo absent; exit 0; fi
id="$(stat -c '` + applyMarkerIDFormat + `' "$f" 2>/dev/null)" || { echo "apply marker exists but cannot be inspected" >&2; exit 1; }
if [ ! -f "$f" ] || [ ! -r "$f" ]; then echo "unreadable $id"; exit 0; fi
echo "present $id"
head -c ` + strconv.Itoa(ApplyMarkerReadLimit+1) + ` "$f"
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
	// ID is the marker path's identity (inode:ctime:size) when there is one:
	// what a stale clear compares, so it never removes a marker a new apply
	// wrote since the check.
	ID string
	// Why says, for a stale marker, why it is not believed.
	Why string
}

// ParseApplyMarkerCheck classifies ApplyMarkerCheckScript's output. The box
// user writes the marker, so it is data: one that cannot be read, is larger
// than any apply writes, is not the expected JSON, or carries no expiry is
// stale, never held forever.
func ParseApplyMarkerCheck(out string) (ApplyMarkerCheck, error) {
	clock, rest, _ := strings.Cut(out, "\n")
	now, err := strconv.ParseInt(strings.TrimSpace(clock), 10, 64)
	if err != nil {
		return ApplyMarkerCheck{}, fmt.Errorf("apply marker check: unexpected box clock %q", strings.TrimSpace(clock))
	}
	state, content, _ := strings.Cut(rest, "\n")
	c := ApplyMarkerCheck{Now: now}
	fields := strings.Fields(state)
	switch {
	case len(fields) == 1 && fields[0] == "absent":
		c.Status = ApplyMarkerAbsent
		return c, nil
	case len(fields) == 2 && (fields[0] == "present" || fields[0] == "unreadable") && applyMarkerIDPattern.MatchString(fields[1]):
		c.ID = fields[1]
	default:
		return ApplyMarkerCheck{}, fmt.Errorf("apply marker check: unexpected state %q", state)
	}
	if fields[0] == "unreadable" {
		c.Status, c.Why = ApplyMarkerStale, "it cannot be read"
		return c, nil
	}
	if len(content) > ApplyMarkerReadLimit {
		c.Status, c.Why = ApplyMarkerStale, "it is larger than any apply writes"
		return c, nil
	}
	var m ApplyMarker
	if err := json.Unmarshal([]byte(content), &m); err != nil || m.ExpiresAt <= 0 {
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

// ApplyMarkerClearResult is what ApplyMarkerClearStaleScript did.
type ApplyMarkerClearResult int

const (
	// ApplyMarkerClearUnknown is the zero value; no clear reports it.
	ApplyMarkerClearUnknown ApplyMarkerClearResult = iota
	// ApplyMarkerClearRemoved: the stale marker is gone; a run may start.
	ApplyMarkerClearRemoved
	// ApplyMarkerClearKept: the marker path no longer holds the stale marker
	// checked (a new apply's marker, or nothing), and is left as it is; check
	// again.
	ApplyMarkerClearKept
	// ApplyMarkerClearFailed: the stale marker is still there and the box
	// user cannot remove it (for example a read-only ~/.claude/skills).
	ApplyMarkerClearFailed
)

// Outputs of ApplyMarkerClearStaleScript.
const (
	applyMarkerRemoved = "removed"
	applyMarkerKept    = "kept"
	applyMarkerFailed  = "failed"
)

// ApplyMarkerClearStaleScript removes the marker path as the box user only
// while its identity is still id (ApplyMarkerCheck.ID), so a marker a new
// apply wrote since the check survives, and prints what it did
// (ParseApplyMarkerCleared). id is validated, never quoted: it is digits,
// colons and a minus only.
//
// Anything at the path is removed, a directory included (#3540), and nothing
// else: the path is first renamed to a capture name beside it, which moves a
// symlink as a link and never follows it, and rm on the capture neither
// follows a symlink inside a directory nor crosses a mount. The rename also
// narrows the race with a new apply to the instant between the identity
// check and the rename (both in this one script), and is undone when the
// captured file turns out not to be the one checked: a new apply's marker
// caught in that instant is put back, not deleted (a run checking in that
// same instant could still start; the re-check after a start then sees the
// marker). The capture is compared by inode and size, since the rename moves
// its change time.
func ApplyMarkerClearStaleScript(id string) (string, error) {
	return applyMarkerClearStaleScript(id, "")
}

// applyMarkerClearStaleScript is ApplyMarkerClearStaleScript with between run
// after the identity check and before the capture: where a test lands a new
// apply's marker. Production passes "".
func applyMarkerClearStaleScript(id, between string) (string, error) {
	if !applyMarkerIDPattern.MatchString(id) {
		return "", fmt.Errorf("apply marker: %q is not a marker identity", id)
	}
	fields := strings.Split(id, ":")
	captured := fields[0] + ":" + fields[2]
	return `f=` + applyMarkerPath + `
c="$f.stale.$$"
if [ "$(stat -c '` + applyMarkerIDFormat + `' "$f" 2>/dev/null)" != '` + id + `' ]; then echo ` + applyMarkerKept + `; exit 0; fi
` + between + `rm -rf --one-file-system "$c" 2>/dev/null
if ! mv -T "$f" "$c" 2>/dev/null; then
  if [ -e "$f" ] || [ -L "$f" ]; then echo ` + applyMarkerFailed + `; else echo ` + applyMarkerKept + `; fi
  exit 0
fi
if [ "$(stat -c '%i:%s' "$c" 2>/dev/null)" != '` + captured + `' ]; then
  mv -nT "$c" "$f" 2>/dev/null
  if [ -e "$f" ] || [ -L "$f" ]; then rm -rf --one-file-system "$c" 2>/dev/null; fi
  echo ` + applyMarkerKept + `
  exit 0
fi
rm -rf --one-file-system "$c" 2>/dev/null
echo ` + applyMarkerRemoved + `
`, nil
}

// ParseApplyMarkerCleared reads ApplyMarkerClearStaleScript's output.
func ParseApplyMarkerCleared(out string) (ApplyMarkerClearResult, error) {
	switch strings.TrimSpace(out) {
	case applyMarkerRemoved:
		return ApplyMarkerClearRemoved, nil
	case applyMarkerKept:
		return ApplyMarkerClearKept, nil
	case applyMarkerFailed:
		return ApplyMarkerClearFailed, nil
	}
	return ApplyMarkerClearUnknown, fmt.Errorf("apply marker: unexpected clear output %q", strings.TrimSpace(out))
}
