package tracker

import (
	"fmt"
	"regexp"
	"strings"
)

// Identity is the platform-verified attribution for one write. Built
// only from a verified JWT's claims and the run record they resolve
// to — never from request fields, so a caller cannot forge or
// influence it. See Stamp.
type Identity struct {
	RunID   string
	SkillID string
	// Model is the skill manifest's declared model tier; empty when the
	// manifest declares none, in which case Stamp omits the parenthesized
	// model segment entirely rather than printing "()".
	Model string
}

// StampKind labels what kind of write a marker is attached to.
// ClaimTrackerIssue's claim-detection scan looks specifically for
// KindClaim.
type StampKind string

const (
	KindClaim   StampKind = "claim"
	KindComment StampKind = "comment"
	KindChange  StampKind = "change"
)

// runIDShortLen bounds the run id shown in the visible signature line —
// long enough to be useful for a human glancing at the tracker, short
// enough not to dominate the line. The full run id is always in the
// hidden marker and the audit log regardless.
const runIDShortLen = 12

// Stamp renders the visible signature line and the hidden
// machine-readable marker appended to every brokered write:
//
//	— <skill>/<run-id-short> (<model>) via Containarium
//	<!-- containarium:run=<run_id> skill=<skill_id> kind=<kind> -->
//
// Every value comes from id, which callers build from verified JWT
// claims and the run record — never from request fields. See
// TestStamp_FromClaimsOnly.
func Stamp(id Identity, kind StampKind) string {
	runShort := id.RunID
	if len(runShort) > runIDShortLen {
		runShort = runShort[:runIDShortLen]
	}
	visible := fmt.Sprintf("— %s/%s", id.SkillID, runShort)
	if id.Model != "" {
		visible += fmt.Sprintf(" (%s)", id.Model)
	}
	visible += " via Containarium"
	marker := fmt.Sprintf("<!-- containarium:run=%s skill=%s kind=%s -->", id.RunID, id.SkillID, kind)
	return visible + "\n" + marker
}

// markerPattern matches Stamp's own hidden marker. Used to detect an
// existing claim when scanning an issue's comments.
var markerPattern = regexp.MustCompile(`<!-- containarium:run=(\S+) skill=(\S+) kind=(\S+) -->`)

// ParseMarker extracts a Stamp marker from body, if present. Scans for
// the LAST match — a body may legitimately contain more than one if a
// provider concatenates edit history, and the most recent stamp is the
// one that matters.
func ParseMarker(body string) (runID, skillID string, kind StampKind, ok bool) {
	matches := markerPattern.FindAllStringSubmatch(body, -1)
	if len(matches) == 0 {
		return "", "", "", false
	}
	last := matches[len(matches)-1]
	return last[1], last[2], StampKind(last[3]), true
}

// markerPrefix is the literal substring that makes a marker
// machine-readable. Stripping it is enough to break ParseMarker's
// match on anything agent-supplied — the rest of a forged attempt is
// left as inert text, not hidden as a real marker would be.
const markerPrefix = "<!-- containarium:"

// Sanitize prepares agent-supplied text to be posted upstream. Agent
// text is data; it must never carry provider commands or forge a
// platform marker:
//
//   - The hidden marker syntax ("<!-- containarium:") is stripped, so a
//     run cannot forge a claim/comment/change marker by including one in
//     a comment body.
//   - GitLab quick-action lines (first non-space character "/" followed
//     by a letter) get a zero-width space (U+200B) inserted before the
//     slash, checked line-by-line and applied both inside and outside
//     code fences — relying on fence parsing to match GitLab's own
//     parser would be a parser-differential bug waiting to happen.
//
// Content flowing the OTHER way (issue bodies returned to the agent) is
// never sanitized — it's returned as plain fields and never interpreted,
// so there's nothing to protect it from.
func Sanitize(body string) string {
	body = strings.ReplaceAll(body, markerPrefix, "")
	return neutralizeQuickActions(body)
}

// quickActionLineStart matches a line whose first non-space character is
// "/" followed by a letter (e.g. "/assign", "  /close").
var quickActionLineStart = regexp.MustCompile(`^(\s*)(/)([A-Za-z])`)

func neutralizeQuickActions(body string) string {
	lines := strings.Split(body, "\n")
	for i, line := range lines {
		loc := quickActionLineStart.FindStringSubmatchIndex(line)
		if loc == nil {
			continue
		}
		slashStart := loc[4] // start of capture group 2, the "/"
		lines[i] = line[:slashStart] + "\u200b" + line[slashStart:]
	}
	return strings.Join(lines, "\n")
}
