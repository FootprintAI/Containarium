// Package submit implements #1923's "no push credential in the box" change
// submission path: extracting a git bundle from the box, pushing it from a
// fresh temporary bare repository on the host, and handing the result to a
// provider adapter's OpenChange.
package submit

import (
	"regexp"
	"strconv"
	"strings"
)

// runIDShortLen matches internal/tracker.Stamp's own truncation length —
// the branch name and the identity stamp should show the same short id
// for the same run, so an operator correlating a branch to a signature
// line sees matching prefixes. Not imported from internal/tracker
// (unexported there) because this package must not depend on it: submit
// is called by the gRPC service after identity/audit have already run,
// not by the core package itself.
const runIDShortLen = 12

// slugMaxLen bounds the human-readable portion of a daemon-chosen
// branch name. Long enough to be recognizable, short enough that a
// pathological title (or one deliberately crafted to be huge) can't
// produce an oversized ref name upstream providers may reject.
const slugMaxLen = 40

// nonSlugRun matches one or more characters that don't belong in a
// slug — anything but ASCII letters, digits, and hyphen.
var nonSlugRun = regexp.MustCompile(`[^a-z0-9]+`)

// slugify lowercases s and collapses every run of non-alphanumeric
// characters to a single hyphen, trimming leading/trailing hyphens and
// capping the result at slugMaxLen. The empty string in means the
// empty string out — BranchName handles that case by omitting the
// slug's leading hyphen rather than calling this on a title that isn't
// there.
func slugify(s string) string {
	s = strings.ToLower(s)
	s = nonSlugRun.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if len(s) > slugMaxLen {
		s = strings.Trim(s[:slugMaxLen], "-")
	}
	return s
}

// runIDShort truncates runID to runIDShortLen, same rule as
// internal/tracker.Stamp.
func runIDShort(runID string) string {
	if len(runID) > runIDShortLen {
		return runID[:runIDShortLen]
	}
	return runID
}

// BranchName returns the daemon-chosen branch a submit pushes to:
// agent/<run-id-short>/<issue>-<slug>. It is a pure function of values
// the daemon already trusts (the verified run id and the issue number
// SubmitTrackerChange resolved against the connection) plus the
// human-supplied title, which only ever contributes a cosmetic slug —
// title cannot influence the run-id or issue segments, and slugify
// strips every character that would let it break out of the ref
// shape. This is what makes "the agent cannot name a ref" true: no
// caller of this package ever has a way to pass a raw branch string
// through to GitPusher.PushBundle.
func BranchName(runID string, issueNumber int64, title string) string {
	if issueNumber < 0 {
		issueNumber = 0
	}
	slug := slugify(title)
	base := runIDShort(runID) + "/" + strconv.FormatInt(issueNumber, 10)
	if slug == "" {
		return "agent/" + base
	}
	return "agent/" + base + "-" + slug
}
