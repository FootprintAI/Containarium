package tracker

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Label contract for issue-triggered role agents (#2024; PRD
// docs/product/issue-triggered-agents.md, "Label contract"; design
// docs/architecture/issue-triggered-agents.md, "Chain guards").
const (
	// LabelNeedsApproval gates an agent-filed follow-up until a human
	// removes it. Forced onto every follow-up a run-scoped token files
	// unless the connection's policy opted into auto_chain.
	LabelNeedsApproval = "agent:needs-approval"

	// The dispatcher's state labels. Written ONLY by the dispatcher's own
	// code path (#2022) — never by a run, whatever its allow-list says.
	LabelAgentQueued  = "agent:queued"
	LabelAgentRunning = "agent:running"
	LabelAgentDone    = "agent:done"
	LabelAgentFailed  = "agent:failed"
)

// ReservedStateLabels is the set a run-scoped token can never write,
// through CreateTrackerIssue or SetTrackerIssueLabels: an injected
// "mark this done" must not be able to move a dispatch's state.
var ReservedStateLabels = []string{LabelAgentQueued, LabelAgentRunning, LabelAgentDone, LabelAgentFailed}

// DefaultLabelAllowList is the design's default: role scopes, model
// routing, and the approval gate. Deliberately NOT agent:* — the state
// labels above must stay out of a run's reach.
var DefaultLabelAllowList = []string{"scope:*", "model:*", LabelNeedsApproval}

// Documented defaults for the zero values of TrackerPolicy.
const (
	DefaultMaxDepth          int32 = 3
	DefaultMaxChildrenPerRun int32 = 5
	DefaultRunTimeout              = time.Hour
)

var (
	// ErrLabelNotAllowed: a label outside the connection's allow-list.
	ErrLabelNotAllowed = errors.New("tracker: label is not in the connection's allow-list")
	// ErrStateLabelReserved: a run-scoped token tried to write one of
	// ReservedStateLabels. No allow-list entry can lift this.
	ErrStateLabelReserved = errors.New("tracker: agent state labels are written only by the dispatcher")
	// ErrLabelInvalid: a label that is not safe to put on the wire — empty,
	// padded with whitespace, or containing ',' or a control character.
	// GitLab takes labels as ONE comma-joined string and splits it back, so
	// "scope:x,agent:done" would otherwise pass the allow-list as one label
	// and land as two (review of #2034).
	ErrLabelInvalid = errors.New("tracker: label is not a valid single label")
)

// MaxLabelLength caps a label at GitHub's own limit for label names (50
// characters, counted in runes); GitLab allows longer, so the stricter
// provider sets the provider-neutral cap. Anything longer would be
// rejected upstream anyway — rejecting it here keeps the failure before
// any upstream call.
const MaxLabelLength = 50

// ValidateLabel is the provider-neutral wire-safety check for one label,
// applied by CheckLabels before any allow-list matching and again by the
// GitLab adapter as defense in depth. It rejects the empty string,
// leading/trailing whitespace, ',' (GitLab's list separator), any control
// character (line breaks and tabs included), any invisible Unicode format
// character (category Cf: zero-width space/joiner/non-joiner, BOM, bidi
// marks and overrides — they make two different labels look identical),
// and anything longer than MaxLabelLength runes. Inner spaces and
// ordinary non-ASCII letters are legal ("good first issue", accented or
// non-Latin label names).
func ValidateLabel(label string) error {
	switch {
	case label == "":
		return fmt.Errorf("%w: %q is empty", ErrLabelInvalid, label)
	case strings.TrimSpace(label) != label:
		return fmt.Errorf("%w: %q has leading or trailing whitespace", ErrLabelInvalid, label)
	case strings.ContainsRune(label, ','):
		return fmt.Errorf("%w: %q contains ','", ErrLabelInvalid, label)
	case utf8.RuneCountInString(label) > MaxLabelLength:
		return fmt.Errorf("%w: %q is longer than %d characters", ErrLabelInvalid, label, MaxLabelLength)
	}
	for _, r := range label {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: %q contains a control character", ErrLabelInvalid, label)
		}
		if unicode.Is(unicode.Cf, r) {
			return fmt.Errorf("%w: %q contains an invisible format character", ErrLabelInvalid, label)
		}
	}
	return nil
}

// Policy is the effective, defaults-applied form of a connection's
// TrackerPolicy. Build it with PolicyFromProto; never read the proto's
// zero values directly.
type Policy struct {
	LabelAllowList    []string
	AutoChain         bool
	MaxDepth          int32
	MaxChildrenPerRun int32
	RunTimeout        time.Duration
}

// PolicyFromProto applies the documented defaults: a nil message or a
// zero-valued field means "default", so an operator who never set a
// policy and one who set an empty one get the same behavior.
func PolicyFromProto(p *pb.TrackerPolicy) Policy {
	out := Policy{
		LabelAllowList:    append([]string(nil), DefaultLabelAllowList...),
		MaxDepth:          DefaultMaxDepth,
		MaxChildrenPerRun: DefaultMaxChildrenPerRun,
		RunTimeout:        DefaultRunTimeout,
	}
	if p == nil {
		return out
	}
	if len(p.GetLabelAllowList()) > 0 {
		out.LabelAllowList = append([]string(nil), p.GetLabelAllowList()...)
	}
	out.AutoChain = p.GetAutoChain()
	if p.GetMaxDepth() > 0 {
		out.MaxDepth = p.GetMaxDepth()
	}
	if p.GetMaxChildrenPerRun() > 0 {
		out.MaxChildrenPerRun = p.GetMaxChildrenPerRun()
	}
	if p.GetRunTimeoutSeconds() > 0 {
		out.RunTimeout = time.Duration(p.GetRunTimeoutSeconds()) * time.Second
	}
	return out
}

// IsReservedStateLabel reports whether label is one of ReservedStateLabels,
// compared after trimming and case-insensitively — GitHub label names are
// case-insensitive, so "Agent:Done" IS the dispatcher's state label there.
func IsReservedStateLabel(label string) bool {
	label = strings.TrimSpace(label)
	for _, r := range ReservedStateLabels {
		if strings.EqualFold(label, r) {
			return true
		}
	}
	return false
}

// LabelAllowed reports whether label matches any allow-list glob.
// Exact, case-sensitive; see MatchLabelGlob.
func (p Policy) LabelAllowed(label string) bool {
	if ValidateLabel(label) != nil {
		return false
	}
	for _, pattern := range p.LabelAllowList {
		if MatchLabelGlob(pattern, label) {
			return true
		}
	}
	return false
}

// CheckLabels validates every label against the policy, returning the
// first offence wrapped in ErrLabelInvalid (not a single wire-safe label —
// checked before anything else, so no glob can admit a smuggled second
// label), ErrStateLabelReserved (run token, reserved state label, any
// case) or ErrLabelNotAllowed. Pure: callers run it BEFORE any upstream
// call, on labels they have already trimmed.
func (p Policy) CheckLabels(labels []string, runToken bool) error {
	for _, label := range labels {
		if err := ValidateLabel(label); err != nil {
			return err
		}
		if runToken && IsReservedStateLabel(label) {
			return fmt.Errorf("%w: %q", ErrStateLabelReserved, label)
		}
		if !p.LabelAllowed(label) {
			return fmt.Errorf("%w: %q", ErrLabelNotAllowed, label)
		}
	}
	return nil
}

// DepthAllowed reports whether a child at depth may be created. A
// non-positive MaxDepth means unlimited (only reachable by constructing
// Policy directly; PolicyFromProto always defaults it).
func (p Policy) DepthAllowed(depth int32) bool {
	return p.MaxDepth <= 0 || depth <= p.MaxDepth
}

// FanoutAllowed reports whether a run that has already created
// existing children may create one more.
func (p Policy) FanoutAllowed(existing int32) bool {
	return p.MaxChildrenPerRun <= 0 || existing < p.MaxChildrenPerRun
}

// MatchLabelGlob matches label against pattern where '*' matches ONE or
// more characters (including '/' and ':' — tracker labels are not paths,
// so path.Match's separator rule would be wrong here; one-or-more so
// "scope:*" does not admit a bare "scope:") and every other character
// matches itself, case-sensitively. A pattern without '*' is an exact
// match. Wire safety (',' etc.) is ValidateLabel's job, checked first.
func MatchLabelGlob(pattern, label string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == label
	}
	parts := strings.Split(pattern, "*")
	var b strings.Builder
	b.WriteString(`\A`)
	for i, part := range parts {
		if i > 0 {
			b.WriteString(`.+`)
		}
		b.WriteString(regexp.QuoteMeta(part))
	}
	b.WriteString(`\z`)
	re, err := regexp.Compile(`(?s)` + b.String())
	if err != nil {
		return false // unreachable: every literal is QuoteMeta'd
	}
	return re.MatchString(label)
}
