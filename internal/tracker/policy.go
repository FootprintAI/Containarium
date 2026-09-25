package tracker

import (
	"errors"
	"fmt"
	"strings"
	"time"

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
)

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

// IsReservedStateLabel reports whether label is one of ReservedStateLabels.
func IsReservedStateLabel(label string) bool {
	for _, r := range ReservedStateLabels {
		if label == r {
			return true
		}
	}
	return false
}

// LabelAllowed reports whether label matches any allow-list glob.
// Exact, case-sensitive; see MatchLabelGlob.
func (p Policy) LabelAllowed(label string) bool {
	if label == "" {
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
// first offence wrapped in ErrStateLabelReserved (run token, reserved
// state label — checked first, since it's the more specific rule) or
// ErrLabelNotAllowed. Pure: callers run it BEFORE any upstream call.
func (p Policy) CheckLabels(labels []string, runToken bool) error {
	for _, label := range labels {
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

// MatchLabelGlob matches label against pattern where '*' matches any
// run of characters (including '/' and ':' — tracker labels are not
// paths, so path.Match's separator rule would be wrong here) and every
// other character matches itself, case-sensitively. A pattern without
// '*' is an exact match.
func MatchLabelGlob(pattern, label string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == label
	}
	if !strings.HasPrefix(label, parts[0]) {
		return false
	}
	rest := label[len(parts[0]):]
	for _, mid := range parts[1 : len(parts)-1] {
		idx := strings.Index(rest, mid)
		if idx < 0 {
			return false
		}
		rest = rest[idx+len(mid):]
	}
	return strings.HasSuffix(rest, parts[len(parts)-1])
}
