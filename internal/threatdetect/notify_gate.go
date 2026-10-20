package threatdetect

import (
	"sync"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// DefaultRenotifyInterval is how long an open finding stays quiet on the
// webhook after a delivery before a repeat of the same condition is
// delivered again (#2643).
const DefaultRenotifyInterval = time.Hour

// gateMaxEntries bounds the per-finding memory. A finding that never resolves
// keeps its entry; past the cap the oldest entry goes, which at worst
// re-delivers that one finding early.
const gateMaxEntries = 4096

// releaseResolveWindow bounds the release+resolve coalescing: a resolve is
// dropped as the second half of an operator release only when it lands this
// soon after the RELEASED delivery (see deliveryGate).
const releaseResolveWindow = 30 * time.Second

// deliveryGate decides which store writes reach the webhook. The stores call
// Notify on every write, including the dedupe path that only bumps count on
// an already-open (rule, tenant, subject); delivering all of those turns one
// persistent condition into an alert every evaluation cycle. The row dedupes
// (#1640); this makes the delivery dedupe too.
//
// A finding is delivered when it is new to the gate, when its severity
// escalates, when its response state changes (#2718: NONE→APPLIED,
// APPLIED→RELEASED/EXPIRED, anything→FAILED — what the process responder did
// is news, not a repeat), when its kill outcome changes (#2775: the first kill
// and the first skipped kill at once, later ones at most once per
// KillRenotifyInterval with the latest pid and the kill count), when interval has passed since its last delivery,
// and once when it resolves. State is in memory: after a restart an open
// finding is delivered again on its next write, which is a re-notify, not a
// storm.
//
// Release + resolve is one delivery, not two: an operator release
// (ProcessResponder.Release) records RELEASED and then resolves the finding in
// the same call. The RELEASED write is delivered; the resolve that follows it
// is not, because it carries nothing the operator was not just told. The
// release is the one kept, not the resolve, so the operator still hears of it
// when the resolve fails. The coalescing is bounded: only a resolve landing
// within releaseResolveWindow of the RELEASED delivery is dropped, and only
// once, so if the release's own resolve failed, a later resolve is delivered.
// Only an operator release coalesces: a TTL expiry or an orphan-sweep release
// leaves the finding open, so a later resolve is a separate event and is
// delivered.
type deliveryGate struct {
	mu       sync.Mutex
	interval time.Duration
	now      func() time.Time
	last     map[int64]gateEntry
}

type gateEntry struct {
	at         time.Time
	severity   pb.ThreatSeverity
	response   pb.ResponseState
	releasedBy string
	kill       killKey
	killAt     time.Time // when a changed kill outcome was last delivered
	// skipSent: a skipped kill has been delivered for this finding. The
	// "first skip is immediate" fast path fires once per finding; a delivered
	// kill clears the skip on the delivered entry, so the entry's kill alone
	// cannot tell a first skip from a later one (#2775 review).
	skipSent bool
}

// KillRenotifyInterval bounds the webhook posts a respawning miner can cause
// (#2775): the first kill and the first skipped kill of a finding are
// delivered at once, and any later change in its kill outcome (another pid,
// a higher kill count, another skip reason) at most once per interval,
// carrying the latest pid and the count. A change that lands inside the
// interval is held back until the finding's next write after it, so the
// webhook never sees one post per kill.
const KillRenotifyInterval = time.Minute

// killKey is the kill outcome on a finding's response: a change in it is news
// (#2775). Under ALERT a kill leaves the response state at NONE, so the state
// alone never shows it.
type killKey struct {
	killed bool
	pid    uint32
	kills  uint32
	skip   pb.KillSkipReason
}

func killOf(f *Finding) killKey {
	if f.Response == nil {
		return killKey{}
	}
	r := f.Response
	return killKey{r.ProcessKilled, r.KilledPID, r.Kills, r.KillSkipReason}
}

// killNews reports whether f's kill outcome should reach the webhook now,
// given what was last delivered for it. Skipped kills are keyed on the reason
// kind, never on text, so a process that exits before every kill is one
// delivery, not one per pid. The first kill and the first skip of a finding
// are each immediate exactly once; after that a changed outcome waits for
// KillRenotifyInterval, so a miner that alternately dies and escapes the
// signal is one post per interval, not two.
func killNews(prev gateEntry, f *Finding, now time.Time) bool {
	cur := killOf(f)
	if cur == prev.kill {
		return false
	}
	if cur.killed && !prev.kill.killed {
		return true // the first kill
	}
	if cur.skip != pb.KillSkipReason_KILL_SKIP_REASON_UNSPECIFIED && !prev.skipSent {
		return true // the first skip
	}
	changed := cur.killed && (cur.pid != prev.kill.pid || cur.kills != prev.kill.kills) ||
		cur.skip != pb.KillSkipReason_KILL_SKIP_REASON_UNSPECIFIED && cur.skip != prev.kill.skip
	return changed && now.Sub(prev.killAt) >= KillRenotifyInterval
}

// responseOf is f's response state and who released it; no response yet is
// NONE.
func responseOf(f *Finding) (pb.ResponseState, string) {
	if f.Response == nil {
		return pb.ResponseState_RESPONSE_STATE_NONE, ""
	}
	return f.Response.State, f.Response.ReleasedBy
}

// releaseResolve reports whether a resolve of f, at now, only repeats the
// operator release just delivered for it (see deliveryGate).
func releaseResolve(prev gateEntry, f *Finding, now time.Time) bool {
	state, by := responseOf(f)
	return prev.response == pb.ResponseState_RESPONSE_STATE_RELEASED && prev.releasedBy == ReleasedByOperator &&
		state == prev.response && by == prev.releasedBy && now.Sub(prev.at) < releaseResolveWindow
}

func newDeliveryGate(interval time.Duration) *deliveryGate {
	if interval <= 0 {
		interval = DefaultRenotifyInterval
	}
	return &deliveryGate{interval: interval, now: time.Now, last: map[int64]gateEntry{}}
}

// shouldDeliver reports whether f should reach the webhook. It records
// nothing for a delivery: call delivered once the finding was actually
// queued, so a dropped delivery does not suppress the next attempt. A
// resolve it suppresses (the second half of an operator release) forgets the
// finding, since delivered will not be called for it.
func (g *deliveryGate) shouldDeliver(f *Finding) bool {
	if f.ID == 0 {
		return true // cannot be tracked; fail open
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	prev, seen := g.last[f.ID]
	if f.State == FindingStateResolved {
		if seen && releaseResolve(prev, f, g.now()) {
			delete(g.last, f.ID) // forgotten: coalesced once, the next resolve delivers
			return false
		}
		return true
	}
	state, _ := responseOf(f)
	return !seen || f.Severity > prev.severity || state != prev.response || killNews(prev, f, g.now()) || g.now().Sub(prev.at) >= g.interval
}

// delivered records that f was queued. A resolved finding is forgotten: it
// can no longer repeat.
func (g *deliveryGate) delivered(f *Finding) {
	if f.ID == 0 {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if f.State == FindingStateResolved {
		delete(g.last, f.ID)
		return
	}
	state, by := responseOf(f)
	now := g.now()
	e := gateEntry{at: now, severity: f.Severity, response: state, releasedBy: by, kill: killOf(f)}
	e.skipSent = e.kill.skip != pb.KillSkipReason_KILL_SKIP_REASON_UNSPECIFIED
	if prev, ok := g.last[f.ID]; ok {
		e.skipSent = e.skipSent || prev.skipSent
		if prev.kill == e.kill {
			e.killAt = prev.killAt
		} else {
			e.killAt = now
		}
	} else {
		e.killAt = now
	}
	g.last[f.ID] = e
	if len(g.last) > gateMaxEntries {
		g.evictOldest()
	}
}

func (g *deliveryGate) evictOldest() {
	var oldestID int64
	var oldest time.Time
	first := true
	for id, e := range g.last {
		if first || e.at.Before(oldest) {
			oldestID, oldest, first = id, e.at, false
		}
	}
	delete(g.last, oldestID)
}
