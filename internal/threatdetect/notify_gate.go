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
// is news, not a repeat), when interval has passed since its last delivery,
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
	return !seen || f.Severity > prev.severity || state != prev.response || g.now().Sub(prev.at) >= g.interval
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
	g.last[f.ID] = gateEntry{at: g.now(), severity: f.Severity, response: state, releasedBy: by}
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
