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

// deliveryGate decides which store writes reach the webhook. The stores call
// Notify on every write, including the dedupe path that only bumps count on
// an already-open (rule, tenant, subject); delivering all of those turns one
// persistent condition into an alert every evaluation cycle. The row dedupes
// (#1640); this makes the delivery dedupe too.
//
// A finding is delivered when it is new to the gate, when its severity
// escalates, when interval has passed since its last delivery, and once when
// it resolves. State is in memory: after a restart an open finding is
// delivered again on its next write, which is a re-notify, not a storm.
type deliveryGate struct {
	mu       sync.Mutex
	interval time.Duration
	now      func() time.Time
	last     map[int64]gateEntry
}

type gateEntry struct {
	at       time.Time
	severity pb.ThreatSeverity
}

func newDeliveryGate(interval time.Duration) *deliveryGate {
	if interval <= 0 {
		interval = DefaultRenotifyInterval
	}
	return &deliveryGate{interval: interval, now: time.Now, last: map[int64]gateEntry{}}
}

// shouldDeliver reports whether f should reach the webhook. It does not
// record anything: call delivered once the finding was actually queued, so a
// dropped delivery does not suppress the next attempt.
func (g *deliveryGate) shouldDeliver(f *Finding) bool {
	if f.ID == 0 {
		return true // cannot be tracked; fail open
	}
	if f.State == FindingStateResolved {
		return true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	prev, seen := g.last[f.ID]
	return !seen || f.Severity > prev.severity || g.now().Sub(prev.at) >= g.interval
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
	now := g.now()
	g.last[f.ID] = gateEntry{at: now, severity: f.Severity}
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
