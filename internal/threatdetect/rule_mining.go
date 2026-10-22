package threatdetect

import (
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/footprintai/containarium/internal/netbpf"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// DestinationMatcher reports whether ip is on the known-bad-destination
// list, and the matching entry's CIDR. *BadDestinationRule satisfies it; the
// mining-behavior rule takes it injected so a listed pool qualifies on any
// port.
type DestinationMatcher interface {
	MatchDestination(ip netip.Addr) (cidr string, ok bool)
}

type miningCPUPoint struct {
	at    time.Time
	cores float64
}

// Coverage and bound for a container's CPU history (review of #2647). None
// depends on the spacing between samples: inferring the collector's tick
// from observed gaps let a single short gap blind the rule.
const (
	// miningMinCoverage: the oldest sample inside the window must be at
	// least this fraction of the window old.
	miningMinCoverage = 0.8
	// miningMinSamples: at least this many samples must be in the window.
	miningMinSamples = 3
	// miningMaxPoints is the hard cap on samples kept per container.
	miningMaxPoints = 256

	// miningAssumedMinTick is the shortest collector sample interval the
	// window bound assumes (the default tick).
	miningAssumedMinTick = 30 * time.Second

	// MaxMiningWindow is the longest window the rule accepts. At most
	// miningMaxPoints samples are kept, so at the assumed minimum tick the
	// history spans miningMaxPoints x 30s = 128 min. Coverage needs the
	// oldest in-window sample to be >= miningMinCoverage x window old, so
	// a window above 256 x 30s / 0.8 = 160 min can never be satisfied and
	// the rule would silently never fire. 128 min (the full history span,
	// rounded down to the minute) is the accepted cap: inside that hard
	// limit with headroom for a tick a little above 30s.
	MaxMiningWindow = time.Duration(miningMaxPoints) * miningAssumedMinTick / time.Minute * time.Minute

	// MinMiningWindow is the shortest window the rule accepts. The sweep keeps
	// samples newer than now-window, so at the assumed tick the oldest
	// retained sample is at most window-tick old; coverage demands
	// miningMinCoverage x window. Those meet only when
	// (1-miningMinCoverage) x window >= tick, i.e. window >= 150s at 30s; a
	// shorter window is accepted by the CLI and then silently never fires
	// (#2674). Six ticks (3 min) is that limit with headroom for sweep jitter.
	MinMiningWindow = 6 * miningAssumedMinTick
)

// miningContainer is one container's CPU history.
type miningContainer struct {
	ip     netip.Addr
	limit  float64 // latest sample's limits.cpu, in cores
	lastAt time.Time
	points []miningCPUPoint // oldest first
}

// trim bounds the history whether or not Sweep runs: points older than
// 2 x window behind the newest go, and at most miningMaxPoints are kept
// (oldest dropped), which also bounds a stuck clock that repeats one
// timestamp.
func (c *miningContainer) trim(window time.Duration) {
	if len(c.points) == 0 {
		return
	}
	cutoff := c.points[len(c.points)-1].at.Add(-2 * window)
	drop := 0
	for drop < len(c.points) && !c.points[drop].at.After(cutoff) {
		drop++
	}
	if len(c.points)-drop > miningMaxPoints {
		drop = len(c.points) - miningMaxPoints
	}
	if drop > 0 {
		c.points = append(c.points[:0], c.points[drop:]...)
	}
}

type miningFlowKey struct {
	src, dst     netip.Addr
	sport, dport uint16
	proto        uint8
}

// miningFlow is a candidate flow: to a stratum port or a listed destination.
type miningFlow struct {
	rec     netbpf.FlowRecord
	seenAt  time.Time // last flow poll that reported it
	matched string    // "bad-destination:<cidr>" or "port:<n>"
}

// MiningBehaviorRule implements Rule and CPUConsumer for
// THREAT_RULE_ID_MINING_BEHAVIOR (#2635): a container whose mean CPU over
// the window reaches the bar while it holds a flow, at least flow_min_age
// old and seen within the window, to a stratum port or a listed
// destination. Signals only accumulate on OnCPU/OnFlows; Sweep evaluates.
// While the condition holds every sweep re-fires the same subject
// (destination ip:port) and the finding store dedupes it into one open
// finding, so a second pool opens a second finding.
type MiningBehaviorRule struct {
	matcher DestinationMatcher // nil: stratum ports only

	mu         sync.Mutex
	containers map[string]*miningContainer
	flows      map[netip.Addr]map[miningFlowKey]*miningFlow // by source (container) IP
}

// NewMiningBehaviorRule builds the rule. matcher may be nil.
func NewMiningBehaviorRule(matcher DestinationMatcher) *MiningBehaviorRule {
	return &MiningBehaviorRule{
		matcher:    matcher,
		containers: make(map[string]*miningContainer),
		flows:      make(map[netip.Addr]map[miningFlowKey]*miningFlow),
	}
}

func (r *MiningBehaviorRule) ID() pb.ThreatRuleId {
	return pb.ThreatRuleId_THREAT_RULE_ID_MINING_BEHAVIOR
}

func miningThresholds(ctx RuleContext) MiningThresholds {
	if ctx.MiningThresholds == nil {
		return DefaultMiningThresholds()
	}
	return ctx.MiningThresholds()
}

// OnCPU appends each sample to its container's bounded history. Never
// fires.
func (r *MiningBehaviorRule) OnCPU(ctx RuleContext, samples []CPUSample) []RawFinding {
	window := miningThresholds(ctx).Window
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range samples {
		c := r.containers[s.Container]
		if c == nil {
			c = &miningContainer{}
			r.containers[s.Container] = c
		}
		c.ip = s.IP
		c.limit = s.LimitCores
		c.lastAt = s.At
		c.points = append(c.points, miningCPUPoint{at: s.At, cores: s.Cores})
		c.trim(window)
	}
	return nil
}

// OnFlows records candidate flows. Never fires.
func (r *MiningBehaviorRule) OnFlows(ctx RuleContext, flows []netbpf.FlowRecord) []RawFinding {
	th := miningThresholds(ctx)
	now := ctx.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, f := range flows {
		// A list entry names the pool, so it wins over a bare port match.
		var matched string
		if cidr, ok := r.listed(f.Dst()); ok {
			matched = "bad-destination:" + cidr
		} else if th.isStratumPort(f.Dport) {
			matched = "port:" + strconv.Itoa(int(f.Dport))
		} else {
			continue
		}
		src := f.Src()
		byKey := r.flows[src]
		if byKey == nil {
			byKey = make(map[miningFlowKey]*miningFlow)
			r.flows[src] = byKey
		}
		byKey[miningFlowKey{src: src, dst: f.Dst(), sport: f.Sport, dport: f.Dport, proto: f.Proto}] = &miningFlow{rec: f, seenAt: now, matched: matched}
	}
	return nil
}

func (r *MiningBehaviorRule) listed(ip netip.Addr) (string, bool) {
	if r.matcher == nil {
		return "", false
	}
	return r.matcher.MatchDestination(ip)
}

// OnDeny is a no-op: the rule reads CPU and flows only.
func (r *MiningBehaviorRule) OnDeny(RuleContext, netbpf.DenyEvent) []RawFinding { return nil }

// Sweep prunes state to the window, expires containers silent for
// 2 x window, and fires one HIGH finding per qualifying destination of each
// container whose CPU mean over a fully covered window reaches the bar.
func (r *MiningBehaviorRule) Sweep(ctx RuleContext, now time.Time) []RawFinding {
	th := miningThresholds(ctx)
	cutoff := now.Add(-th.Window)
	r.mu.Lock()
	defer r.mu.Unlock()

	for src, byKey := range r.flows {
		for k, f := range byKey {
			if !f.seenAt.After(cutoff) {
				delete(byKey, k)
			}
		}
		if len(byKey) == 0 {
			delete(r.flows, src)
		}
	}

	var out []RawFinding
	for name, c := range r.containers {
		if now.Sub(c.lastAt) > 2*th.Window {
			delete(r.containers, name)
			continue
		}
		kept := c.points[:0]
		for _, p := range c.points {
			if p.at.After(cutoff) {
				kept = append(kept, p)
			}
		}
		c.points = kept
		// The mean must cover the window, not a burst at its end or a lone
		// sample after a gap: enough samples, the oldest at least
		// miningMinCoverage x window old.
		if len(kept) < miningMinSamples || float64(now.Sub(kept[0].at)) < miningMinCoverage*float64(th.Window) {
			continue
		}
		var sum, peak float64
		for _, p := range kept {
			sum += p.cores
			peak = max(peak, p.cores)
		}
		mean := sum / float64(len(kept))
		if mean < th.Bar(c.limit) {
			continue
		}
		best := map[string]*miningFlow{} // subject -> longest-lived flow
		for _, f := range r.flows[c.ip] {
			age := f.rec.LastNs - f.rec.FirstNs
			if f.rec.LastNs < f.rec.FirstNs || time.Duration(age) < th.FlowMinAge { // #nosec G115 -- age bounded by uptime
				continue
			}
			subject := netip.AddrPortFrom(f.rec.Dst(), f.rec.Dport).String()
			if prev, ok := best[subject]; !ok || age > prev.rec.LastNs-prev.rec.FirstNs {
				best[subject] = f
			}
		}
		if len(best) == 0 {
			continue
		}
		tenantID, _ := ctx.TenantForIP(c.ip)
		cpu := CPUEvidence{
			MeanCores:     mean,
			PeakCores:     peak,
			WindowSeconds: int64(th.Window / time.Second),
			Samples:       int32(min(len(kept), 1<<31-1)), // #nosec G115 -- clamped
		}
		for subject, mf := range best {
			f := mf.rec
			// The kernel stamps are monotonic, so anchor on the poll that
			// reported the flow, as flowsToEBPF does for the traffic view.
			age := time.Duration(f.LastNs - f.FirstNs) // #nosec G115 -- LastNs >= FirstNs checked above
			out = append(out, RawFinding{
				Rule:      pb.ThreatRuleId_THREAT_RULE_ID_MINING_BEHAVIOR,
				Severity:  pb.ThreatSeverity_THREAT_SEVERITY_HIGH,
				TenantID:  tenantID,
				Container: name,
				Subject:   subject,
				Evidence: Evidence{
					CPU: []CPUEvidence{cpu},
					Flows: []FlowEvidence{{
						SrcIP:     f.Src().String(),
						DstIP:     f.Dst().String(),
						SrcPort:   uint32(f.Sport),
						DstPort:   uint32(f.Dport),
						Protocol:  badDestProtoName(f.Proto),
						Bytes:     int64(f.Bytes),   // #nosec G115 -- one flow's counters
						Packets:   int64(f.Packets), // #nosec G115 -- one flow's counters
						FirstSeen: mf.seenAt.Add(-age),
						LastSeen:  mf.seenAt,
						Matched:   mf.matched,
					}},
				},
			})
		}
	}
	return out
}

// trackedContainers is for tests: how many containers hold CPU state.
func (r *MiningBehaviorRule) trackedContainers() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.containers)
}

// pointCount is for tests: how many CPU points a container holds.
func (r *MiningBehaviorRule) pointCount(container string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c := r.containers[container]; c != nil {
		return len(c.points)
	}
	return 0
}
