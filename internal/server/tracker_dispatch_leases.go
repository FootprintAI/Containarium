package server

import (
	"context"
	"log"
	"strings"
	"sync"

	"github.com/footprintai/containarium/internal/runlease"
	"github.com/footprintai/containarium/internal/tracker"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otelmetric "go.opentelemetry.io/otel/metric"
)

// Failure visibility, server half (#2026): the production RunStarter is
// also the dispatcher's tracker.RunLeases — which dispatched runs this
// daemon holds, and a way to end a timed-out one's lease — and the
// daemon emits the dispatcher's terminal events as OTel metrics.

// dispatchedRuns is the set of tracker-dispatched runs this daemon
// holds. A run enters it when StartRun begins (before provisioning) and
// leaves it only after its end has been reported to the dispatch row,
// so the sweep can never see a run that is merely finishing as lost.
type dispatchedRuns struct {
	mu   sync.Mutex
	runs map[string]*dispatchedRun
}

// dispatchedRun is one entry: its lease once provisioned, and whether
// that lease has been ended (by the run's own end or by the sweep —
// whichever comes first; the other is a no-op).
type dispatchedRun struct {
	mu    sync.Mutex
	lease *runlease.Lease
	ended bool
}

// track returns runID's entry, creating it if needed.
func (d *dispatchedRuns) track(runID string) *dispatchedRun {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.runs == nil {
		d.runs = map[string]*dispatchedRun{}
	}
	h, ok := d.runs[runID]
	if !ok {
		h = &dispatchedRun{}
		d.runs[runID] = h
	}
	return h
}

func (d *dispatchedRuns) get(runID string) (*dispatchedRun, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	h, ok := d.runs[runID]
	return h, ok
}

func (d *dispatchedRuns) untrack(runID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.runs, runID)
}

func (h *dispatchedRun) setLease(l runlease.Lease) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lease = &l
}

// endDispatchedLease ends h's lease once. A run still provisioning has
// no lease yet: nothing to end here (a failed provisioning cleans up
// after itself; a successful one whose row was failed meanwhile is torn
// down by launchDispatchedRun).
func (s *AgentSkillServer) endDispatchedLease(ctx context.Context, h *dispatchedRun, reason string) {
	h.mu.Lock()
	if h.ended || h.lease == nil {
		h.mu.Unlock()
		return
	}
	h.ended = true
	lease := *h.lease
	h.mu.Unlock()
	s.endRunLease(ctx, lease, s.boxWiper(), reason)
}

var _ tracker.RunLeases = trackerRunStarter{}

// Live reports whether runID is a dispatched run this daemon holds.
func (r trackerRunStarter) Live(runID string) bool {
	_, ok := r.agents.dispatched.get(runID)
	return ok
}

// End ends a dispatched run's lease for the sweep: its JWTs are revoked
// and its seed wiped, so whatever the in-box agent is still doing, it
// can no longer write through the broker. The run's own end, when the
// agent returns, then finds the lease already ended and its report a
// lost compare-and-set.
func (r trackerRunStarter) End(ctx context.Context, runID string) {
	h, ok := r.agents.dispatched.get(runID)
	if !ok {
		return
	}
	h.mu.Lock()
	provisioned := h.lease != nil
	h.mu.Unlock()
	if !provisioned {
		// Its row is already terminal, so its start report will lose the
		// compare-and-set and launchDispatchedRun tears it down then.
		log.Printf("[tracker] dispatched run %s: timed out while still provisioning; its lease is ended when provisioning returns", runID)
		return
	}
	r.agents.endDispatchedLease(ctx, h, dispatchSweepReason)
}

// Metric names for the PRD's success metrics.
const (
	trackerDispatchTerminalMetric = "containarium.tracker.dispatch.terminal"
	trackerDispatchLatencyMetric  = "containarium.tracker.dispatch.result_latency"
)

// trackerDispatchObserver emits tracker.DispatchEnded as OTel metrics:
// a terminal-state counter by state, failure cause and scope, and the
// label-applied -> result latency histogram.
type trackerDispatchObserver struct {
	terminal otelmetric.Int64Counter
	latency  otelmetric.Float64Histogram
}

var _ tracker.DispatchObserver = (*trackerDispatchObserver)(nil)

func newTrackerDispatchObserver(meter otelmetric.Meter) (*trackerDispatchObserver, error) {
	terminal, err := meter.Int64Counter(trackerDispatchTerminalMetric,
		otelmetric.WithDescription("Tracker dispatches that reached a terminal state, by state, failure cause and scope"))
	if err != nil {
		return nil, err
	}
	latency, err := meter.Float64Histogram(trackerDispatchLatencyMetric,
		otelmetric.WithDescription("Time from a dispatch's agent:queued label to its result (done or failed)"),
		otelmetric.WithUnit("s"),
		otelmetric.WithExplicitBucketBoundaries(10, 30, 60, 120, 300, 600, 1200, 1800, 3600, 7200, 14400))
	if err != nil {
		return nil, err
	}
	return &trackerDispatchObserver{terminal: terminal, latency: latency}, nil
}

// DispatchEnded records one terminal transition. Attribute values come
// from the proto enum names ("done", "failed"; "none", "timeout", ...).
func (o *trackerDispatchObserver) DispatchEnded(ev tracker.DispatchEnded) {
	failure := "none"
	if ev.Failure != pb.TrackerDispatchFailure_TRACKER_DISPATCH_FAILURE_UNSPECIFIED {
		failure = strings.ToLower(strings.TrimPrefix(ev.Failure.String(), "TRACKER_DISPATCH_FAILURE_"))
	}
	state := strings.ToLower(strings.TrimPrefix(ev.State.String(), "TRACKER_DISPATCH_STATE_"))
	set := otelmetric.WithAttributes(
		attribute.String("state", state),
		attribute.String("failure", failure),
		attribute.String("scope", ev.Scope),
	)
	ctx := context.Background()
	o.terminal.Add(ctx, 1, set)
	o.latency.Record(ctx, ev.Latency.Seconds(), set)
}

var (
	globalTrackerDispatchObserverOnce sync.Once
	globalTrackerDispatchObserver     tracker.DispatchObserver
)

// trackerDispatchObserverFromGlobal builds the observer once over the
// global meter provider (a no-op provider when monitoring is off). nil
// when the instruments cannot be created; dispatch still works.
func trackerDispatchObserverFromGlobal() tracker.DispatchObserver {
	globalTrackerDispatchObserverOnce.Do(func() {
		obs, err := newTrackerDispatchObserver(otel.GetMeterProvider().Meter("containarium"))
		if err != nil {
			log.Printf("[tracker] dispatch metrics disabled: %v", err)
			return
		}
		globalTrackerDispatchObserver = obs
	})
	return globalTrackerDispatchObserver
}
