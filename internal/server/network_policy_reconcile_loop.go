package server

import (
	"context"
	"log"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otelmetric "go.opentelemetry.io/otel/metric"

	"github.com/footprintai/containarium/internal/events"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// defaultContainerEventDebounce is the trailing debounce on the event-driven
// reconcile path (#3050): a burst of container events produces one pass, this
// long after the last event of the burst, so passes cannot run back to back.
const defaultContainerEventDebounce = 2 * time.Second

// containerTopologyEvents are the bus events that change which boxes exist,
// run, or hold which address: the only ones a topology reconciler needs to
// wake early for (#3050). Metrics, traffic, security-finding, app, route and
// anonymous-box events do not change topology; before #3050 the traffic and
// finding streams alone ran full reconcile passes back to back.
var containerTopologyEvents = map[pb.EventType]bool{
	pb.EventType_EVENT_TYPE_CONTAINER_CREATED:       true,
	pb.EventType_EVENT_TYPE_CONTAINER_DELETED:       true,
	pb.EventType_EVENT_TYPE_CONTAINER_STARTED:       true,
	pb.EventType_EVENT_TYPE_CONTAINER_STOPPED:       true,
	pb.EventType_EVENT_TYPE_CONTAINER_STATE_CHANGED: true,
}

// containerTopologyKick subscribes to bus and returns a channel that receives
// one signal per burst of container topology events, debounce after the
// burst's last event (a trailing debounce). A signal already pending absorbs
// later bursts. It returns a nil channel (which blocks forever in a select)
// when bus is nil. The subscription is made before it returns and ends when
// ctx is done.
func containerTopologyKick(ctx context.Context, bus *events.Bus, debounce time.Duration) <-chan struct{} {
	if bus == nil {
		return nil
	}
	// The bus filters by resource type; the event type is checked below.
	sub := bus.Subscribe(&pb.SubscribeEventsRequest{
		ResourceTypes: []pb.ResourceType{pb.ResourceType_RESOURCE_TYPE_CONTAINER},
	})
	kick := make(chan struct{}, 1)
	go func() {
		defer bus.Unsubscribe(sub.ID)
		timer := time.NewTimer(debounce)
		timer.Stop()
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-sub.Events:
				if !ok {
					return
				}
				if !containerTopologyEvents[ev.GetType()] {
					continue
				}
				timer.Reset(debounce) // trailing: restart on every event of the burst
			case <-timer.C:
				select {
				case kick <- struct{}{}:
				default: // a pass is already pending; coalesce
				}
			}
		}
	}()
	return kick
}

// Reconcile-pass metrics (#3050). The OTel names use dots; VictoriaMetrics
// stores them with underscores (containarium_netpolicy_reconcile_passes_total,
// containarium_netpolicy_reconcile_passes_per_minute).
const (
	netPolicyReconcilePassesName = "containarium.netpolicy.reconcile_passes_total"
	netPolicyReconcileRateName   = "containarium.netpolicy.reconcile_passes_per_minute"
	netPolicyReconcileRateWindow = time.Minute
)

// Reconcile triggers, the "trigger" attribute on the pass counter.
const (
	reconcileTriggerInitial = "initial"
	reconcileTriggerTimer   = "timer"
	reconcileTriggerEvent   = "event"
)

// reconcileMeter counts reconcile passes and reports how many ran in the
// trailing minute, so a runaway loop is visible on a dashboard.
type reconcileMeter struct {
	passes otelmetric.Int64Counter
	now    func() time.Time

	mu     sync.Mutex
	recent []time.Time // pass start times within the trailing window, oldest first
}

func newReconcileMeter(mp otelmetric.MeterProvider, now func() time.Time) *reconcileMeter {
	m := &reconcileMeter{now: now}
	meter := mp.Meter("containarium")
	c, err := meter.Int64Counter(netPolicyReconcilePassesName,
		otelmetric.WithDescription("Network-policy reconcile passes, by trigger (initial, timer, event)"))
	if err != nil {
		log.Printf("[netpolicy] reconcile pass counter: %v", err)
	} else {
		m.passes = c
	}
	if _, err := meter.Int64ObservableGauge(netPolicyReconcileRateName,
		otelmetric.WithDescription("Network-policy reconcile passes that started in the trailing minute"),
		otelmetric.WithInt64Callback(func(_ context.Context, o otelmetric.Int64Observer) error {
			o.Observe(int64(m.perMinute()))
			return nil
		})); err != nil {
		log.Printf("[netpolicy] reconcile rate gauge: %v", err)
	}
	return m
}

// record counts one pass started by trigger.
func (m *reconcileMeter) record(trigger string) {
	if m.passes != nil {
		m.passes.Add(context.Background(), 1, otelmetric.WithAttributes(attribute.String("trigger", trigger)))
	}
	t := m.now()
	m.mu.Lock()
	m.recent = append(m.recent, t)
	m.pruneLocked(t)
	m.mu.Unlock()
}

// perMinute is the number of passes that started in the trailing window.
func (m *reconcileMeter) perMinute() int {
	t := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked(t)
	return len(m.recent)
}

func (m *reconcileMeter) pruneLocked(now time.Time) {
	cut := 0
	for cut < len(m.recent) && now.Sub(m.recent[cut]) >= netPolicyReconcileRateWindow {
		cut++
	}
	if cut > 0 {
		m.recent = append(m.recent[:0], m.recent[cut:]...)
	}
}

// runPass runs one reconcile pass and counts it.
func (e *NetworkPolicyEnforcer) runPass(trigger string) {
	if e.meter != nil {
		e.meter.record(trigger)
	}
	pass := e.pass
	if pass == nil {
		pass = e.reconcile
	}
	if err := pass(e.ctx); err != nil {
		log.Printf("[netpolicy] reconcile (%s): %v", trigger, err)
	}
}

// reconcileLoop re-converges every e.interval and when kick fires (a debounced
// burst of container events). Errors are logged, not fatal. Runs until e.ctx is
// done; the caller has done e.wg.Add(1).
func (e *NetworkPolicyEnforcer) reconcileLoop(kick <-chan struct{}) {
	defer e.wg.Done()
	tick := time.NewTicker(e.interval)
	defer tick.Stop()
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-tick.C:
			e.runPass(reconcileTriggerTimer)
		case <-kick:
			e.runPass(reconcileTriggerEvent)
		}
	}
}

// fullListInspector is the enforcer's containerInspector over the Incus
// client: each pass's container list is one recursive Incus request
// (ListContainersFull) instead of one GetInstance plus one GetInstanceState per
// instance (#3050). GetRawInstance is the client's own.
type fullListInspector struct{ *incus.Client }

var _ containerInspector = fullListInspector{}

func (f fullListInspector) ListContainers() ([]incus.ContainerInfo, error) {
	return f.ListContainersFull()
}

// globalReconcileMeter returns a meter on the global OTel provider.
func globalReconcileMeter() *reconcileMeter {
	return newReconcileMeter(otel.GetMeterProvider(), time.Now)
}
