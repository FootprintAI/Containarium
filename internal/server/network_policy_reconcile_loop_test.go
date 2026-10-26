package server

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/footprintai/containarium/internal/events"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// countingInspector counts ListContainers calls: one Incus container list is
// what each reconcile pass costs (gather), so the count is the pass's Incus
// call volume in units of "one full list".
type countingInspector struct{ lists atomic.Int32 }

func (c *countingInspector) ListContainers() ([]incus.ContainerInfo, error) {
	c.lists.Add(1)
	return nil, nil
}

func (c *countingInspector) GetRawInstance(string) (map[string]string, string, error) {
	return nil, "", nil
}

// loopEnforcer is an enforcer whose reconcile pass is one ListContainers on
// insp (what gather does), driven by the real loop and bus subscription.
func loopEnforcer(t *testing.T, bus *events.Bus, interval, debounce time.Duration) (*NetworkPolicyEnforcer, *countingInspector) {
	t.Helper()
	insp := &countingInspector{}
	e := NewNetworkPolicyEnforcer("", nil, NewMemTenantRegistry(), insp, nil, bus, false)
	e.interval = interval
	e.eventDebounce = debounce
	e.pass = func(context.Context) error { _, err := insp.ListContainers(); return err }
	e.ctx, e.cancel = context.WithCancel(context.Background())
	kick := containerTopologyKick(e.ctx, bus, e.eventDebounce)
	e.wg.Add(1)
	go e.reconcileLoop(kick)
	t.Cleanup(func() { e.cancel(); e.wg.Wait() })
	return e, insp
}

// emitNonContainerEvents publishes one of every event kind the bus carries
// that does not change container topology: metrics, traffic, security
// findings, app and route events, and an anonymous-box funnel event.
func emitNonContainerEvents(bus *events.Bus) {
	em := events.NewEmitter(bus)
	em.EmitMetricsUpdate(nil)
	em.EmitTrafficEvent(&pb.TrafficEvent{Connection: &pb.Connection{ContainerName: "a-box"}})
	em.EmitSecurityFinding(&pb.Finding{TenantId: "t"})
	em.EmitAppDeployed(&pb.App{Id: "app"})
	em.EmitAppStateChanged(&pb.App{Id: "app"}, pb.AppState_APP_STATE_RUNNING)
	em.EmitRouteAdded(&pb.ProxyRoute{FullDomain: "app.example.com"})
	bus.Publish(&pb.Event{Type: pb.EventType_EVENT_TYPE_ANON_CONNECT, ResourceType: pb.ResourceType_RESOURCE_TYPE_ANON_BOX})
}

// #3050: a steady stream of non-container events (traffic, findings, ...) must
// not drive reconcile passes; the Incus list volume stays at the timer
// baseline. Before the fix every such event ran a full pass, back to back.
func TestReconcileLoop_NonContainerEventStreamStaysAtTimerBaseline(t *testing.T) {
	bus := events.NewBus()
	const interval = 200 * time.Millisecond
	const run = 1100 * time.Millisecond
	_, insp := loopEnforcer(t, bus, interval, 20*time.Millisecond)

	deadline := time.Now().Add(run)
	for time.Now().Before(deadline) {
		emitNonContainerEvents(bus)
		time.Sleep(time.Millisecond)
	}

	baseline := int32(run / interval) // timer ticks in the window
	if got := insp.lists.Load(); got > baseline+1 {
		t.Fatalf("Incus container lists = %d over %s of non-container events, want at most the timer baseline %d (+1)", got, run, baseline)
	}
}

// #3050: a burst of container topology events produces one pass, after the
// trailing debounce, not one pass per event.
func TestReconcileLoop_ContainerEventBurstIsOneDebouncedPass(t *testing.T) {
	bus := events.NewBus()
	const debounce = 150 * time.Millisecond
	_, insp := loopEnforcer(t, bus, time.Hour, debounce) // timer out of the picture

	em := events.NewEmitter(bus)
	c := &pb.Container{Name: "a-box"}
	for i := 0; i < 5; i++ {
		em.EmitContainerCreated(c)
		em.EmitContainerStarted(c)
		em.EmitContainerStateChanged(c, pb.ContainerState_CONTAINER_STATE_STOPPED)
		em.EmitContainerStopped(c)
		em.EmitContainerDeleted(c.Name)
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(debounce / 3)
	if got := insp.lists.Load(); got != 0 {
		t.Fatalf("passes before the debounce elapsed = %d, want 0 (events still arriving %s ago)", got, debounce/3)
	}
	time.Sleep(debounce * 3)
	if got := insp.lists.Load(); got != 1 {
		t.Fatalf("passes after a burst of 25 container events = %d, want exactly 1", got)
	}
}

// #3050: exactly the container topology events kick a pass.
func TestContainerTopologyKick_EventSet(t *testing.T) {
	c := &pb.Container{Name: "a-box"}
	for _, tc := range []struct {
		name string
		emit func(*events.Emitter, *events.Bus)
		want bool
	}{
		{"created", func(em *events.Emitter, _ *events.Bus) { em.EmitContainerCreated(c) }, true},
		{"deleted", func(em *events.Emitter, _ *events.Bus) { em.EmitContainerDeleted(c.Name) }, true},
		{"started", func(em *events.Emitter, _ *events.Bus) { em.EmitContainerStarted(c) }, true},
		{"stopped", func(em *events.Emitter, _ *events.Bus) { em.EmitContainerStopped(c) }, true},
		{"state changed", func(em *events.Emitter, _ *events.Bus) {
			em.EmitContainerStateChanged(c, pb.ContainerState_CONTAINER_STATE_RUNNING)
		}, true},
		{"metrics", func(em *events.Emitter, _ *events.Bus) { em.EmitMetricsUpdate(nil) }, false},
		{"traffic", func(em *events.Emitter, _ *events.Bus) { em.EmitTrafficEvent(&pb.TrafficEvent{}) }, false},
		{"security finding", func(em *events.Emitter, _ *events.Bus) { em.EmitSecurityFinding(&pb.Finding{}) }, false},
		{"app deployed", func(em *events.Emitter, _ *events.Bus) { em.EmitAppDeployed(&pb.App{}) }, false},
		{"route added", func(em *events.Emitter, _ *events.Bus) { em.EmitRouteAdded(&pb.ProxyRoute{}) }, false},
		{"anon box", func(_ *events.Emitter, b *events.Bus) {
			b.Publish(&pb.Event{Type: pb.EventType_EVENT_TYPE_ANON_CONNECT, ResourceType: pb.ResourceType_RESOURCE_TYPE_ANON_BOX})
		}, false},
		{"container resource, unknown type", func(_ *events.Emitter, b *events.Bus) {
			b.Publish(&pb.Event{Type: pb.EventType_EVENT_TYPE_UNSPECIFIED, ResourceType: pb.ResourceType_RESOURCE_TYPE_CONTAINER})
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bus := events.NewBus()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			kick := containerTopologyKick(ctx, bus, 5*time.Millisecond)
			tc.emit(events.NewEmitter(bus), bus)
			var got bool
			select {
			case <-kick:
				got = true
			case <-time.After(150 * time.Millisecond):
			}
			if got != tc.want {
				t.Fatalf("kicked = %v, want %v", got, tc.want)
			}
		})
	}
}

// A nil bus yields a nil channel: the loop runs on the timer alone.
func TestContainerTopologyKick_NilBus(t *testing.T) {
	if ch := containerTopologyKick(context.Background(), nil, time.Second); ch != nil {
		t.Fatal("want a nil channel for a nil bus")
	}
}

// #3050: passes are counted by trigger, and the per-minute gauge reports the
// passes that started in the trailing minute.
func TestReconcileMeter_CountsPassesAndRate(t *testing.T) {
	rd := metric.NewManualReader()
	now := time.Unix(1_700_000_000, 0)
	m := newReconcileMeter(metric.NewMeterProvider(metric.WithReader(rd)), func() time.Time { return now })

	m.record(reconcileTriggerInitial)
	for i := 0; i < 3; i++ {
		m.record(reconcileTriggerTimer)
	}
	now = now.Add(30 * time.Second)
	m.record(reconcileTriggerEvent)
	m.record(reconcileTriggerEvent)

	var rm metricdata.ResourceMetrics
	if err := rd.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	byTrigger := map[string]int64{}
	var rate int64 = -1
	for _, sm := range rm.ScopeMetrics {
		for _, md := range sm.Metrics {
			switch md.Name {
			case netPolicyReconcilePassesName:
				for _, dp := range md.Data.(metricdata.Sum[int64]).DataPoints {
					v, _ := dp.Attributes.Value("trigger")
					byTrigger[v.AsString()] = dp.Value
				}
			case netPolicyReconcileRateName:
				rate = md.Data.(metricdata.Gauge[int64]).DataPoints[0].Value
			}
		}
	}
	want := map[string]int64{reconcileTriggerInitial: 1, reconcileTriggerTimer: 3, reconcileTriggerEvent: 2}
	for k, v := range want {
		if byTrigger[k] != v {
			t.Errorf("passes{trigger=%s} = %d, want %d (all: %v)", k, byTrigger[k], v, byTrigger)
		}
	}
	if rate != 6 {
		t.Errorf("passes per minute = %d, want 6", rate)
	}

	// 31 s later the first four passes are outside the trailing minute.
	now = now.Add(31 * time.Second)
	if got := m.perMinute(); got != 2 {
		t.Errorf("passes per minute after the window moved = %d, want 2", got)
	}
}
