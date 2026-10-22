package server

import (
	"context"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/footprintai/containarium/internal/anonbox"
	"github.com/footprintai/containarium/internal/events"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func funnelTestSink(t *testing.T) (*anonFunnelSink, *sdkmetric.ManualReader, *events.Subscriber) {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })
	bus := events.NewBus()
	sub := bus.Subscribe(&pb.SubscribeEventsRequest{})
	t.Cleanup(func() { bus.Unsubscribe(sub.ID) })
	s, err := newAnonFunnelSink(bus, mp)
	if err != nil {
		t.Fatal(err)
	}
	return s, reader, sub
}

func counterValues(t *testing.T, reader *sdkmetric.ManualReader) (map[string]int64, map[string]uint64) {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	sums := map[string]int64{}
	histCounts := map[string]uint64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			switch d := m.Data.(type) {
			case metricdata.Sum[int64]:
				for _, p := range d.DataPoints {
					sums[m.Name] += p.Value
				}
			case metricdata.Histogram[float64]:
				for _, p := range d.DataPoints {
					histCounts[m.Name] += p.Count
				}
			}
		}
	}
	return sums, histCounts
}

func drain(sub *events.Subscriber) []*pb.Event {
	var out []*pb.Event
	for {
		select {
		case e := <-sub.Events:
			out = append(out, e)
		default:
			return out
		}
	}
}

// Every step increments exactly its own counter once and publishes
// exactly one event of the matching type carrying the fingerprint hash.
func TestAnonFunnelSink_EachStepOnce(t *testing.T) {
	s, reader, sub := funnelTestSink(t)

	for _, k := range anonbox.AllFunnelKinds {
		s.Record(anonbox.FunnelEvent{Kind: k, FPHash: "ff00", BoxName: "anon-1a2b3c4d-container", Reason: "r", Duration: 12 * time.Second})
	}

	sums, hists := counterValues(t, reader)
	for _, k := range anonbox.AllFunnelKinds {
		name := "containarium.anon." + string(k) + "_total"
		if sums[name] != 1 {
			t.Errorf("%s = %d, want 1", name, sums[name])
		}
	}
	if len(sums) != len(anonbox.AllFunnelKinds) {
		t.Errorf("unexpected counters: %v", sums)
	}
	if hists["containarium.anon.time_to_shell_seconds"] != 1 {
		t.Errorf("time_to_shell count = %d, want 1 (only shell_ready records it)", hists["containarium.anon.time_to_shell_seconds"])
	}

	evs := drain(sub)
	if len(evs) != len(anonbox.AllFunnelKinds) {
		t.Fatalf("published %d events, want %d", len(evs), len(anonbox.AllFunnelKinds))
	}
	seen := map[pb.EventType]int{}
	for _, e := range evs {
		seen[e.Type]++
		if e.FingerprintHash != "ff00" || e.ResourceType != pb.ResourceType_RESOURCE_TYPE_ANON_BOX || e.ResourceId != "anon-1a2b3c4d-container" {
			t.Errorf("event %v: %+v", e.Type, e)
		}
		ae := e.GetAnonEvent()
		if ae == nil || ae.FingerprintHash != "ff00" || ae.Reason != "r" {
			t.Errorf("payload %v: %+v", e.Type, ae)
		}
		if e.Type == pb.EventType_EVENT_TYPE_ANON_SHELL_READY && ae.Seconds != 12 {
			t.Errorf("shell_ready seconds = %v", ae.Seconds)
		}
	}
	for k, typ := range anonFunnelEventTypes {
		if seen[typ] != 1 {
			t.Errorf("%s → %v published %d times", k, typ, seen[typ])
		}
	}
}

func TestAnonFunnelSink_UnknownKindDropped(t *testing.T) {
	s, reader, sub := funnelTestSink(t)
	s.Record(anonbox.FunnelEvent{Kind: "bogus"})
	sums, _ := counterValues(t, reader)
	if len(sums) != 0 || len(drain(sub)) != 0 {
		t.Errorf("unknown kind must record nothing: %v", sums)
	}
}

func TestAnonFunnelSink_NoBus(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	s, err := newAnonFunnelSink(nil, mp)
	if err != nil {
		t.Fatal(err)
	}
	s.Record(anonbox.FunnelEvent{Kind: anonbox.FunnelConnect})
	sums, _ := counterValues(t, reader)
	if sums["containarium.anon.connect_total"] != 1 {
		t.Errorf("metrics must work without a bus: %v", sums)
	}
}
