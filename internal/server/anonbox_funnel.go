package server

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	otelmetric "go.opentelemetry.io/otel/metric"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/footprintai/containarium/internal/anonbox"
	"github.com/footprintai/containarium/internal/events"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// anonFunnelSink turns every anonbox funnel step into (a) an
// EVENT_TYPE_ANON_* event on the daemon's event bus, for subscribers such
// as the cloud control plane, and (b) an OTel counter
// containarium.anon.<step>_total — plus the time-to-shell histogram — so
// the PRD's three metrics are one VictoriaMetrics query each (#2201).
// The same call site feeds both, so they can never disagree.
type anonFunnelSink struct {
	bus      *events.Bus
	counters map[anonbox.FunnelKind]otelmetric.Int64Counter
	shell    otelmetric.Float64Histogram
}

// anonFunnelEventTypes maps a step to its proto event type.
var anonFunnelEventTypes = map[anonbox.FunnelKind]pb.EventType{
	anonbox.FunnelConnect:           pb.EventType_EVENT_TYPE_ANON_CONNECT,
	anonbox.FunnelShellReady:        pb.EventType_EVENT_TYPE_ANON_SHELL_READY,
	anonbox.FunnelReconnect:         pb.EventType_EVENT_TYPE_ANON_RECONNECT,
	anonbox.FunnelClaimLinkIssued:   pb.EventType_EVENT_TYPE_ANON_CLAIM_LINK_ISSUED,
	anonbox.FunnelClaimCompleted:    pb.EventType_EVENT_TYPE_ANON_CLAIM_COMPLETED,
	anonbox.FunnelExpired:           pb.EventType_EVENT_TYPE_ANON_EXPIRED,
	anonbox.FunnelKilledAbuse:       pb.EventType_EVENT_TYPE_ANON_KILLED_ABUSE,
	anonbox.FunnelRejectedCapacity:  pb.EventType_EVENT_TYPE_ANON_REJECTED_CAPACITY,
	anonbox.FunnelRejectedRateLimit: pb.EventType_EVENT_TYPE_ANON_REJECTED_RATELIMIT,
	anonbox.FunnelRejectedDoor:      pb.EventType_EVENT_TYPE_ANON_REJECTED_DOOR,
}

// newAnonFunnelSink registers one counter per step on mp's "containarium"
// meter, named containarium.anon.<step>_total (rendered by the
// collector → VictoriaMetrics path as containarium_anon_<step>_total), and
// the containarium.anon.time_to_shell_seconds histogram.
func newAnonFunnelSink(bus *events.Bus, mp otelmetric.MeterProvider) (*anonFunnelSink, error) {
	meter := mp.Meter("containarium")
	s := &anonFunnelSink{bus: bus, counters: map[anonbox.FunnelKind]otelmetric.Int64Counter{}}
	for _, k := range anonbox.AllFunnelKinds {
		c, err := meter.Int64Counter(fmt.Sprintf("containarium.anon.%s_total", k),
			otelmetric.WithDescription("Anonymous-box funnel: "+string(k)+" events"))
		if err != nil {
			return nil, fmt.Errorf("anon funnel counter %s: %w", k, err)
		}
		s.counters[k] = c
	}
	h, err := meter.Float64Histogram("containarium.anon.time_to_shell_seconds",
		otelmetric.WithDescription("Anonymous-box funnel: seconds from a key knocking to its new box being provisioned"),
		otelmetric.WithUnit("s"))
	if err != nil {
		return nil, fmt.Errorf("anon time-to-shell histogram: %w", err)
	}
	s.shell = h
	return s, nil
}

// Record implements anonbox.Funnel. Never blocks: the bus drops on a full
// subscriber channel and OTel instruments are non-blocking.
func (s *anonFunnelSink) Record(ev anonbox.FunnelEvent) {
	typ, ok := anonFunnelEventTypes[ev.Kind]
	if !ok {
		log.Printf("[anon-funnel] unknown step %q dropped", ev.Kind)
		return
	}
	ctx := context.Background()
	if c, ok := s.counters[ev.Kind]; ok {
		c.Add(ctx, 1)
	}
	if ev.Kind == anonbox.FunnelShellReady {
		s.shell.Record(ctx, ev.Duration.Seconds(), otelmetric.WithAttributes(attribute.String("box", ev.BoxName)))
	}
	if s.bus != nil {
		s.bus.Publish(&pb.Event{
			Id:              uuid.New().String(),
			Type:            typ,
			ResourceType:    pb.ResourceType_RESOURCE_TYPE_ANON_BOX,
			ResourceId:      ev.BoxName,
			Timestamp:       timestamppb.Now(),
			FingerprintHash: ev.FPHash,
			Payload: &pb.Event_AnonEvent{AnonEvent: &pb.AnonEvent{
				BoxName:         ev.BoxName,
				FingerprintHash: ev.FPHash,
				Reason:          ev.Reason,
				Seconds:         ev.Duration.Seconds(),
			}},
		})
	}
}

// anonObserveLoop is the door's one-minute maintenance tick: expiry
// warnings into the guests (#2202, Manager.Warn) and the expired / killed
// funnel events (#2201, Manager.Observe). Warn runs first so a box that
// is about to disappear still gets its last word.
func anonObserveLoop(ctx context.Context, m *anonbox.Manager, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := m.Warn(ctx); err != nil {
				log.Printf("[anon-warner] %v", err)
			}
			if err := m.Observe(ctx); err != nil {
				log.Printf("[anon-funnel] observe: %v", err)
			}
		}
	}
}
