package audit

import (
	"context"
	"log"
	"time"

	"github.com/footprintai/containarium/internal/events"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// EventSubscriber subscribes to the global event bus and persists events as audit log entries
type EventSubscriber struct {
	bus    *events.Bus
	store  *Store
	cancel context.CancelFunc
	done   chan struct{}
}

// NewEventSubscriber creates a new event subscriber
func NewEventSubscriber(bus *events.Bus, store *Store) *EventSubscriber {
	return &EventSubscriber{
		bus:   bus,
		store: store,
		done:  make(chan struct{}),
	}
}

// Start begins subscribing to events and writing them to the audit store
func (es *EventSubscriber) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	es.cancel = cancel

	// Subscribe to all resource types except metrics and traffic (too noisy)
	sub := es.bus.Subscribe(&pb.SubscribeEventsRequest{
		ResourceTypes: []pb.ResourceType{
			pb.ResourceType_RESOURCE_TYPE_CONTAINER,
			pb.ResourceType_RESOURCE_TYPE_APP,
			pb.ResourceType_RESOURCE_TYPE_ROUTE,
		},
	})

	go func() {
		defer close(es.done)
		defer es.bus.Unsubscribe(sub.ID)

		for {
			select {
			case <-ctx.Done():
				return
			case event, ok := <-sub.Events:
				if !ok {
					return
				}
				es.writeEvent(event)
			}
		}
	}()
}

// Stop cancels the subscriber goroutine and waits for it to finish
func (es *EventSubscriber) Stop() {
	if es.cancel != nil {
		es.cancel()
	}
	<-es.done
}

// writeEvent converts an event bus event to an audit log entry and persists it
func (es *EventSubscriber) writeEvent(event *pb.Event) {
	entry := &AuditEntry{
		Timestamp:    event.Timestamp.AsTime(),
		Username:     "", // Events don't carry user identity; the corresponding API request log does
		Action:       event.Type.String(),
		ResourceType: resourceTypeString(event.ResourceType),
		ResourceID:   event.ResourceId,
		Detail:       eventDetail(event),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := es.store.Log(ctx, entry); err != nil {
		log.Printf("audit: failed to persist event %s: %v", event.Type, err)
	}
}

// resourceTypeString converts a proto ResourceType to a human-readable string
func resourceTypeString(rt pb.ResourceType) string {
	switch rt {
	case pb.ResourceType_RESOURCE_TYPE_CONTAINER:
		return "container"
	case pb.ResourceType_RESOURCE_TYPE_APP:
		return "app"
	case pb.ResourceType_RESOURCE_TYPE_ROUTE:
		return "route"
	case pb.ResourceType_RESOURCE_TYPE_METRICS:
		return "metrics"
	case pb.ResourceType_RESOURCE_TYPE_TRAFFIC:
		return "traffic"
	default:
		return "unknown"
	}
}

// eventDetail extracts a brief description from the event payload
func eventDetail(event *pb.Event) string {
	switch p := event.Payload.(type) {
	case *pb.Event_ContainerEvent:
		if p.ContainerEvent != nil && p.ContainerEvent.Container != nil {
			c := p.ContainerEvent.Container
			return "image=" + c.Image + " state=" + c.State.String()
		}
	case *pb.Event_AppEvent:
		if p.AppEvent != nil && p.AppEvent.App != nil {
			a := p.AppEvent.App
			return "name=" + a.Name + " state=" + a.State.String()
		}
	case *pb.Event_RouteEvent:
		if p.RouteEvent != nil && p.RouteEvent.Route != nil {
			r := p.RouteEvent.Route
			return "domain=" + r.FullDomain
		}
	}
	return ""
}
