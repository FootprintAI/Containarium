package events

import (
	"sync"

	"github.com/google/uuid"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

const (
	// DefaultChannelBufferSize is the default buffer size for subscriber channels
	DefaultChannelBufferSize = 100
)

// Subscriber represents a client subscribed to events
type Subscriber struct {
	// ID is the unique identifier for this subscriber
	ID string

	// Events is the channel where events are sent
	Events chan *pb.Event

	// Filter contains the subscription filter options
	Filter *pb.SubscribeEventsRequest

	// Done is closed when the subscriber should stop
	Done chan struct{}
}

// shouldReceive checks if this subscriber should receive the given event
func (s *Subscriber) shouldReceive(event *pb.Event) bool {
	// If no filter, receive everything except metrics (unless explicitly requested)
	if s.Filter == nil {
		return event.ResourceType != pb.ResourceType_RESOURCE_TYPE_METRICS
	}

	// Check metrics filter
	if event.ResourceType == pb.ResourceType_RESOURCE_TYPE_METRICS {
		return s.Filter.IncludeMetrics
	}

	// If no resource type filter, accept all non-metrics
	if len(s.Filter.ResourceTypes) == 0 {
		return true
	}

	// Check if event's resource type is in filter
	for _, rt := range s.Filter.ResourceTypes {
		if rt == event.ResourceType {
			return true
		}
	}

	return false
}

// Bus is the central event pub/sub system
type Bus struct {
	subscribers map[string]*Subscriber
	mu          sync.RWMutex
}

// NewBus creates a new event bus
func NewBus() *Bus {
	return &Bus{
		subscribers: make(map[string]*Subscriber),
	}
}

// Subscribe creates a new subscription with the given filter
func (b *Bus) Subscribe(filter *pb.SubscribeEventsRequest) *Subscriber {
	b.mu.Lock()
	defer b.mu.Unlock()

	sub := &Subscriber{
		ID:     uuid.New().String(),
		Events: make(chan *pb.Event, DefaultChannelBufferSize),
		Filter: filter,
		Done:   make(chan struct{}),
	}

	b.subscribers[sub.ID] = sub
	return sub
}

// Unsubscribe removes a subscriber from the bus
func (b *Bus) Unsubscribe(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if sub, ok := b.subscribers[id]; ok {
		close(sub.Done)
		close(sub.Events)
		delete(b.subscribers, id)
	}
}

// Publish sends an event to all matching subscribers
func (b *Bus) Publish(event *pb.Event) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for _, sub := range b.subscribers {
		if sub.shouldReceive(event) {
			// Non-blocking send - drop event if channel is full
			select {
			case sub.Events <- event:
			default:
				// Channel full, event dropped for this subscriber
			}
		}
	}
}

// SubscriberCount returns the number of active subscribers
func (b *Bus) SubscriberCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subscribers)
}

// Global event bus instance
var globalBus *Bus
var busOnce sync.Once

// GetBus returns the global event bus instance
func GetBus() *Bus {
	busOnce.Do(func() {
		globalBus = NewBus()
	})
	return globalBus
}
