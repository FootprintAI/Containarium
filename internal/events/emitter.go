package events

import (
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Emitter provides type-safe methods for emitting events
type Emitter struct {
	bus *Bus
}

// NewEmitter creates a new event emitter
func NewEmitter(bus *Bus) *Emitter {
	return &Emitter{bus: bus}
}

// newEvent creates a new event with common fields populated
func newEvent(eventType pb.EventType, resourceType pb.ResourceType, resourceID string) *pb.Event {
	return &pb.Event{
		Id:           uuid.New().String(),
		Type:         eventType,
		ResourceType: resourceType,
		ResourceId:   resourceID,
		Timestamp:    timestamppb.Now(),
	}
}

// Container Events

// EmitContainerCreated emits an event when a container is created
func (e *Emitter) EmitContainerCreated(container *pb.Container) {
	event := newEvent(
		pb.EventType_EVENT_TYPE_CONTAINER_CREATED,
		pb.ResourceType_RESOURCE_TYPE_CONTAINER,
		container.Name,
	)
	event.Payload = &pb.Event_ContainerEvent{
		ContainerEvent: &pb.ContainerEvent{
			Container: container,
		},
	}
	e.bus.Publish(event)
}

// EmitContainerDeleted emits an event when a container is deleted
func (e *Emitter) EmitContainerDeleted(containerName string) {
	event := newEvent(
		pb.EventType_EVENT_TYPE_CONTAINER_DELETED,
		pb.ResourceType_RESOURCE_TYPE_CONTAINER,
		containerName,
	)
	e.bus.Publish(event)
}

// EmitContainerStarted emits an event when a container is started
func (e *Emitter) EmitContainerStarted(container *pb.Container) {
	event := newEvent(
		pb.EventType_EVENT_TYPE_CONTAINER_STARTED,
		pb.ResourceType_RESOURCE_TYPE_CONTAINER,
		container.Name,
	)
	event.Payload = &pb.Event_ContainerEvent{
		ContainerEvent: &pb.ContainerEvent{
			Container:     container,
			PreviousState: pb.ContainerState_CONTAINER_STATE_STOPPED,
		},
	}
	e.bus.Publish(event)
}

// EmitContainerStopped emits an event when a container is stopped
func (e *Emitter) EmitContainerStopped(container *pb.Container) {
	event := newEvent(
		pb.EventType_EVENT_TYPE_CONTAINER_STOPPED,
		pb.ResourceType_RESOURCE_TYPE_CONTAINER,
		container.Name,
	)
	event.Payload = &pb.Event_ContainerEvent{
		ContainerEvent: &pb.ContainerEvent{
			Container:     container,
			PreviousState: pb.ContainerState_CONTAINER_STATE_RUNNING,
		},
	}
	e.bus.Publish(event)
}

// EmitContainerStateChanged emits an event when a container's state changes
func (e *Emitter) EmitContainerStateChanged(container *pb.Container, previousState pb.ContainerState) {
	event := newEvent(
		pb.EventType_EVENT_TYPE_CONTAINER_STATE_CHANGED,
		pb.ResourceType_RESOURCE_TYPE_CONTAINER,
		container.Name,
	)
	event.Payload = &pb.Event_ContainerEvent{
		ContainerEvent: &pb.ContainerEvent{
			Container:     container,
			PreviousState: previousState,
		},
	}
	e.bus.Publish(event)
}

// App Events

// EmitAppDeployed emits an event when an app is deployed
func (e *Emitter) EmitAppDeployed(app *pb.App) {
	event := newEvent(
		pb.EventType_EVENT_TYPE_APP_DEPLOYED,
		pb.ResourceType_RESOURCE_TYPE_APP,
		app.Id,
	)
	event.Payload = &pb.Event_AppEvent{
		AppEvent: &pb.AppEvent{
			App: app,
		},
	}
	e.bus.Publish(event)
}

// EmitAppDeleted emits an event when an app is deleted
func (e *Emitter) EmitAppDeleted(appID string) {
	event := newEvent(
		pb.EventType_EVENT_TYPE_APP_DELETED,
		pb.ResourceType_RESOURCE_TYPE_APP,
		appID,
	)
	e.bus.Publish(event)
}

// EmitAppStarted emits an event when an app is started
func (e *Emitter) EmitAppStarted(app *pb.App) {
	event := newEvent(
		pb.EventType_EVENT_TYPE_APP_STARTED,
		pb.ResourceType_RESOURCE_TYPE_APP,
		app.Id,
	)
	event.Payload = &pb.Event_AppEvent{
		AppEvent: &pb.AppEvent{
			App:           app,
			PreviousState: pb.AppState_APP_STATE_STOPPED,
		},
	}
	e.bus.Publish(event)
}

// EmitAppStopped emits an event when an app is stopped
func (e *Emitter) EmitAppStopped(app *pb.App) {
	event := newEvent(
		pb.EventType_EVENT_TYPE_APP_STOPPED,
		pb.ResourceType_RESOURCE_TYPE_APP,
		app.Id,
	)
	event.Payload = &pb.Event_AppEvent{
		AppEvent: &pb.AppEvent{
			App:           app,
			PreviousState: pb.AppState_APP_STATE_RUNNING,
		},
	}
	e.bus.Publish(event)
}

// EmitAppStateChanged emits an event when an app's state changes
func (e *Emitter) EmitAppStateChanged(app *pb.App, previousState pb.AppState) {
	event := newEvent(
		pb.EventType_EVENT_TYPE_APP_STATE_CHANGED,
		pb.ResourceType_RESOURCE_TYPE_APP,
		app.Id,
	)
	event.Payload = &pb.Event_AppEvent{
		AppEvent: &pb.AppEvent{
			App:           app,
			PreviousState: previousState,
		},
	}
	e.bus.Publish(event)
}

// Route Events

// EmitRouteAdded emits an event when a route is added
func (e *Emitter) EmitRouteAdded(route *pb.ProxyRoute) {
	event := newEvent(
		pb.EventType_EVENT_TYPE_ROUTE_ADDED,
		pb.ResourceType_RESOURCE_TYPE_ROUTE,
		route.FullDomain,
	)
	event.Payload = &pb.Event_RouteEvent{
		RouteEvent: &pb.RouteEvent{
			Route: route,
		},
	}
	e.bus.Publish(event)
}

// EmitRouteDeleted emits an event when a route is deleted
func (e *Emitter) EmitRouteDeleted(domain string) {
	event := newEvent(
		pb.EventType_EVENT_TYPE_ROUTE_DELETED,
		pb.ResourceType_RESOURCE_TYPE_ROUTE,
		domain,
	)
	e.bus.Publish(event)
}

// Metrics Events

// EmitMetricsUpdate emits a metrics update event
func (e *Emitter) EmitMetricsUpdate(metrics []*pb.ContainerMetrics) {
	event := newEvent(
		pb.EventType_EVENT_TYPE_METRICS_UPDATE,
		pb.ResourceType_RESOURCE_TYPE_METRICS,
		"",
	)
	event.Payload = &pb.Event_MetricsEvent{
		MetricsEvent: &pb.MetricsEvent{
			Metrics: metrics,
		},
	}
	e.bus.Publish(event)
}
