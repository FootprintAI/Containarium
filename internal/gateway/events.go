package gateway

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/events"
	"github.com/footprintai/containarium/internal/safecast"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

const (
	// SSE heartbeat interval to keep connections alive through proxies
	sseHeartbeatInterval = 15 * time.Second
)

// EventHandler handles Server-Sent Events for real-time updates
type EventHandler struct {
	bus *events.Bus
}

// NewEventHandler creates a new event handler
func NewEventHandler(bus *events.Bus) *EventHandler {
	return &EventHandler{bus: bus}
}

// HandleSSE handles SSE connections for event streaming
func (h *EventHandler) HandleSSE(w http.ResponseWriter, r *http.Request) {
	// Check if SSE is supported
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	// Validate origin for security
	origin := r.Header.Get("Origin")
	if origin != "" && !isAllowedOrigin(origin) {
		http.Error(w, "Origin not allowed", http.StatusForbidden)
		return
	}

	// Parse filter from query params
	filter := parseEventFilter(r)

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // Disable nginx buffering

	// Allow CORS for SSE
	if origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}

	// Subscribe to events
	sub := h.bus.Subscribe(filter)
	defer h.bus.Unsubscribe(sub.ID)

	log.Printf("SSE client connected: %s (filter: %+v)", sub.ID, filter)

	// Send initial connection event
	h.sendEvent(w, flusher, "connected", map[string]string{
		"subscriptionId": sub.ID,
	})

	// Create heartbeat ticker to keep connection alive through proxies
	heartbeat := time.NewTicker(sseHeartbeatInterval)
	defer heartbeat.Stop()

	// Stream events
	for {
		select {
		case <-r.Context().Done():
			log.Printf("SSE client disconnected: %s", sub.ID)
			return
		case <-sub.Done:
			log.Printf("SSE subscription closed: %s", sub.ID)
			return
		case <-heartbeat.C:
			// Send SSE comment as heartbeat (lines starting with : are comments)
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		case event, ok := <-sub.Events:
			if !ok {
				return
			}
			h.sendProtoEvent(w, flusher, event)
		}
	}
}

// parseEventFilter parses subscription filter from query parameters
func parseEventFilter(r *http.Request) *pb.SubscribeEventsRequest {
	filter := &pb.SubscribeEventsRequest{}

	// Parse resource types
	resourceTypes := r.URL.Query()["resourceTypes"]
	for _, rt := range resourceTypes {
		switch strings.ToUpper(rt) {
		case "CONTAINER", "RESOURCE_TYPE_CONTAINER":
			filter.ResourceTypes = append(filter.ResourceTypes, pb.ResourceType_RESOURCE_TYPE_CONTAINER)
		case "APP", "RESOURCE_TYPE_APP":
			filter.ResourceTypes = append(filter.ResourceTypes, pb.ResourceType_RESOURCE_TYPE_APP)
		case "ROUTE", "RESOURCE_TYPE_ROUTE":
			filter.ResourceTypes = append(filter.ResourceTypes, pb.ResourceType_RESOURCE_TYPE_ROUTE)
		case "METRICS", "RESOURCE_TYPE_METRICS":
			filter.ResourceTypes = append(filter.ResourceTypes, pb.ResourceType_RESOURCE_TYPE_METRICS)
		}
	}

	// Parse include metrics
	if includeMetrics := r.URL.Query().Get("includeMetrics"); includeMetrics == "true" {
		filter.IncludeMetrics = true
	}

	// Parse metrics interval
	if intervalStr := r.URL.Query().Get("metricsInterval"); intervalStr != "" {
		if interval, err := strconv.Atoi(intervalStr); err == nil {
			if interval >= 1 && interval <= 60 {
				filter.MetricsIntervalSeconds = safecast.I32(interval)
			}
		}
	}

	return filter
}

// sendEvent sends a generic SSE event
func (h *EventHandler) sendEvent(w http.ResponseWriter, flusher http.Flusher, eventType string, data interface{}) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Printf("Failed to marshal event data: %v", err)
		return
	}

	fmt.Fprintf(w, "event: %s\n", eventType)
	fmt.Fprintf(w, "data: %s\n\n", jsonData)
	flusher.Flush()
}

// sendProtoEvent sends a protobuf event as SSE
func (h *EventHandler) sendProtoEvent(w http.ResponseWriter, flusher http.Flusher, event *pb.Event) {
	// Convert proto event to JSON-friendly format
	eventData := map[string]interface{}{
		"id":           event.Id,
		"type":         event.Type.String(),
		"resourceType": event.ResourceType.String(),
		"resourceId":   event.ResourceId,
		"timestamp":    event.Timestamp.AsTime().Format("2006-01-02T15:04:05.000Z"),
	}

	// Add payload based on type
	switch p := event.Payload.(type) {
	case *pb.Event_ContainerEvent:
		eventData["containerEvent"] = containerEventToPayload(p.ContainerEvent)
	case *pb.Event_AppEvent:
		eventData["appEvent"] = appEventToPayload(p.AppEvent)
	case *pb.Event_RouteEvent:
		eventData["routeEvent"] = routeEventToPayload(p.RouteEvent)
	case *pb.Event_MetricsEvent:
		eventData["metricsEvent"] = metricsEventToPayload(p.MetricsEvent)
	}

	jsonData, err := json.Marshal(eventData)
	if err != nil {
		log.Printf("Failed to marshal proto event: %v", err)
		return
	}

	// Use event type as SSE event name for filtering
	eventName := strings.ToLower(strings.TrimPrefix(event.Type.String(), "EVENT_TYPE_"))
	fmt.Fprintf(w, "event: %s\n", eventName)
	fmt.Fprintf(w, "data: %s\n\n", jsonData)
	flusher.Flush()
}

// isAllowedOrigin checks if the origin is allowed
func isAllowedOrigin(origin string) bool {
	allowedOrigins := getEventAllowedOrigins()
	for _, allowed := range allowedOrigins {
		if origin == allowed {
			return true
		}
	}
	return false
}

// getEventAllowedOrigins returns allowed origins for SSE
func getEventAllowedOrigins() []string {
	envOrigins := os.Getenv("CONTAINARIUM_ALLOWED_ORIGINS")
	if envOrigins != "" {
		origins := strings.Split(envOrigins, ",")
		for i, origin := range origins {
			origins[i] = strings.TrimSpace(origin)
		}
		return origins
	}
	// Dev defaults only. Production deployments MUST set
	// CONTAINARIUM_ALLOWED_ORIGINS to include their public origin —
	// the cluster's apex hostname doesn't belong in this OSS file
	// (per CLAUDE.md OSS-disclosure rule).
	return []string{
		"http://localhost:3000",
		"http://localhost:8080",
		"http://localhost",
	}
}

// Helper functions to convert proto messages to maps

// The SSE payload shapes.
//
// These were map[string]interface{} literals, which meant a mistyped key was
// valid Go producing valid JSON with the wrong field name. web-ui declares the
// matching shape in src/types/events.ts, so the two agreed only by inspection
// — nothing on either side would have caught a drift.
//
// Named structs so the field names are compile-checked. The JSON is
// unchanged: same keys, same casing, and the same omit-when-empty behaviour
// the map literals got by only assigning present fields.

type ssePayloadContainer struct {
	Name          string `json:"name"`
	Username      string `json:"username"`
	State         string `json:"state"`
	IPAddress     string `json:"ipAddress"`
	CPU           string `json:"cpu"`
	Memory        string `json:"memory"`
	Disk          string `json:"disk"`
	Image         string `json:"image"`
	PodmanEnabled bool   `json:"podmanEnabled"`
}

type ssePayloadContainerEvent struct {
	Container     *ssePayloadContainer `json:"container,omitempty"`
	PreviousState string               `json:"previousState,omitempty"`
}

type ssePayloadApp struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Username      string `json:"username"`
	ContainerName string `json:"containerName"`
	Subdomain     string `json:"subdomain"`
	FullDomain    string `json:"fullDomain"`
	Port          int32  `json:"port"`
	State         string `json:"state"`
}

type ssePayloadAppEvent struct {
	App           *ssePayloadApp `json:"app,omitempty"`
	PreviousState string         `json:"previousState,omitempty"`
}

type ssePayloadRoute struct {
	Subdomain   string `json:"subdomain"`
	FullDomain  string `json:"fullDomain"`
	ContainerIP string `json:"containerIp"`
	Port        int32  `json:"port"`
	Active      bool   `json:"active"`
	AppID       string `json:"appId"`
	AppName     string `json:"appName"`
}

type ssePayloadRouteEvent struct {
	Route *ssePayloadRoute `json:"route,omitempty"`
}

type ssePayloadMetric struct {
	Name             string `json:"name"`
	CPUUsageSeconds  int64  `json:"cpuUsageSeconds"`
	MemoryUsageBytes int64  `json:"memoryUsageBytes"`
	MemoryPeakBytes  int64  `json:"memoryPeakBytes"`
	DiskUsageBytes   int64  `json:"diskUsageBytes"`
	NetworkRxBytes   int64  `json:"networkRxBytes"`
	NetworkTxBytes   int64  `json:"networkTxBytes"`
	ProcessCount     int32  `json:"processCount"`
}

type ssePayloadMetricsEvent struct {
	Metrics []ssePayloadMetric `json:"metrics"`
}

func containerEventToPayload(e *pb.ContainerEvent) *ssePayloadContainerEvent {
	if e == nil {
		return nil
	}
	out := &ssePayloadContainerEvent{Container: containerToPayload(e.Container)}
	if e.PreviousState != pb.ContainerState_CONTAINER_STATE_UNSPECIFIED {
		out.PreviousState = e.PreviousState.String()
	}
	return out
}

func containerToPayload(c *pb.Container) *ssePayloadContainer {
	if c == nil {
		return nil
	}
	return &ssePayloadContainer{
		Name:          c.Name,
		Username:      c.Username,
		State:         c.State.String(),
		IPAddress:     c.Network.GetIpAddress(),
		CPU:           c.Resources.GetCpu(),
		Memory:        c.Resources.GetMemory(),
		Disk:          c.Resources.GetDisk(),
		Image:         c.Image,
		PodmanEnabled: c.PodmanEnabled,
	}
}

func appEventToPayload(e *pb.AppEvent) *ssePayloadAppEvent {
	if e == nil {
		return nil
	}
	out := &ssePayloadAppEvent{App: appToPayload(e.App)}
	if e.PreviousState != pb.AppState_APP_STATE_UNSPECIFIED {
		out.PreviousState = e.PreviousState.String()
	}
	return out
}

func appToPayload(a *pb.App) *ssePayloadApp {
	if a == nil {
		return nil
	}
	return &ssePayloadApp{
		ID:            a.Id,
		Name:          a.Name,
		Username:      a.Username,
		ContainerName: a.ContainerName,
		Subdomain:     a.Subdomain,
		FullDomain:    a.FullDomain,
		Port:          a.Port,
		State:         a.State.String(),
	}
}

func routeEventToPayload(e *pb.RouteEvent) *ssePayloadRouteEvent {
	if e == nil {
		return nil
	}
	out := &ssePayloadRouteEvent{}
	if e.Route != nil {
		out.Route = &ssePayloadRoute{
			Subdomain:   e.Route.Subdomain,
			FullDomain:  e.Route.FullDomain,
			ContainerIP: e.Route.ContainerIp,
			Port:        e.Route.Port,
			Active:      e.Route.Active,
			AppID:       e.Route.AppId,
			AppName:     e.Route.AppName,
		}
	}
	return out
}

func metricsEventToPayload(e *pb.MetricsEvent) *ssePayloadMetricsEvent {
	if e == nil {
		return nil
	}
	metrics := make([]ssePayloadMetric, len(e.Metrics))
	for i, m := range e.Metrics {
		metrics[i] = ssePayloadMetric{
			Name:             m.Name,
			CPUUsageSeconds:  m.CpuUsageSeconds,
			MemoryUsageBytes: m.MemoryUsageBytes,
			MemoryPeakBytes:  m.MemoryPeakBytes,
			DiskUsageBytes:   m.DiskUsageBytes,
			NetworkRxBytes:   m.NetworkRxBytes,
			NetworkTxBytes:   m.NetworkTxBytes,
			ProcessCount:     m.ProcessCount,
		}
	}
	return &ssePayloadMetricsEvent{Metrics: metrics}
}
