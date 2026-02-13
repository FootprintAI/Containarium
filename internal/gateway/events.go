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
				filter.MetricsIntervalSeconds = int32(interval)
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
		eventData["containerEvent"] = containerEventToMap(p.ContainerEvent)
	case *pb.Event_AppEvent:
		eventData["appEvent"] = appEventToMap(p.AppEvent)
	case *pb.Event_RouteEvent:
		eventData["routeEvent"] = routeEventToMap(p.RouteEvent)
	case *pb.Event_MetricsEvent:
		eventData["metricsEvent"] = metricsEventToMap(p.MetricsEvent)
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
	return []string{
		"http://localhost:3000",
		"http://localhost:8080",
		"http://localhost",
		"https://containarium.kafeido.app",
	}
}

// Helper functions to convert proto messages to maps

func containerEventToMap(e *pb.ContainerEvent) map[string]interface{} {
	if e == nil {
		return nil
	}
	result := map[string]interface{}{}
	if e.Container != nil {
		result["container"] = containerToMap(e.Container)
	}
	if e.PreviousState != pb.ContainerState_CONTAINER_STATE_UNSPECIFIED {
		result["previousState"] = e.PreviousState.String()
	}
	return result
}

func containerToMap(c *pb.Container) map[string]interface{} {
	if c == nil {
		return nil
	}
	return map[string]interface{}{
		"name":          c.Name,
		"username":      c.Username,
		"state":         c.State.String(),
		"ipAddress":     c.Network.GetIpAddress(),
		"cpu":           c.Resources.GetCpu(),
		"memory":        c.Resources.GetMemory(),
		"disk":          c.Resources.GetDisk(),
		"image":         c.Image,
		"dockerEnabled": c.DockerEnabled,
	}
}

func appEventToMap(e *pb.AppEvent) map[string]interface{} {
	if e == nil {
		return nil
	}
	result := map[string]interface{}{}
	if e.App != nil {
		result["app"] = appToMap(e.App)
	}
	if e.PreviousState != pb.AppState_APP_STATE_UNSPECIFIED {
		result["previousState"] = e.PreviousState.String()
	}
	return result
}

func appToMap(a *pb.App) map[string]interface{} {
	if a == nil {
		return nil
	}
	return map[string]interface{}{
		"id":            a.Id,
		"name":          a.Name,
		"username":      a.Username,
		"containerName": a.ContainerName,
		"subdomain":     a.Subdomain,
		"fullDomain":    a.FullDomain,
		"port":          a.Port,
		"state":         a.State.String(),
	}
}

func routeEventToMap(e *pb.RouteEvent) map[string]interface{} {
	if e == nil {
		return nil
	}
	result := map[string]interface{}{}
	if e.Route != nil {
		result["route"] = map[string]interface{}{
			"subdomain":   e.Route.Subdomain,
			"fullDomain":  e.Route.FullDomain,
			"containerIp": e.Route.ContainerIp,
			"port":        e.Route.Port,
			"active":      e.Route.Active,
			"appId":       e.Route.AppId,
			"appName":     e.Route.AppName,
		}
	}
	return result
}

func metricsEventToMap(e *pb.MetricsEvent) map[string]interface{} {
	if e == nil {
		return nil
	}
	metrics := make([]map[string]interface{}, len(e.Metrics))
	for i, m := range e.Metrics {
		metrics[i] = map[string]interface{}{
			"name":             m.Name,
			"cpuUsageSeconds":  m.CpuUsageSeconds,
			"memoryUsageBytes": m.MemoryUsageBytes,
			"memoryPeakBytes":  m.MemoryPeakBytes,
			"diskUsageBytes":   m.DiskUsageBytes,
			"networkRxBytes":   m.NetworkRxBytes,
			"networkTxBytes":   m.NetworkTxBytes,
			"processCount":     m.ProcessCount,
		}
	}
	return map[string]interface{}{
		"metrics": metrics,
	}
}
