package gateway

import (
	"encoding/json"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// These payloads were map[string]interface{} literals. web-ui declares the
// matching shape in src/types/events.ts, so the Go side and the TypeScript
// side agreed only by inspection — a mistyped key was valid Go, valid JSON,
// and wrong, with nothing on either side to catch it.
//
// Typing them is only safe if the emitted JSON is unchanged, so that is what
// these assert: the exact key set, and the types the browser will see.

func marshalToMap(t *testing.T, v any) map[string]json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return m
}

func assertKeys(t *testing.T, got map[string]json.RawMessage, want ...string) {
	t.Helper()
	for _, k := range want {
		if _, ok := got[k]; !ok {
			t.Errorf("payload is missing %q — web-ui's events.ts declares it", k)
		}
	}
	if len(got) != len(want) {
		keys := make([]string, 0, len(got))
		for k := range got {
			keys = append(keys, k)
		}
		t.Errorf("payload has %d keys, want %d: got %v, want %v", len(got), len(want), keys, want)
	}
}

func TestContainerPayloadShape(t *testing.T) {
	got := marshalToMap(t, containerToPayload(&pb.Container{
		Name: "alice-container", Username: "alice",
		State:     pb.ContainerState_CONTAINER_STATE_RUNNING,
		Network:   &pb.NetworkInfo{IpAddress: "10.0.3.5"},
		Resources: &pb.ResourceLimits{Cpu: "2", Memory: "4GB", Disk: "20GB"},
		Image:     "ubuntu:24.04", PodmanEnabled: true,
	}))
	assertKeys(t, got, "name", "username", "state", "ipAddress", "cpu", "memory", "disk", "image", "podmanEnabled")
}

// previousState is omitted when unspecified — the map literal got that by
// only assigning the key when set, and omitempty has to reproduce it.
func TestContainerEventOmitsUnsetPreviousState(t *testing.T) {
	got := marshalToMap(t, containerEventToPayload(&pb.ContainerEvent{
		Container: &pb.Container{Name: "alice-container"},
	}))
	if _, present := got["previousState"]; present {
		t.Error("previousState is emitted when unspecified — it was omitted before, and a " +
			"consumer distinguishing absent from empty would now see a state change that " +
			"did not happen")
	}

	withPrev := marshalToMap(t, containerEventToPayload(&pb.ContainerEvent{
		Container:     &pb.Container{Name: "alice-container"},
		PreviousState: pb.ContainerState_CONTAINER_STATE_STOPPED,
	}))
	if _, present := withPrev["previousState"]; !present {
		t.Error("previousState is dropped when it IS set")
	}
}

func TestAppPayloadShape(t *testing.T) {
	got := marshalToMap(t, appToPayload(&pb.App{
		Id: "app-1", Name: "web", Username: "alice", ContainerName: "alice-container",
		Subdomain: "web", FullDomain: "web.example.com", Port: 8080,
		State: pb.AppState_APP_STATE_RUNNING,
	}))
	assertKeys(t, got, "id", "name", "username", "containerName", "subdomain", "fullDomain", "port", "state")
}

func TestRoutePayloadShape(t *testing.T) {
	ev := routeEventToPayload(&pb.RouteEvent{Route: &pb.ProxyRoute{
		Subdomain: "web", FullDomain: "web.example.com", ContainerIp: "10.0.3.5",
		Port: 8080, Active: true, AppId: "app-1", AppName: "web",
	}})
	inner := marshalToMap(t, ev.Route)
	assertKeys(t, inner, "subdomain", "fullDomain", "containerIp", "port", "active", "appId", "appName")
}

// The metric counters are int64 in the proto and were emitted as JSON numbers
// by the map literal. Typing them as strings would have been a silent break
// for any consumer doing arithmetic on them.
func TestMetricsPayloadEmitsNumbersNotStrings(t *testing.T) {
	b, err := json.Marshal(metricsEventToPayload(&pb.MetricsEvent{
		Metrics: []*pb.ContainerMetrics{{Name: "alice-container", CpuUsageSeconds: 42, MemoryUsageBytes: 1024}},
	}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var out struct {
		Metrics []struct {
			CPUUsageSeconds  json.RawMessage `json:"cpuUsageSeconds"`
			MemoryUsageBytes json.RawMessage `json:"memoryUsageBytes"`
		} `json:"metrics"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out.Metrics) != 1 {
		t.Fatalf("want 1 metric, got %d", len(out.Metrics))
	}
	if string(out.Metrics[0].CPUUsageSeconds) != "42" {
		t.Errorf("cpuUsageSeconds = %s, want the bare number 42 — a quoted string breaks any "+
			"consumer doing arithmetic on it", out.Metrics[0].CPUUsageSeconds)
	}
	if string(out.Metrics[0].MemoryUsageBytes) != "1024" {
		t.Errorf("memoryUsageBytes = %s, want 1024", out.Metrics[0].MemoryUsageBytes)
	}
}
