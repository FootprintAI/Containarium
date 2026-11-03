package mcp

import (
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCreateContainerBirthIdleStopSchema(t *testing.T) {
	server, err := NewServer(&Config{ServerURL: "http://127.0.0.1:1", JWTToken: "test"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range server.tools {
		if tool.Name != "create_container" {
			continue
		}
		properties := tool.InputSchema["properties"].(map[string]interface{})
		field, ok := properties["idle_stop_minutes"].(map[string]interface{})
		if !ok || field["type"] != "integer" || field["minimum"] != 0 {
			t.Fatalf("birth idle-stop must be an optional integer >= 0: %+v", field)
		}
		for _, required := range tool.InputSchema["required"].([]string) {
			if required == "idle_stop_minutes" {
				t.Fatal("birth idle-stop must remain optional")
			}
		}
		return
	}
	t.Fatal("create_container tool missing")
}

func TestHandleCreateContainerBirthIdleStopWire(t *testing.T) {
	for _, tc := range []struct {
		name     string
		extra    map[string]interface{}
		expected float64
		present  bool
		disable  bool
	}{
		{name: "explicit birth idle stop", extra: map[string]interface{}{"idle_stop_minutes": float64(7)}, expected: 7, present: true},
		{name: "omitted keeps default", extra: map[string]interface{}{}},
		{name: "zero keeps default", extra: map[string]interface{}{"idle_stop_minutes": float64(0)}},
		{name: "disable flag unaffected", extra: map[string]interface{}{"disable_auto_sleep": true}, disable: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var captured map[string]interface{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/v1/containers" {
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
				}
				if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
					t.Errorf("decode: %v", err)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"container":{"name":"alice-container","username":"alice","state":"CONTAINER_STATE_RUNNING"},"message":"ok"}`))
			}))
			defer srv.Close()

			args := map[string]interface{}{"username": "alice", "ssh_keys": []interface{}{"ssh-ed25519 AAAA"}}
			for k, v := range tc.extra {
				args[k] = v
			}
			_, err := handleCreateContainer(NewClient(srv.URL, "token"), args)
			if err != nil {
				t.Fatalf("create: %v", err)
			}
			idle, exists := captured["idleStopMinutes"]
			if exists != tc.present || (exists && idle != tc.expected) {
				t.Errorf("idleStopMinutes: got %v (present %t), want %v (present %t)", idle, exists, tc.expected, tc.present)
			}
			flag, exists := captured["disableAutoSleep"]
			if exists != tc.disable || (exists && flag != true) {
				t.Errorf("disableAutoSleep: got %v (present %t), want %t", flag, exists, tc.disable)
			}
		})
	}
}

func TestHandleCreateContainerBirthIdleStopRejectsInvalid(t *testing.T) {
	for _, tc := range []struct {
		name    string
		value   interface{}
		disable bool
	}{
		{"negative", float64(-1), false},
		{"fractional", float64(1.25), false},
		{"overflow", float64(2147483648), false},
		{"NaN", math.NaN(), false},
		{"string", "1", false},
		{"bool", true, false},
		{"contradictory flag", float64(5), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := map[string]interface{}{
				"username":           "alice",
				"ssh_keys":           []interface{}{"ssh-ed25519 AAAA"},
				"idle_stop_minutes":  tc.value,
				"disable_auto_sleep": tc.disable,
			}
			_, err := handleCreateContainer(NewClient("http://127.0.0.1:1", "test"), args)
			if err == nil {
				t.Fatalf("%s must reject invalid birth auto-sleep before request", tc.name)
			}
		})
	}
}

func TestCreateContainerRequestIdleStopJSON(t *testing.T) {
	for _, tc := range []struct {
		minutes int32
		present bool
	}{
		{minutes: 0, present: false},
		{minutes: 20, present: true},
	} {
		data, err := json.Marshal(CreateContainerRequest{Username: "alice", IdleStopMinutes: tc.minutes})
		if err != nil {
			t.Fatal(err)
		}
		var parsed map[string]interface{}
		if err := json.Unmarshal(data, &parsed); err != nil {
			t.Fatal(err)
		}
		_, ok := parsed["idleStopMinutes"]
		if ok != tc.present {
			t.Fatalf("minutes %d: wire presence %t, want %t; JSON %s", tc.minutes, ok, tc.present, data)
		}
	}
}
