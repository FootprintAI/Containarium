package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHandleToggleAutoSleep_RequiresUsername — missing or empty
// username short-circuits before any HTTP call. Client URL points at
// an unreachable address; reaching it would surface a different
// error.
func TestHandleToggleAutoSleep_RequiresUsername(t *testing.T) {
	client := NewClient("http://127.0.0.1:1", "tok")
	cases := []map[string]interface{}{
		{},
		{"enabled": true},
		{"username": "", "enabled": true},
	}
	for _, args := range cases {
		_, err := handleToggleAutoSleep(client, args)
		if err == nil {
			t.Errorf("expected error for args=%v", args)
			continue
		}
		if !strings.Contains(err.Error(), "username") {
			t.Errorf("err = %v, want mention of 'username'", err)
		}
	}
}

// TestHandleToggleAutoSleep_RequiresEnabledBool — `enabled` is a
// required field; pass-through types other than bool (or absent) must
// fail before the HTTP call.
func TestHandleToggleAutoSleep_RequiresEnabledBool(t *testing.T) {
	client := NewClient("http://127.0.0.1:1", "tok")
	cases := []map[string]interface{}{
		{"username": "alice"},                     // missing
		{"username": "alice", "enabled": "true"},  // string, not bool
		{"username": "alice", "enabled": 1},       // int, not bool
	}
	for _, args := range cases {
		_, err := handleToggleAutoSleep(client, args)
		if err == nil || !strings.Contains(err.Error(), "enabled") {
			t.Errorf("args=%v: err = %v, want 'enabled' validation", args, err)
		}
	}
}

// TestHandleToggleAutoSleep_OmitsThresholdDefaultsToZero — when
// idleThresholdMinutes is absent from args, the handler sends 0 over
// the wire. The server side then applies its 15-minute default. This
// is the contract between MCP and the daemon.
func TestHandleToggleAutoSleep_OmitsThresholdDefaultsToZero(t *testing.T) {
	var captured map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewDecoder(r.Body).Decode(&captured))
		_, _ = w.Write([]byte(`{"message":"ok","autoSleepEnabled":true,"idleThresholdMinutes":15}`))
	}))
	defer srv.Close()
	client := NewClient(srv.URL, "tok")

	out, err := handleToggleAutoSleep(client, map[string]interface{}{
		"username": "alice",
		"enabled":  true,
	})
	require.NoError(t, err)
	assert.Contains(t, out, "auto_sleep_enabled=true")
	assert.EqualValues(t, 0, captured["idle_threshold_minutes"], "absent idleThresholdMinutes must wire as 0 so server applies default")
}

// TestHandleToggleAutoSleep_ThresholdPropagates — explicit
// idleThresholdMinutes lands intact on the wire. Verifies JSON-number
// (float64) decode path in getIntArg.
func TestHandleToggleAutoSleep_ThresholdPropagates(t *testing.T) {
	var captured map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewDecoder(r.Body).Decode(&captured))
		_, _ = w.Write([]byte(`{"message":"ok","autoSleepEnabled":true,"idleThresholdMinutes":45}`))
	}))
	defer srv.Close()
	client := NewClient(srv.URL, "tok")

	_, err := handleToggleAutoSleep(client, map[string]interface{}{
		"username":             "alice",
		"enabled":              true,
		"idleThresholdMinutes": float64(45), // JSON number arrives as float64
	})
	require.NoError(t, err)
	assert.EqualValues(t, 45, captured["idle_threshold_minutes"])
}

// TestHandleStartContainer_WaitForReadyPropagates — the waitForReady
// MCP arg must land in the request body as wait_for_ready.
func TestHandleStartContainer_WaitForReadyPropagates(t *testing.T) {
	var captured map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewDecoder(r.Body).Decode(&captured))
		_, _ = w.Write([]byte(`{"message":"started","container":{"state":"Running"},"readyTimedOut":false}`))
	}))
	defer srv.Close()
	client := NewClient(srv.URL, "tok")

	_, err := handleStartContainer(client, map[string]interface{}{
		"username":     "alice",
		"waitForReady": true,
	})
	require.NoError(t, err)
	assert.Equal(t, true, captured["wait_for_ready"])
}

// TestHandleStartContainer_DefaultWaitForReadyFalse — the boolean
// default must be false (matches the proto's zero value); otherwise
// every start_container without an explicit waitForReady would block
// on the 30s probe.
func TestHandleStartContainer_DefaultWaitForReadyFalse(t *testing.T) {
	var captured map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewDecoder(r.Body).Decode(&captured))
		_, _ = w.Write([]byte(`{"message":"started","container":{"state":"Running"},"readyTimedOut":false}`))
	}))
	defer srv.Close()
	client := NewClient(srv.URL, "tok")

	_, err := handleStartContainer(client, map[string]interface{}{"username": "alice"})
	require.NoError(t, err)
	assert.Equal(t, false, captured["wait_for_ready"])
}

// TestHandleStartContainer_RequiresUsername — handler validates
// before hitting the wire.
func TestHandleStartContainer_RequiresUsername(t *testing.T) {
	client := NewClient("http://127.0.0.1:1", "tok")
	_, err := handleStartContainer(client, map[string]interface{}{})
	if err == nil || !strings.Contains(err.Error(), "username") {
		t.Errorf("err = %v, want 'username is required'", err)
	}
}

// TestHandleStartContainer_ShowsTimeoutWarning — when daemon reports
// readyTimedOut=true, the response text includes a warning sigil
// that operators recognise.
func TestHandleStartContainer_ShowsTimeoutWarning(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"message":"started","container":{"state":"Running"},"readyTimedOut":true}`))
	}))
	defer srv.Close()
	client := NewClient(srv.URL, "tok")
	out, err := handleStartContainer(client, map[string]interface{}{"username": "alice", "waitForReady": true})
	require.NoError(t, err)
	assert.Contains(t, out, "readiness probe timed out")
}
