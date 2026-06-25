package mcp

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// stateServer serves GET /v1/containers/<box> returning a sequence of
// states (the last one repeats once exhausted), so a test can model a box
// transitioning CREATING → RUNNING across polls.
func stateServer(t *testing.T, states []string, ip string) (*httptest.Server, *int32) {
	t.Helper()
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v1/containers/") {
			http.NotFound(w, r)
			return
		}
		n := atomic.AddInt32(&calls, 1)
		idx := int(n) - 1
		if idx >= len(states) {
			idx = len(states) - 1
		}
		state := states[idx]
		ipField := ip
		if state != "CONTAINER_STATE_RUNNING" {
			ipField = "" // not assigned until running
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"container":{"username":"tester","state":%q,"sshHost":"","network":{"ipAddress":%q}}}`, state, ipField)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func TestMCPWaitConnectable_RunningImmediately(t *testing.T) {
	srv, calls := stateServer(t, []string{"CONTAINER_STATE_RUNNING"}, "10.0.0.9")
	c := NewClient(srv.URL, "t")

	target, err := mcpWaitConnectable(c, "box", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target.Host != "10.0.0.9" || target.User != "tester" {
		t.Errorf("bad target: %+v", target)
	}
	if got := atomic.LoadInt32(calls); got != 1 {
		t.Errorf("expected 1 poll, got %d", got)
	}
}

func TestMCPWaitConnectable_WaitsThroughCreating(t *testing.T) {
	old := connectPollInterval
	connectPollInterval = 5 * time.Millisecond
	t.Cleanup(func() { connectPollInterval = old })

	srv, calls := stateServer(t, []string{
		"CONTAINER_STATE_CREATING",
		"CONTAINER_STATE_PROVISIONING",
		"CONTAINER_STATE_RUNNING",
	}, "10.0.0.5")
	c := NewClient(srv.URL, "t")

	target, err := mcpWaitConnectable(c, "box", "", "")
	if err != nil {
		t.Fatalf("should have waited for running, got: %v", err)
	}
	if target.Host != "10.0.0.5" {
		t.Errorf("bad target host: %q", target.Host)
	}
	if got := atomic.LoadInt32(calls); got < 3 {
		t.Errorf("expected at least 3 polls (creating→provisioning→running), got %d", got)
	}
}

func TestMCPWaitConnectable_StoppedFailsFast(t *testing.T) {
	old := connectPollInterval
	connectPollInterval = 5 * time.Millisecond
	t.Cleanup(func() { connectPollInterval = old })

	srv, calls := stateServer(t, []string{"CONTAINER_STATE_STOPPED"}, "")
	c := NewClient(srv.URL, "t")

	_, err := mcpWaitConnectable(c, "box", "", "")
	if err == nil {
		t.Fatal("expected an error for a stopped box")
	}
	if !strings.Contains(err.Error(), "start it first") {
		t.Errorf("stopped box should advise starting; got: %v", err)
	}
	if got := atomic.LoadInt32(calls); got != 1 {
		t.Errorf("stopped box should fail on the first poll, got %d polls", got)
	}
}

func TestMCPWaitConnectable_TransientTimesOut(t *testing.T) {
	oldI, oldT := connectPollInterval, connectReadyTimeout
	connectPollInterval = 5 * time.Millisecond
	connectReadyTimeout = 25 * time.Millisecond
	t.Cleanup(func() { connectPollInterval, connectReadyTimeout = oldI, oldT })

	srv, _ := stateServer(t, []string{"CONTAINER_STATE_CREATING"}, "")
	c := NewClient(srv.URL, "t")

	_, err := mcpWaitConnectable(c, "box", "", "")
	if err == nil {
		t.Fatal("expected a timeout error for a box stuck creating")
	}
	if !strings.Contains(err.Error(), "still creating") {
		t.Errorf("timeout should mention it's still creating; got: %v", err)
	}
}
