package sentinel

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRenderMetrics_Format(t *testing.T) {
	m := NewManager(Config{}, &fakeRecoveryProvider{})
	m.preemptCount = 3
	m.recoveredCount = 2
	out := m.renderMetrics(0 /*down*/, 42)

	for _, want := range []string{
		"# TYPE sentinel_preempted_total counter",
		"sentinel_preempted_total 3",
		"sentinel_recovered_total 2",
		"sentinel_state 0",
		"sentinel_outage_seconds 42",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics output missing %q\n--- got ---\n%s", want, out)
		}
	}
	// The net (3 preempted - 2 recovered = 1 outstanding) is what an
	// external alert evaluates; the raw counters must both be present.
}

func TestMetricsHandler_ServesText(t *testing.T) {
	m := NewManager(Config{}, &fakeRecoveryProvider{})
	m.state.Store(StateProxy)
	m.preemptCount = 1
	rec := httptest.NewRecorder()
	m.MetricsHandler()(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("content-type = %q, want text/plain…", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "sentinel_state 1") { // proxy = up
		t.Errorf("expected sentinel_state 1 (proxy); got:\n%s", body)
	}
}

func TestFireAlert_NoWebhookIsNoop(t *testing.T) {
	// No AlertWebhookURL → fireAlert must not panic or block.
	m := NewManager(Config{}, &fakeRecoveryProvider{})
	m.fireAlert("preempted", "gcp", 0) // should simply return
}

func TestFireAlert_PostsPayload(t *testing.T) {
	var (
		mu   sync.Mutex
		got  alertPayload
		seen bool
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		_ = json.Unmarshal(b, &got)
		seen = true
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	m := NewManager(Config{AlertWebhookURL: srv.URL}, &fakeRecoveryProvider{})
	m.preemptCount = 5
	m.recoveredCount = 2
	m.fireAlert("preempted", "gcp", 0)

	// fireAlert dispatches the POST asynchronously; wait briefly.
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		done := seen
		mu.Unlock()
		if done || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	if !seen {
		t.Fatal("webhook was never called")
	}
	if got.Event != "preempted" || got.Backend != "gcp" {
		t.Errorf("payload event/backend = %q/%q", got.Event, got.Backend)
	}
	if got.PreemptedTotal != 5 || got.RecoveredTotal != 2 || got.Outstanding != 3 {
		t.Errorf("payload counters = preempted:%d recovered:%d outstanding:%d, want 5/2/3",
			got.PreemptedTotal, got.RecoveredTotal, got.Outstanding)
	}
}
