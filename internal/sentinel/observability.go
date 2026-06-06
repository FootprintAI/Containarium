package sentinel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// Spot-preemption observability (#514 follow-up).
//
// The monitoring stack (VictoriaMetrics + vmalert + Alertmanager) runs in a
// container ON the backend spot VM, so it dies WITH the spot — it cannot
// alert on the spot's own preemption. The always-on sentinel is the only
// component that survives the outage, so it owns this signal, exposed two
// ways:
//
//   - An outbound webhook fired the instant the spot is preempted ("down")
//     and the instant it returns to proxy ("recovered"/"up"). Self-contained;
//     depends on nothing on the spot.
//   - A Prometheus /metrics endpoint with two monotonic counters
//     (sentinel_preempted_total / sentinel_recovered_total) plus point-in-time
//     gauges, for an EXTERNAL scraper to alert on the net
//     (preempted_total - recovered_total > 0 == "currently down").
//
// Both run from the sentinel's single event-loop goroutine (fireAlert is
// called from handleEvent / healthCheckAll); the HTTP /metrics read takes a
// consistent snapshot via the exported getters.

// alertPayload is the JSON body POSTed to AlertWebhookURL.
type alertPayload struct {
	Event          string `json:"event"` // "preempted" | "recovered"
	Backend        string `json:"backend"`
	PreemptedTotal int    `json:"preempted_total"`
	RecoveredTotal int    `json:"recovered_total"`
	// Outstanding is preempted_total - recovered_total: > 0 means the spot
	// is currently down (an unrecovered preemption). This is the "net" to
	// alert on; included so a dumb webhook consumer can branch without state.
	Outstanding   int    `json:"outstanding"`
	OutageSeconds int64  `json:"outage_seconds,omitempty"` // set on "recovered"
	Timestamp     string `json:"timestamp"`
}

// fireAlert POSTs an alert to the configured webhook, best-effort and
// asynchronous so it never blocks (or fails) the event loop. A nil/empty
// AlertWebhookURL is a no-op. The counters are read on the calling
// goroutine (consistent snapshot) and captured into the payload before the
// POST is dispatched.
func (m *Manager) fireAlert(event, backend string, outage time.Duration) {
	if m.config.AlertWebhookURL == "" {
		return
	}
	payload := alertPayload{
		Event:          event,
		Backend:        backend,
		PreemptedTotal: m.preemptCount,
		RecoveredTotal: m.recoveredCount,
		Outstanding:    m.preemptCount - m.recoveredCount,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
	}
	if outage > 0 {
		payload.OutageSeconds = int64(outage.Seconds())
	}
	url := m.config.AlertWebhookURL
	go func() {
		body, err := json.Marshal(payload)
		if err != nil {
			log.Printf("[sentinel] alert webhook: marshal: %v", err)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			log.Printf("[sentinel] alert webhook: build request: %v", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Printf("[sentinel] alert webhook POST %s failed: %v", event, err)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode >= 400 {
			log.Printf("[sentinel] alert webhook POST %s returned %d", event, resp.StatusCode)
			return
		}
		log.Printf("[sentinel] alert webhook %s delivered (outstanding=%d)", event, payload.Outstanding)
	}()
}

// MetricsHandler serves Prometheus text-format metrics for the spot
// preemption/recovery signal. Mounted at /metrics on the sentinel's
// always-on HTTP server, so an EXTERNAL Prometheus / Grafana Cloud can
// scrape it (the on-spot VictoriaMetrics can't — it's on the box that goes
// down). Alert on `sentinel_preempted_total - sentinel_recovered_total > 0`.
func (m *Manager) MetricsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		state := 0 // 0 = maintenance/down, 1 = proxy/up
		if m.CurrentState() == StateProxy {
			state = 1
		}
		outageSecs := int64(0)
		if od := m.OutageDuration(); od > 0 {
			outageSecs = int64(od.Seconds())
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		fmt.Fprint(w, m.renderMetrics(state, outageSecs))
	}
}

// renderMetrics builds the Prometheus exposition text. Split out (pure) so
// it's unit-testable without an HTTP round trip.
func (m *Manager) renderMetrics(state int, outageSecs int64) string {
	var b bytes.Buffer
	fmt.Fprint(&b, "# HELP sentinel_preempted_total Total spot-VM preemption events observed.\n")
	fmt.Fprint(&b, "# TYPE sentinel_preempted_total counter\n")
	fmt.Fprintf(&b, "sentinel_preempted_total %d\n", m.PreemptCount())
	fmt.Fprint(&b, "# HELP sentinel_recovered_total Total returns to proxy after an outage.\n")
	fmt.Fprint(&b, "# TYPE sentinel_recovered_total counter\n")
	fmt.Fprintf(&b, "sentinel_recovered_total %d\n", m.RecoveredCount())
	fmt.Fprint(&b, "# HELP sentinel_state Backend serving state: 1 proxy (up), 0 maintenance (down).\n")
	fmt.Fprint(&b, "# TYPE sentinel_state gauge\n")
	fmt.Fprintf(&b, "sentinel_state %d\n", state)
	fmt.Fprint(&b, "# HELP sentinel_outage_seconds Duration of the current outage; 0 when serving.\n")
	fmt.Fprint(&b, "# TYPE sentinel_outage_seconds gauge\n")
	fmt.Fprintf(&b, "sentinel_outage_seconds %d\n", outageSecs)
	return b.String()
}
