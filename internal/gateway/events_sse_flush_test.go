package gateway

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/events"
)

// #2773 review: HandleSSE used to type-assert w.(http.Flusher), which only
// worked because /v1/events/subscribe is mounted raw and audit-skipped. Under
// the audited chain the wrapper hides the Flusher, so every subscriber would
// have been told "SSE not supported". The handler now flushes through
// http.ResponseController, which follows Unwrap. This mounts it on an
// audited path (not one of audit's skip prefixes) and reads the first event.
func TestHandleSSE_FlushesFirstEventUnderAuditMiddleware(t *testing.T) {
	bus := events.NewBus()
	h := NewEventHandler(bus)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/test/sse", h.HandleSSE)

	srv := httptest.NewServer(audit.HTTPAuditMiddleware(mux, noopAuditLogger{}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/v1/test/sse", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("Content-Type = %q, want text/event-stream", ct)
	}

	// The handler is still blocked in its select loop (no events, heartbeat
	// is 15s away): the only way these lines arrive is the per-event flush.
	sc := bufio.NewScanner(resp.Body)
	var got []string
	for sc.Scan() {
		got = append(got, sc.Text())
		if len(got) == 2 {
			break
		}
	}
	if len(got) != 2 || got[0] != "event: connected" || !strings.HasPrefix(got[1], `data: {"subscriptionId":`) {
		t.Fatalf("first event = %q, want connected event", got)
	}
	cancel()
}

// A writer with no Flusher anywhere below it is the one case that still
// earns the 500; the status must be the sentinel-matched branch, not a
// buffered 200.
func TestHandleSSE_NoFlusherIsStill500(t *testing.T) {
	h := NewEventHandler(events.NewBus())
	rec := httptest.NewRecorder()
	// Embedding the interface hides the recorder's Flush and offers no Unwrap.
	w := struct{ http.ResponseWriter }{rec}
	h.HandleSSE(w, httptest.NewRequest(http.MethodGet, "/v1/events/subscribe", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "SSE not supported") {
		t.Fatalf("body = %q", rec.Body.String())
	}
}
