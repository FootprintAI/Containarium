package audit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Trenyx audit finding #4 (2026-09-16), HTTP half: HTTPAuditMiddleware had
// no test coverage at all before this. These tests cover both silent-loss
// paths the report named — a Log() error, and a full buffered channel
// dropping an entry before Log() was even attempted — now increment the
// shared persist-failure counter (see metrics_test.go for the equivalent
// gRPC-side coverage).

func waitForPersistFailureCount(t *testing.T, want int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if GetPersistFailureReport().Count >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("persist-failure count never reached %d; got %d", want, GetPersistFailureReport().Count)
}

func TestHTTPAuditMiddleware_LogErrorRecordsPersistFailure(t *testing.T) {
	ResetPersistFailuresForTest()
	t.Cleanup(ResetPersistFailuresForTest)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := HTTPAuditMiddleware(inner, errAuditLogger{})

	req := httptest.NewRequest(http.MethodPost, "/v1/containers/create", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("inner handler status = %d, want 200 — an audit-write failure must never surface to the request", rec.Code)
	}
	waitForPersistFailureCount(t, 1)
}

func TestHTTPAuditMiddleware_ChannelFullRecordsPersistFailure(t *testing.T) {
	ResetPersistFailuresForTest()
	t.Cleanup(ResetPersistFailuresForTest)

	blocker := &blockingAuditLogger{proceed: make(chan struct{})}
	defer close(blocker.proceed)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := HTTPAuditMiddleware(inner, blocker)

	fire := func() {
		req := httptest.NewRequest(http.MethodPost, "/v1/containers/create", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
	}

	// First request is dequeued immediately by the writer goroutine and
	// blocks inside Log(), holding the "in flight" slot — the 256-entry
	// buffer starts fully free after this.
	fire()
	time.Sleep(20 * time.Millisecond)

	for i := 0; i < 256; i++ {
		fire() // fills the buffer exactly
	}

	before := GetPersistFailureReport().Count
	fire() // the 258th request: buffer full, entry dropped and must be counted

	if got := GetPersistFailureReport().Count; got != before+1 {
		t.Fatalf("persist-failure count = %d, want %d — a channel-full drop must be counted", got, before+1)
	}
}
