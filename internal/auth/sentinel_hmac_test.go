package auth

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

const testSecret = "abcdefghijklmnopqrstuvwxyz0123456789ABCD" // 40 bytes, satisfies SentinelMinSecretLen

func TestSignAndVerify_Roundtrip(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/authorized-keys", nil)
	SignSentinelRequest(req, []byte(testSecret))

	if err := VerifySentinelRequest(req, []byte(testSecret), time.Now()); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
}

func TestVerify_MissingHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/certs", nil)
	if err := VerifySentinelRequest(req, []byte(testSecret), time.Now()); err == nil {
		t.Fatal("unsigned request must be rejected")
	}
}

func TestVerify_WrongSecret(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/certs", nil)
	SignSentinelRequest(req, []byte(testSecret))

	otherSecret := strings.Repeat("X", 40)
	if err := VerifySentinelRequest(req, []byte(otherSecret), time.Now()); err == nil {
		t.Fatal("request signed with a different secret must be rejected")
	}
}

func TestVerify_TamperedPath(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/certs", nil)
	SignSentinelRequest(req, []byte(testSecret))

	// Forge a different path on the same signature. The verifier
	// rebuilds the canonical string from req.URL.Path, so a path
	// change must invalidate the signature.
	tampered := httptest.NewRequest(http.MethodGet, "/authorized-keys", nil)
	tampered.Header.Set(SentinelHeaderTimestamp, req.Header.Get(SentinelHeaderTimestamp))
	tampered.Header.Set(SentinelHeaderSignature, req.Header.Get(SentinelHeaderSignature))

	if err := VerifySentinelRequest(tampered, []byte(testSecret), time.Now()); err == nil {
		t.Fatal("tampered path must invalidate signature")
	}
}

func TestVerify_TamperedMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/certs", nil)
	SignSentinelRequest(req, []byte(testSecret))

	tampered := httptest.NewRequest(http.MethodPost, "/certs", nil)
	tampered.Header.Set(SentinelHeaderTimestamp, req.Header.Get(SentinelHeaderTimestamp))
	tampered.Header.Set(SentinelHeaderSignature, req.Header.Get(SentinelHeaderSignature))

	if err := VerifySentinelRequest(tampered, []byte(testSecret), time.Now()); err == nil {
		t.Fatal("tampered method must invalidate signature")
	}
}

func TestVerify_OldTimestampRejected(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/certs", nil)
	SignSentinelRequest(req, []byte(testSecret))

	future := time.Now().Add(SentinelMaxClockSkew + time.Minute)
	if err := VerifySentinelRequest(req, []byte(testSecret), future); err == nil {
		t.Fatal("stale timestamp must be rejected (replay protection)")
	}
}

func TestVerify_FutureTimestampRejected(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/certs", nil)
	// Manually stamp a far-future timestamp.
	req.Header.Set(SentinelHeaderTimestamp, strconv.FormatInt(time.Now().Add(2*SentinelMaxClockSkew).Unix(), 10))
	req.Header.Set(SentinelHeaderSignature, computeSentinelSignature([]byte(testSecret), http.MethodGet, "/certs", req.Header.Get(SentinelHeaderTimestamp)))

	if err := VerifySentinelRequest(req, []byte(testSecret), time.Now()); err == nil {
		t.Fatal("far-future timestamp must be rejected")
	}
}

func TestMiddleware_FailsClosedWithoutSecret(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	srv := SentinelHMACMiddleware(nil, next) // nil secret

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/certs", nil)
	srv.ServeHTTP(rec, req)

	if called {
		t.Fatal("handler must not run when secret is unconfigured")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
}

// TestMiddleware_UnconfiguredLogsLoudly is the regression guard for
// #341 §1: when the secret is missing and a request actually hits,
// the daemon must emit a WARNING (not just at startup) so the
// operator sees the misconfig in real-time log output during an
// incident.
func TestMiddleware_UnconfiguredLogsLoudly(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	// Reset rate-limit so this test stands on its own.
	lastDaemonMisconfigLogNs.Store(0)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	srv := SentinelHMACMiddleware(nil, next)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/authorized-keys", nil)
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
	if !strings.Contains(buf.String(), "sentinel-auth secret unconfigured") {
		t.Fatalf("missing-secret middleware must log misconfig; got %q", buf.String())
	}
	if !strings.Contains(buf.String(), "/authorized-keys") {
		t.Fatalf("log line should mention the request path; got %q", buf.String())
	}
}

// TestMiddleware_UnconfiguredLogRateLimit guards against log-flood:
// keysync hits every interval (often <1s), so without rate-limiting
// the daemon would dump 100+ identical WARNING lines per minute.
// The middleware logs at most once per minute — second invocation
// in the same window must be silent.
func TestMiddleware_UnconfiguredLogRateLimit(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	lastDaemonMisconfigLogNs.Store(0)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	srv := SentinelHMACMiddleware(nil, next)

	for i := 0; i < 5; i++ {
		srv.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/certs", nil))
	}

	if got := strings.Count(buf.String(), "sentinel-auth secret unconfigured"); got != 1 {
		t.Fatalf("want exactly 1 misconfig WARNING under rate-limit; got %d", got)
	}
}

func TestMiddleware_FailsClosedWithShortSecret(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	srv := SentinelHMACMiddleware([]byte("short"), next)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/certs", nil)
	SignSentinelRequest(req, []byte("short"))
	srv.ServeHTTP(rec, req)

	if called {
		t.Fatal("short secret must be treated as unconfigured")
	}
}

func TestMiddleware_PassesValidRequest(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	srv := SentinelHMACMiddleware([]byte(testSecret), next)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/certs", nil)
	SignSentinelRequest(req, []byte(testSecret))
	srv.ServeHTTP(rec, req)

	if !called {
		t.Fatal("valid signed request must reach handler")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
}

// ----- response signing -----

func TestSignAndVerifyResponse_Roundtrip(t *testing.T) {
	body := []byte(`{"peers":[{"id":"tunnel-1","proxy_path":"/peer/tunnel-1","healthy":true}]}`)
	rec := httptest.NewRecorder()
	SignSentinelResponse(rec, []byte(testSecret), body)
	rec.Body.Write(body)

	resp := rec.Result()
	if err := VerifySentinelResponse(resp, []byte(testSecret), body, time.Now()); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
}

func TestVerifyResponse_MissingHeaders(t *testing.T) {
	body := []byte(`{"peers":[]}`)
	// Build a response with no sig headers.
	rec := httptest.NewRecorder()
	rec.Body.Write(body)
	resp := rec.Result()

	if err := VerifySentinelResponse(resp, []byte(testSecret), body, time.Now()); err == nil {
		t.Fatal("unsigned response must be rejected")
	}
}

func TestVerifyResponse_TamperedBody(t *testing.T) {
	originalBody := []byte(`{"peers":[{"id":"tunnel-1","proxy_path":"/peer/tunnel-1"}]}`)
	rec := httptest.NewRecorder()
	SignSentinelResponse(rec, []byte(testSecret), originalBody)
	resp := rec.Result()

	// An attacker swaps the body bytes (e.g. injects a malicious
	// proxy_path). Even with the legitimate signature headers, the
	// recomputed HMAC over the tampered body must mismatch.
	tamperedBody := []byte(`{"peers":[{"id":"attacker","proxy_path":"/peer/attacker"}]}`)
	if err := VerifySentinelResponse(resp, []byte(testSecret), tamperedBody, time.Now()); err == nil {
		t.Fatal("tampered body must invalidate signature")
	}
}

func TestVerifyResponse_WrongSecret(t *testing.T) {
	body := []byte(`{"peers":[]}`)
	rec := httptest.NewRecorder()
	SignSentinelResponse(rec, []byte(testSecret), body)
	resp := rec.Result()

	other := strings.Repeat("X", 40)
	if err := VerifySentinelResponse(resp, []byte(other), body, time.Now()); err == nil {
		t.Fatal("wrong secret must reject the response")
	}
}

func TestVerifyResponse_StaleTimestamp(t *testing.T) {
	body := []byte(`{"peers":[]}`)
	rec := httptest.NewRecorder()
	SignSentinelResponse(rec, []byte(testSecret), body)
	resp := rec.Result()

	// Verifier "now" is far in the future → timestamp is stale.
	future := time.Now().Add(SentinelMaxClockSkew + time.Minute)
	if err := VerifySentinelResponse(resp, []byte(testSecret), body, future); err == nil {
		t.Fatal("stale timestamp must be rejected")
	}
}

func TestSignResponse_NoSecret_NoHeaders(t *testing.T) {
	// When the sentinel hasn't been configured with the secret it
	// should NOT write fake headers — the daemon's verifier will
	// then fail-closed (or, during rollout, log a loud warning).
	rec := httptest.NewRecorder()
	SignSentinelResponse(rec, nil, []byte(`{"peers":[]}`))

	if rec.Header().Get(SentinelHeaderSignature) != "" {
		t.Fatal("unconfigured secret must not produce signature header")
	}
	if rec.Header().Get(SentinelHeaderTimestamp) != "" {
		t.Fatal("unconfigured secret must not produce timestamp header")
	}
}

func TestSignResponse_ShortSecret_NoHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	SignSentinelResponse(rec, []byte("short"), []byte(`{"peers":[]}`))

	if rec.Header().Get(SentinelHeaderSignature) != "" {
		t.Fatal("short secret must not produce signature header")
	}
}
