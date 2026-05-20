package auth

import (
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
