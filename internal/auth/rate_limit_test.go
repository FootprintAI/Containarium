package auth

import (
	"net/http/httptest"
	"testing"
	"time"
)

// Phase 2.8 — per-IP rate limit on failed auth attempts
// (audit C-MED-3).

func TestAuthFailureLimiter_AllowsInitialBurst(t *testing.T) {
	l := NewAuthFailureLimiter()
	now := time.Now()
	for i := 0; i < authFailureBurst; i++ {
		if !l.Allow("10.0.0.1", now) {
			t.Fatalf("burst attempt %d should be allowed (max=%d)", i, authFailureBurst)
		}
	}
}

func TestAuthFailureLimiter_BlocksOverBurst(t *testing.T) {
	l := NewAuthFailureLimiter()
	now := time.Now()
	for i := 0; i < authFailureBurst; i++ {
		l.Allow("10.0.0.1", now)
	}
	if l.Allow("10.0.0.1", now) {
		t.Fatal("attempt over burst should be blocked")
	}
}

func TestAuthFailureLimiter_RefillsOverTime(t *testing.T) {
	l := NewAuthFailureLimiter()
	now := time.Now()
	// Burn the burst.
	for i := 0; i < authFailureBurst; i++ {
		l.Allow("10.0.0.1", now)
	}
	if l.Allow("10.0.0.1", now) {
		t.Fatal("immediate next attempt should still be blocked")
	}
	// Wait long enough to refill at least one token.
	later := now.Add(2 * time.Minute) // >= 1 token at 6/min
	if !l.Allow("10.0.0.1", later) {
		t.Fatal("after refill window, attempt should be allowed again")
	}
}

func TestAuthFailureLimiter_IPsAreIndependent(t *testing.T) {
	l := NewAuthFailureLimiter()
	now := time.Now()
	// Exhaust IP A.
	for i := 0; i < authFailureBurst; i++ {
		l.Allow("10.0.0.1", now)
	}
	if l.Allow("10.0.0.1", now) {
		t.Fatal("A exhausted")
	}
	// IP B starts fresh.
	if !l.Allow("10.0.0.2", now) {
		t.Fatal("B should be unaffected by A's exhaustion")
	}
}

func TestAuthFailureLimiter_NilSafe(t *testing.T) {
	// Tests sometimes pass a nil limiter; helper should fail-open.
	var l *AuthFailureLimiter
	if !l.Allow("10.0.0.1", time.Now()) {
		t.Fatal("nil limiter should be fail-open")
	}
}

func TestClientIPFromRequest_PrefersXFFLeftmost(t *testing.T) {
	r := httptest.NewRequest("GET", "/whatever", nil)
	r.Header.Set("X-Forwarded-For", "203.0.113.5, 10.0.0.5, 10.0.0.6")
	r.RemoteAddr = "10.0.0.6:55555"
	if got := clientIPFromRequest(r); got != "203.0.113.5" {
		t.Fatalf("XFF leftmost = %q, want 203.0.113.5", got)
	}
}

func TestClientIPFromRequest_FallsBackToRemoteAddr(t *testing.T) {
	r := httptest.NewRequest("GET", "/whatever", nil)
	r.RemoteAddr = "192.0.2.1:55555"
	if got := clientIPFromRequest(r); got != "192.0.2.1" {
		t.Fatalf("got %q, want 192.0.2.1", got)
	}
}

func TestClientIPFromRequest_TrimsXFFWhitespace(t *testing.T) {
	r := httptest.NewRequest("GET", "/whatever", nil)
	r.Header.Set("X-Forwarded-For", "  203.0.113.5  ")
	if got := clientIPFromRequest(r); got != "203.0.113.5" {
		t.Fatalf("got %q, want trimmed 203.0.113.5", got)
	}
}
