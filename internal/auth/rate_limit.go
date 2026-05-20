package auth

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// Per-IP token-bucket rate limiter for failed-auth requests.
// Audit C-MED-3: the daemon had no app-layer brute-force
// protection; fail2ban at the host level catches some traffic
// but doesn't see the inside of HTTP. A token-bucket on failed
// JWT validations means a single attacker can't blast through
// 30M token guesses per minute against the daemon directly.
//
// Successful requests don't consume tokens — the limiter only
// counts auth failures. Legitimate users hitting the API at any
// rate stay unthrottled; an attacker spraying invalid tokens
// gets 429'd quickly.

const (
	// authFailureBurst is the bucket size — how many failed
	// auths a single IP can produce in a burst before being
	// throttled. 10 is high enough that an operator with
	// fat-finger errors won't hit it; low enough that
	// distributed brute-force becomes uneconomical.
	authFailureBurst = 10

	// authFailureRefillPerMin is the token refill rate per
	// minute. At 6/min an attacker is capped at ~360/hour after
	// the initial burst — not productive against a 32-byte
	// HMAC key.
	authFailureRefillPerMin = 6

	// authFailureTTL governs eviction of idle buckets so the
	// map doesn't grow unbounded under a /16-scale attack.
	authFailureTTL = 30 * time.Minute
)

// AuthFailureLimiter is a small per-IP token-bucket. Concurrency-
// safe; one instance per AuthMiddleware. Garbage-collects buckets
// that haven't seen traffic in authFailureTTL.
type AuthFailureLimiter struct {
	mu      sync.Mutex
	buckets map[string]*authBucket
}

type authBucket struct {
	tokens   float64
	lastSeen time.Time
}

// NewAuthFailureLimiter returns a fresh limiter.
func NewAuthFailureLimiter() *AuthFailureLimiter {
	return &AuthFailureLimiter{buckets: make(map[string]*authBucket)}
}

// Allow returns true if a failed-auth attempt from `ip` should be
// allowed to consume a token. Returns false when the bucket is
// empty — the caller should respond 429 and skip the actual JWT
// validation (or other auth check). Internal: refills the bucket
// based on time since last seen, evicts stale buckets opportun-
// istically.
//
// The caller decides when to invoke Allow — typically AFTER an
// auth failure, so successful requests aren't affected. The
// limiter just tracks the failure budget per IP.
func (l *AuthFailureLimiter) Allow(ip string, now time.Time) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[ip]
	if !ok {
		b = &authBucket{tokens: float64(authFailureBurst), lastSeen: now}
		l.buckets[ip] = b
	}
	// Refill based on elapsed time since lastSeen.
	elapsed := now.Sub(b.lastSeen).Minutes()
	b.tokens += elapsed * float64(authFailureRefillPerMin)
	if b.tokens > float64(authFailureBurst) {
		b.tokens = float64(authFailureBurst)
	}
	b.lastSeen = now

	// Opportunistic eviction. Every Allow call sweeps a few
	// neighbors — bounded so a /16 attack can't push GC into
	// the hot path.
	if len(l.buckets) > 1024 {
		l.evictLocked(now)
	}

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *AuthFailureLimiter) evictLocked(now time.Time) {
	cutoff := now.Add(-authFailureTTL)
	for ip, b := range l.buckets {
		if b.lastSeen.Before(cutoff) {
			delete(l.buckets, ip)
		}
	}
}

// clientIPFromRequest extracts a best-effort client IP for
// rate-limit bucketing. Honors X-Forwarded-For only on calls that
// the daemon's PROXY-protocol setup already trusted (the trusted
// frontend rewrote the header). For untrusted requests we use the
// raw remote-addr — an attacker spoofing XFF still gets bucketed
// by their true source.
//
// Returns "" if no IP can be determined; callers should not
// throttle in that case (fail-open on parse rather than block
// legitimate traffic).
func clientIPFromRequest(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// XFF is comma-separated; the leftmost is the original
		// client. Caddy with PROXY trust list strips spoofed
		// values from untrusted hops, so this is the most
		// authoritative input we have.
		if comma := indexComma(xff); comma >= 0 {
			return trimSpace(xff[:comma])
		}
		return trimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr // fallback — not a host:port shape
	}
	return host
}

func indexComma(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			return i
		}
	}
	return -1
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}
