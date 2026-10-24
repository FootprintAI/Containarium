package sentinel

import (
	"context"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/footprintai/containarium/internal/auth"
)

// Per-primary daemon-AUTH health for /status (#2892).
//
// A mismatch between the sentinel's CONTAINARIUM_SENTINEL_AUTH_SECRET and a
// daemon's is otherwise visible only as 401s in logs. This records, per
// primary, whether a daemon-AUTH-gated request from its address was rejected
// with 401 since its own last authenticated registration, heartbeat or
// deregister, and when. It holds NOTHING derived from the secret: only pool
// names, times and counts.
//
// Only primaries that register over HTTP (/sentinel/primaries) are listed.
// A primary promoted by a tunnel handshake never makes those requests, so it
// is never listed, whatever its secret.
//
// Two rules keep an unauthenticated caller from creating state or poisoning
// a real primary:
//
//   - A primary's identity (its pool) is learned only from an AUTHENTICATED
//     /sentinel/primaries request, together with that request's transport
//     source address. No other request creates an entry, and the cap below
//     bounds them even then.
//   - A rejected request is attributed by its source address alone, never by
//     the pool name it carries (that name is unauthenticated). It counts
//     against a primary only when exactly one tracked primary was last seen
//     authenticating from that address; otherwise it bumps one global
//     counter, which is O(1) memory however many arrive.
//
// Residual: a client sending from the same address as a primary (the same
// host, or the same NAT) can make that primary look failing until its next
// heartbeat (every 30s) authenticates again. It cannot hide a real failure:
// failures_since_success only resets on that primary's own authenticated
// registration, heartbeat or deregister (bind), not on any other
// authenticated request from the same address.

// PrimaryAuthState is the outcome of a primary's most recent daemon-AUTH
// request.
type PrimaryAuthState string

const (
	// PrimaryAuthOK: no 401 from the primary's address since its last
	// authenticated registration, heartbeat or deregister.
	PrimaryAuthOK PrimaryAuthState = "ok"
	// PrimaryAuthFailing401: a 401 from the primary's address since then
	// (secret mismatch, or clock skew beyond auth.SentinelMaxClockSkew).
	PrimaryAuthFailing401 PrimaryAuthState = "failing_401"
)

const (
	// maxTrackedPrimaryAuth caps tracked primaries. Entries are created only
	// by authenticated callers, so this is defence in depth.
	maxTrackedPrimaryAuth = 256
	// primaryAuthRetention drops a primary not heard from (success or
	// attributed failure) for this long. Long enough to outlive a
	// deregistration followed by a rotation that 401s.
	primaryAuthRetention = 24 * time.Hour
)

// PrimaryAuthHealthJSON is one primary's entry in /status.
type PrimaryAuthHealthJSON struct {
	Pool                 string           `json:"pool"`
	State                PrimaryAuthState `json:"state"`
	LastSuccess          string           `json:"last_success,omitempty"`
	LastFailure          string           `json:"last_failure,omitempty"`
	FailuresSinceSuccess uint64           `json:"failures_since_success"`
}

type primaryAuthEntry struct {
	addr                 string
	lastSuccess          time.Time
	lastFailure          time.Time
	failuresSinceSuccess uint64
}

func (e *primaryAuthEntry) lastSeen() time.Time {
	if e.lastFailure.After(e.lastSuccess) {
		return e.lastFailure
	}
	return e.lastSuccess
}

// primaryAuthTracker is usable as a zero value.
type primaryAuthTracker struct {
	mu               sync.Mutex
	entries          map[Pool]*primaryAuthEntry
	unattributed     uint64
	lastUnattributed time.Time
	now              func() time.Time
}

func (t *primaryAuthTracker) clock() time.Time {
	if t.now != nil {
		return t.now()
	}
	return time.Now()
}

// prune drops expired entries. Caller holds mu.
func (t *primaryAuthTracker) prune(now time.Time) {
	for pool, e := range t.entries {
		if now.Sub(e.lastSeen()) > primaryAuthRetention {
			delete(t.entries, pool)
		}
	}
}

// bind records an AUTHENTICATED request from pool at addr. Only call it after
// the HMAC middleware has accepted the request.
func (t *primaryAuthTracker) bind(pool Pool, addr string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.clock()
	if t.entries == nil {
		t.entries = make(map[Pool]*primaryAuthEntry)
	}
	e, ok := t.entries[pool]
	if !ok {
		t.prune(now)
		if len(t.entries) >= maxTrackedPrimaryAuth {
			var oldest Pool
			var oldestAt time.Time
			first := true
			for p, x := range t.entries {
				if first || x.lastSeen().Before(oldestAt) {
					oldest, oldestAt, first = p, x.lastSeen(), false
				}
			}
			delete(t.entries, oldest)
		}
		e = &primaryAuthEntry{}
		t.entries[pool] = e
	}
	e.addr = addr
	e.lastSuccess = now
	e.failuresSinceSuccess = 0
}

// observe records the outcome of a daemon-AUTH-gated request from addr. A
// 401 is attributed to the one primary last bound to addr, if any. An
// authenticated request changes nothing here: only that primary's own bind
// clears its failures, so another daemon authenticating from the same
// address cannot hide a primary's wrong secret.
func (t *primaryAuthTracker) observe(addr string, authenticated bool) {
	if authenticated {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.clock()
	var match *primaryAuthEntry
	n := 0
	for _, e := range t.entries {
		if addr != "" && e.addr == addr {
			match = e
			n++
		}
	}
	if n == 1 {
		match.lastFailure = now
		match.failuresSinceSuccess++
		return
	}
	t.unattributed++
	t.lastUnattributed = now
}

// snapshot returns per-primary health sorted by pool, plus the unattributed
// 401 count and time of the latest one.
func (t *primaryAuthTracker) snapshot() ([]PrimaryAuthHealthJSON, uint64, time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.prune(t.clock())
	out := make([]PrimaryAuthHealthJSON, 0, len(t.entries))
	for pool, e := range t.entries {
		h := PrimaryAuthHealthJSON{
			Pool:                 string(pool),
			State:                PrimaryAuthOK,
			FailuresSinceSuccess: e.failuresSinceSuccess,
		}
		if !e.lastSuccess.IsZero() {
			h.LastSuccess = e.lastSuccess.Format(time.RFC3339)
		}
		if !e.lastFailure.IsZero() {
			h.LastFailure = e.lastFailure.Format(time.RFC3339)
		}
		// Only the primary's own authenticated registration, heartbeat or
		// deregister (bind) resets the count, so a non-zero count means a 401
		// from its address since then.
		if e.failuresSinceSuccess > 0 {
			h.State = PrimaryAuthFailing401
		}
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Pool < out[j].Pool })
	return out, t.unattributed, t.lastUnattributed
}

// requestSourceAddr is the transport source IP: what a client cannot choose
// without actually sending from it (unlike any header or pool name).
func requestSourceAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	return host
}

type daemonAuthReachedKey struct{}

// daemonAuthGate is auth.SentinelHMACMiddleware over the daemon AUTH secret,
// plus recording each request's outcome in m.authHealth. The middleware
// either rejects with 401 or calls next, so reaching next is exactly
// "authenticated".
func (m *Manager) daemonAuthGate(next http.Handler) http.Handler {
	gated := auth.SentinelHMACMiddleware(m.hmacSecret, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if reached, ok := r.Context().Value(daemonAuthReachedKey{}).(*bool); ok {
			*reached = true
		}
		next.ServeHTTP(w, r)
	}))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reached bool
		gated.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), daemonAuthReachedKey{}, &reached)))
		m.authHealth.observe(requestSourceAddr(r), reached)
	})
}
