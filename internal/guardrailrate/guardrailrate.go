// Package guardrailrate is the per-subject token-bucket rate limit on the
// guardrail APIs (#2404): the gated DeployRecipe path and
// GuardrailPolicyService Set/Get. There is no limit on how much data a gated
// deploy may copy (#2368); what is bounded is how often a caller may ask the
// daemon to do that work.
//
// The model is internal/sandbox/ratelimit (a golang.org/x/time/rate bucket
// per subject, burst defaulting to the per-minute rate), plus what a
// guardrail limit needs on top: an injectable clock, a gRPC
// RESOURCE_EXHAUSTED refusal carrying a RetryInfo hint (HTTP 429 through
// grpc-gateway), one throttle log line per caller per ThrottleLogInterval,
// and eviction of idle buckets.
package guardrailrate

import (
	"fmt"
	"log"
	"math"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

// ThrottleLogInterval is the most often one caller's throttling is logged
// per limit; a flood of refused calls cannot flood the daemon log.
const ThrottleLogInterval = time.Minute

// Limit is one configured rate. PerMinute <= 0 disables the limit. Burst <= 0
// defaults to PerMinute rounded down, floor 1 (internal/sandbox/ratelimit's
// convention).
type Limit struct {
	PerMinute float64
	Burst     int
}

// Option configures a Limiter.
type Option func(*Limiter)

// WithClock replaces time.Now (tests use a fake clock).
func WithClock(now func() time.Time) Option { return func(l *Limiter) { l.now = now } }

// WithLogf replaces log.Printf for the throttle line.
func WithLogf(logf func(string, ...any)) Option { return func(l *Limiter) { l.logf = logf } }

// Limiter is a per-subject token bucket. A nil *Limiter, or one built from a
// disabled Limit, allows everything. Safe for concurrent use.
type Limiter struct {
	name  string
	every rate.Limit
	burst int
	// idleTTL is how long an empty bucket takes to refill completely: a
	// bucket idle that long is indistinguishable from a new one, so it is
	// dropped.
	idleTTL time.Duration

	now  func() time.Time
	logf func(string, ...any)

	mu        sync.Mutex
	buckets   map[string]*bucket
	lastSweep time.Time
}

type bucket struct {
	lim        *rate.Limiter
	lastSeen   time.Time
	lastLogged time.Time
	suppressed int
}

// New builds the limiter named name (it appears in refusals and log lines).
func New(name string, lim Limit, opts ...Option) *Limiter {
	l := &Limiter{name: name, now: time.Now, logf: log.Printf}
	for _, o := range opts {
		o(l)
	}
	if lim.PerMinute <= 0 {
		return l
	}
	burst := lim.Burst
	if burst <= 0 {
		burst = int(lim.PerMinute)
	}
	if burst < 1 {
		burst = 1
	}
	l.every = rate.Limit(lim.PerMinute / 60)
	l.burst = burst
	l.idleTTL = time.Duration(float64(burst) / float64(l.every) * float64(time.Second))
	l.buckets = make(map[string]*bucket)
	return l
}

// Enabled reports whether the limiter refuses anything at all.
func (l *Limiter) Enabled() bool { return l != nil && l.every > 0 }

// Check consumes one token from subject's bucket. It returns nil when the
// call may proceed, or a RESOURCE_EXHAUSTED status with a RetryInfo detail
// when the caller is over the limit; a refused call consumes nothing.
func (l *Limiter) Check(subject string) error {
	if !l.Enabled() {
		return nil
	}
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweep(now)
	b, ok := l.buckets[subject]
	if !ok {
		b = &bucket{lim: rate.NewLimiter(l.every, l.burst)}
		l.buckets[subject] = b
	}
	b.lastSeen = now
	if b.lim.AllowN(now, 1) {
		return nil
	}

	missing := 1 - b.lim.TokensAt(now)
	retry := time.Duration(math.Ceil(missing/float64(l.every))) * time.Second
	if retry < time.Second {
		retry = time.Second
	}
	l.logThrottled(subject, b, now)

	st := status.New(codes.ResourceExhausted,
		fmt.Sprintf("%s rate limit exceeded for this caller; retry in %s", l.name, retry))
	if withInfo, err := st.WithDetails(&errdetails.RetryInfo{RetryDelay: durationpb.New(retry)}); err == nil {
		st = withInfo
	}
	return st.Err()
}

// logThrottled writes at most one line per caller per ThrottleLogInterval,
// counting the refusals it did not log. Caller holds l.mu.
func (l *Limiter) logThrottled(subject string, b *bucket, now time.Time) {
	if !b.lastLogged.IsZero() && now.Sub(b.lastLogged) < ThrottleLogInterval {
		b.suppressed++
		return
	}
	l.logf("[guardrail-rate] %s: throttled subject %q (%d more refusal(s) since the last line for this caller)",
		l.name, subject, b.suppressed)
	b.lastLogged = now
	b.suppressed = 0
}

// sweep drops buckets idle for at least idleTTL, at most once per idleTTL.
// Caller holds l.mu.
func (l *Limiter) sweep(now time.Time) {
	if now.Sub(l.lastSweep) < l.idleTTL {
		return
	}
	for s, b := range l.buckets {
		if now.Sub(b.lastSeen) >= l.idleTTL {
			delete(l.buckets, s)
		}
	}
	l.lastSweep = now
}

func (l *Limiter) bucketCount() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
