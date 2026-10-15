package guardrailrate

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeClock is the limiter's clock in every test: no test sleeps.
type fakeClock struct{ t time.Time }

func newFakeClock() *fakeClock               { return &fakeClock{t: time.Unix(1_700_000_000, 0)} }
func (c *fakeClock) Now() time.Time          { return c.t }
func (c *fakeClock) Advance(d time.Duration) { c.t = c.t.Add(d) }
func (c *fakeClock) opt() Option             { return WithClock(c.Now) }
func (r *logRecorder) opt() Option           { return WithLogf(r.logf) }
func (r *logRecorder) logf(f string, a ...any) {
	r.mu.Lock()
	r.lines = append(r.lines, fmt.Sprintf(f, a...))
	r.mu.Unlock()
}

type logRecorder struct {
	mu    sync.Mutex
	lines []string
}

func (r *logRecorder) count() int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.lines) }

// allowed calls Check n times for subject and returns how many passed.
func allowed(l *Limiter, subject string, n int) int {
	ok := 0
	for i := 0; i < n; i++ {
		if l.Check(subject) == nil {
			ok++
		}
	}
	return ok
}

func TestCheck_BurstThenThrottleThenRefill(t *testing.T) {
	clk := newFakeClock()
	l := New("gated deploy", Limit{PerMinute: 6, Burst: 3}, clk.opt(), WithLogf(func(string, ...any) {}))

	if got := allowed(l, "alice", 3); got != 3 {
		t.Fatalf("within burst: %d of 3 allowed", got)
	}
	err := l.Check("alice")
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("4th call = %v, want ResourceExhausted", err)
	}
	// 6/min refills one token every 10s.
	clk.Advance(9 * time.Second)
	if l.Check("alice") == nil {
		t.Fatal("allowed after 9s, want still throttled (one token per 10s)")
	}
	clk.Advance(time.Second)
	if err := l.Check("alice"); err != nil {
		t.Fatalf("after 10s: %v, want one token refilled", err)
	}
}

func TestCheck_RetryHint(t *testing.T) {
	clk := newFakeClock()
	l := New("gated deploy", Limit{PerMinute: 6, Burst: 1}, clk.opt(), WithLogf(func(string, ...any) {}))
	_ = l.Check("alice")
	clk.Advance(4 * time.Second)
	err := l.Check("alice")
	st, _ := status.FromError(err)
	if st.Code() != codes.ResourceExhausted {
		t.Fatalf("code = %v, want ResourceExhausted", st.Code())
	}
	var info *errdetails.RetryInfo
	for _, d := range st.Details() {
		if ri, ok := d.(*errdetails.RetryInfo); ok {
			info = ri
		}
	}
	if info == nil {
		t.Fatalf("no RetryInfo detail on %v", err)
	}
	if got := info.GetRetryDelay().AsDuration(); got != 6*time.Second {
		t.Errorf("RetryInfo delay = %v, want 6s (next token in 10s, 4s elapsed)", got)
	}
	if !strings.Contains(st.Message(), "retry in 6s") {
		t.Errorf("message %q does not carry the retry hint", st.Message())
	}
}

// Acceptance criterion 2: one subject's exhausted bucket never throttles
// another subject.
func TestCheck_PerSubjectBuckets(t *testing.T) {
	clk := newFakeClock()
	l := New("policy set", Limit{PerMinute: 10, Burst: 1}, clk.opt(), WithLogf(func(string, ...any) {}))
	if l.Check("alice") != nil {
		t.Fatal("alice's first call throttled")
	}
	if l.Check("alice") == nil {
		t.Fatal("alice's second call allowed, want throttled")
	}
	if err := l.Check("bob"); err != nil {
		t.Fatalf("bob throttled by alice's bucket: %v", err)
	}
}

// Acceptance criterion 5: 0 disables.
func TestCheck_ZeroRateDisables(t *testing.T) {
	for _, l := range []*Limiter{
		New("x", Limit{PerMinute: 0, Burst: 3}),
		New("x", Limit{}),
		nil,
	} {
		if got := allowed(l, "alice", 1000); got != 1000 {
			t.Errorf("disabled limiter allowed %d of 1000", got)
		}
	}
}

// Burst left at 0 defaults to the per-minute rate (the convention of
// internal/sandbox/ratelimit), floor 1.
func TestNew_BurstDefaultsToPerMinute(t *testing.T) {
	for _, tc := range []struct {
		perMinute float64
		want      int
	}{{10, 10}, {120, 120}, {0.5, 1}} {
		l := New("x", Limit{PerMinute: tc.perMinute}, newFakeClock().opt(), WithLogf(func(string, ...any) {}))
		if got := allowed(l, "alice", tc.want+5); got != tc.want {
			t.Errorf("PerMinute %v, no burst: %d allowed at once, want %d", tc.perMinute, got, tc.want)
		}
	}
}

// Acceptance criterion 4: a flood logs one line per interval per caller.
func TestCheck_ThrottleLogsOncePerIntervalPerCaller(t *testing.T) {
	clk := newFakeClock()
	rec := &logRecorder{}
	l := New("gated deploy", Limit{PerMinute: 0.001, Burst: 1}, clk.opt(), rec.opt())

	_ = l.Check("alice")
	_ = l.Check("bob")
	for i := 0; i < 50; i++ {
		_ = l.Check("alice")
		_ = l.Check("bob")
	}
	if got := rec.count(); got != 2 {
		t.Fatalf("50 throttled calls each from two callers logged %d lines, want 2 (one per caller): %q", got, rec.lines)
	}
	clk.Advance(ThrottleLogInterval - time.Second)
	_ = l.Check("alice")
	if got := rec.count(); got != 2 {
		t.Fatalf("logged again inside the interval: %q", rec.lines)
	}
	clk.Advance(time.Second)
	_ = l.Check("alice")
	if got := rec.count(); got != 3 {
		t.Fatalf("after one interval: %d lines, want 3: %q", got, rec.lines)
	}
	if last := rec.lines[2]; !strings.Contains(last, `"alice"`) || !strings.Contains(last, "gated deploy") {
		t.Errorf("throttle line %q should name the limit and the caller", last)
	}
}

// Idle buckets are dropped once they would have refilled completely, so
// the map is bounded by recently active callers.
func TestCheck_IdleBucketsAreCollected(t *testing.T) {
	clk := newFakeClock()
	l := New("policy get", Limit{PerMinute: 60, Burst: 2}, clk.opt(), WithLogf(func(string, ...any) {}))
	for i := 0; i < 100; i++ {
		_ = l.Check(fmt.Sprintf("subject-%d", i))
	}
	if got := l.bucketCount(); got != 100 {
		t.Fatalf("%d buckets, want 100", got)
	}
	// Burst 2 at 1/s refills completely in 2s.
	clk.Advance(2 * time.Second)
	_ = l.Check("fresh")
	if got := l.bucketCount(); got != 1 {
		t.Fatalf("%d buckets after every other caller idled past a full refill, want 1", got)
	}
}
