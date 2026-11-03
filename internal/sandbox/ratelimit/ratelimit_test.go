package ratelimit

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

var errBoom = errors.New("boom")

func TestDisabled_AlwaysAllows(t *testing.T) {
	l := Disabled()
	for i := 0; i < 100; i++ {
		if !l.Allow("alice") {
			t.Fatalf("Disabled limiter refused call %d, want always allowed", i)
		}
	}
}

func TestPoisoned_AlwaysDenies(t *testing.T) {
	l := Poisoned(errBoom)
	if l.Allow("alice") {
		t.Fatal("Poisoned limiter allowed a call, want always denied")
	}
	if l.Err() == nil {
		t.Fatal("Err() = nil on a Poisoned limiter, want the configuration error")
	}
}

func TestNew_AllowsUpToBurstThenDenies(t *testing.T) {
	// A slow rate (well under 1/sec) with burst=3 means the 4th call in
	// the same instant must be denied — the token bucket has nothing
	// left and refill is negligible over a test's execution time.
	l := New(0.001, 3)

	for i := 0; i < 3; i++ {
		if !l.Allow("alice") {
			t.Fatalf("call %d within burst was denied, want allowed", i)
		}
	}
	if l.Allow("alice") {
		t.Error("4th call beyond burst was allowed, want denied")
	}
}

func TestNew_PerSubjectBucketsAreIndependent(t *testing.T) {
	l := New(0.001, 1)

	if !l.Allow("alice") {
		t.Fatal("alice's first call was denied, want allowed")
	}
	if l.Allow("alice") {
		t.Error("alice's second call (over her own burst of 1) was allowed, want denied")
	}
	// bob must not be affected by alice's exhausted bucket — a shared
	// bucket keyed on nothing (or the wrong key) would deny this too.
	if !l.Allow("bob") {
		t.Error("bob's first call was denied by alice's rate limit — buckets are not independent per subject")
	}
}

func TestNewFromEnv_BothEmptyIsDisabled(t *testing.T) {
	l := NewFromEnv("", "")
	if l.Err() != nil {
		t.Fatalf("Err() = %v, want nil (both empty = disabled, not an error)", l.Err())
	}
	if !l.Allow("alice") {
		t.Error("NewFromEnv(\"\", \"\") denied a call, want disabled (always allow)")
	}
}

func TestNewFromEnv_InvalidRateIsPoisoned(t *testing.T) {
	for _, rate := range []string{"not-a-number", "0", "-5"} {
		l := NewFromEnv(rate, "")
		if l.Err() == nil {
			t.Errorf("NewFromEnv(%q, \"\").Err() = nil, want an error (invalid/non-positive rate)", rate)
		}
		if l.Allow("alice") {
			t.Errorf("NewFromEnv(%q, \"\") allowed a call, want denied (poisoned)", rate)
		}
	}
}

func TestNewFromEnv_InvalidBurstIsPoisoned(t *testing.T) {
	l := NewFromEnv("60", "not-a-number")
	if l.Err() == nil {
		t.Fatal("NewFromEnv(\"60\", \"not-a-number\").Err() = nil, want an error (invalid burst)")
	}
}

func TestNewFromEnv_ValidRateEnablesEnforcement(t *testing.T) {
	// 60/minute = 1/second; burst defaults to the rate (60) since burst
	// is left empty. Well within burst, so this must be allowed — this
	// is the "operator actually configured a working limit" happy path.
	l := NewFromEnv("60", "")
	if l.Err() != nil {
		t.Fatalf("Err() = %v, want nil", l.Err())
	}
	if !l.Allow("alice") {
		t.Error("a call within a freshly-configured limiter's burst was denied")
	}
}

// synctest advances time.Now and rate.Limiter's clock together without real
// sleeps, so these tests exercise the public Allow path unchanged on main.
func TestNew_EvictsIdleBuckets(t *testing.T) {
	for _, tc := range []struct {
		name   string
		rate   float64
		burst  int
		keys   int
		window time.Duration
	}{
		{name: "small population", rate: 1, burst: 2, keys: 64, window: 2 * time.Second},
		{name: "many distinct keys", rate: 1, burst: 2, keys: 2048, window: 2 * time.Second},
		{name: "slow refill", rate: 0.001, burst: 3, keys: 64, window: 50 * time.Minute},
		{name: "fractional refill", rate: 3, burst: 2, keys: 64, window: 666666667 * time.Nanosecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				l := New(tc.rate, tc.burst)
				for i := 0; i < tc.keys; i++ {
					if !l.Allow(fmt.Sprintf("subject-%d", i)) {
						t.Fatalf("first call for subject %d was denied", i)
					}
				}
				if got := len(l.buckets); got != tc.keys {
					t.Fatalf("initial buckets = %d, want %d", got, tc.keys)
				}

				time.Sleep(tc.window - time.Nanosecond)
				if !l.Allow("probe") {
					t.Fatal("first call for probe was denied")
				}
				if got := len(l.buckets); got != tc.keys+1 {
					t.Fatalf("buckets before full refill = %d, want %d", got, tc.keys+1)
				}

				time.Sleep(time.Nanosecond)
				if !l.Allow("probe") {
					t.Fatal("second call within probe's burst was denied")
				}
				if got := len(l.buckets); got != 1 {
					t.Fatalf("buckets after full refill = %d, want 1 (only probe)", got)
				}
			})
		})
	}
}

func TestNew_EvictionPreservesLiveBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Burst 3 at 0.5/s takes six seconds to refill completely.
		l := New(0.5, 3)
		for i := 0; i < 3; i++ {
			if !l.Allow("active") {
				t.Fatalf("active call %d within burst was denied", i)
			}
		}
		if l.Allow("active") {
			t.Fatal("exhausted active bucket allowed a call")
		}
		for i := 0; i < 2048; i++ {
			l.Allow(fmt.Sprintf("idle-%d", i))
		}

		time.Sleep(3 * time.Second)
		if !l.Allow("active") {
			t.Fatal("active bucket did not refill")
		}
		time.Sleep(3 * time.Second)
		l.Allow("fresh")
		if got := len(l.buckets); got != 2 {
			t.Errorf("buckets after sweep = %d, want 2 (active and fresh)", got)
		}
		// The live bucket has two tokens, not a reset burst of three.
		for i := 0; i < 2; i++ {
			if !l.Allow("active") {
				t.Fatalf("active refill token %d was lost during eviction", i)
			}
		}
		if l.Allow("active") {
			t.Fatal("eviction reset the active bucket's budget")
		}
	})
}

func TestNew_DeniedCallsKeepBucketLive(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := New(0.25, 1)
		l.Allow("idle")
		l.Allow("active")
		active := l.buckets["active"]

		time.Sleep(3 * time.Second)
		if l.Allow("active") {
			t.Fatal("active bucket allowed a call before one token refilled")
		}
		time.Sleep(time.Second)
		l.Allow("fresh")
		if got := len(l.buckets); got != 2 {
			t.Errorf("buckets after sweep = %d, want 2 (active and fresh)", got)
		}
		if l.buckets["active"] != active {
			t.Fatal("bucket touched by a denied call was evicted")
		}
		if !l.Allow("active") || l.Allow("active") {
			t.Fatal("active bucket did not retain its one-token refill budget")
		}
	})
}

func TestNew_EvictionWithConcurrentAllows(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := New(1, 1)
		for i := 0; i < 2048; i++ {
			l.Allow(fmt.Sprintf("idle-%d", i))
		}
		time.Sleep(time.Second)

		const callers = 64
		var wg sync.WaitGroup
		for i := 0; i < callers; i++ {
			wg.Go(func() {
				subject := fmt.Sprintf("live-%d", i)
				if !l.Allow(subject) {
					t.Errorf("first call for %s was denied", subject)
				}
				if l.Allow(subject) {
					t.Errorf("second call for %s exceeded its burst", subject)
				}
			})
		}
		wg.Wait()
		if got := len(l.buckets); got != callers {
			t.Fatalf("buckets after concurrent calls = %d, want %d", got, callers)
		}
	})
}
