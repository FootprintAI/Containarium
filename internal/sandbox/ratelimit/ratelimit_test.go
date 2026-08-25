package ratelimit

import (
	"errors"
	"testing"
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
