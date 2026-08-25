package incus

import (
	"sort"
	"sync/atomic"
	"testing"
)

// TestFetchAllConcurrently_SkipsNotOk is the regression test for
// ListContainers's "skip containers we can't get details for" behavior
// (#1532's refactor from a sequential loop to a bounded worker pool must not
// change what gets returned, only how fast).
func TestFetchAllConcurrently_SkipsNotOk(t *testing.T) {
	names := []string{"a", "b", "c", "d", "e"}
	skip := map[string]bool{"b": true, "d": true}

	got := fetchAllConcurrently(names, 4, func(name string) (string, bool) {
		if skip[name] {
			return "", false
		}
		return name, true
	})

	sort.Strings(got)
	want := []string{"a", "c", "e"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

// TestFetchAllConcurrently_RespectsConcurrencyLimit is the regression test
// for #1532 itself: ListContainers used to make every GetInstance +
// GetInstanceState round-trip one after another, which made `containarium
// list` exceed its client deadline past ~180 containers on one host. This
// asserts the fan-out actually bounds in-flight work rather than firing
// everything at once (which would just move the same serialization problem
// onto Incus's own request queue).
func TestFetchAllConcurrently_RespectsConcurrencyLimit(t *testing.T) {
	const limit = 3
	names := make([]string, 50)
	for i := range names {
		names[i] = "x"
	}

	var inFlight, maxObserved int64
	release := make(chan struct{})
	go func() {
		// Let the pool actually saturate to `limit` before releasing —
		// otherwise a fast test run could finish before concurrency ever
		// peaks, making the assertion vacuously true.
		for atomic.LoadInt64(&inFlight) < limit {
		}
		close(release)
	}()

	fetchAllConcurrently(names, limit, func(string) (struct{}, bool) {
		n := atomic.AddInt64(&inFlight, 1)
		for {
			old := atomic.LoadInt64(&maxObserved)
			if n <= old || atomic.CompareAndSwapInt64(&maxObserved, old, n) {
				break
			}
		}
		<-release
		atomic.AddInt64(&inFlight, -1)
		return struct{}{}, true
	})

	if maxObserved > limit {
		t.Fatalf("max concurrent in-flight = %d, want <= %d", maxObserved, limit)
	}
	if maxObserved < limit {
		t.Fatalf("max concurrent in-flight = %d, want == %d (pool never saturated — test is not exercising the limit)", maxObserved, limit)
	}
}
