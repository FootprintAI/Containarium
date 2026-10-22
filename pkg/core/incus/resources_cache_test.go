package incus

// #2325: Incus' /1.0/resources can hang on a saturated host, and the daemon read it with no deadline from the
// create path (CPU admission), GetSystemInfo and ListBackends. The cache must (1) never block a caller for more than
// its wait budget, (2) keep serving the last good value, notably the hardware-static CPU count, through an outage,
// (3) share one in-flight read, and (4) not retry on every call after a failure.

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type resClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *resClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *resClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func testResCache(fetch func() (*SystemResources, error)) (*resourcesCache, *resClock) {
	clk := &resClock{t: time.Unix(1_700_000_000, 0)}
	return newResourcesCache(fetch, resourcesCacheConfig{
		Fresh: 10 * time.Second, Wait: 60 * time.Millisecond, Backoff: 20 * time.Second, Now: clk.now,
	}), clk
}

func res(cpus int32, used int64) *SystemResources {
	return &SystemResources{TotalCPUs: cpus, TotalMemoryBytes: 64 << 30, UsedMemoryBytes: used, GPUs: []GPUInfo{{Vendor: "x"}}}
}

func TestResourcesCache_FreshValueIsServedWithoutRefetch(t *testing.T) {
	var calls atomic.Int32
	rc, _ := testResCache(func() (*SystemResources, error) { calls.Add(1); return res(8, 1), nil })
	for i := 0; i < 5; i++ {
		got, err := rc.get()
		if err != nil || got.TotalCPUs != 8 {
			t.Fatalf("call %d: %v %+v", i, err, got)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("fetched %d times inside the fresh window, want 1", calls.Load())
	}
}

func TestResourcesCache_RefetchesAfterFreshWindow(t *testing.T) {
	var calls atomic.Int32
	rc, clk := testResCache(func() (*SystemResources, error) { return res(8, int64(calls.Add(1))), nil })
	_, _ = rc.get()
	clk.advance(11 * time.Second)
	got, _ := rc.get()
	if calls.Load() != 2 || got.UsedMemoryBytes != 2 {
		t.Fatalf("calls=%d used=%d; want a refetch after the fresh window", calls.Load(), got.UsedMemoryBytes)
	}
}

func TestResourcesCache_ConcurrentCallersShareOneFetch(t *testing.T) {
	var calls atomic.Int32
	gate := make(chan struct{})
	rc, _ := testResCache(func() (*SystemResources, error) { calls.Add(1); <-gate; return res(8, 1), nil })
	rc.cfg.Wait = 2 * time.Second
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got, err := rc.get(); err != nil || got.TotalCPUs != 8 {
				t.Errorf("caller saw %v %+v", err, got)
			}
		}()
	}
	waitFor(t, func() bool { return calls.Load() >= 1 })
	time.Sleep(30 * time.Millisecond)
	close(gate)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("fetched %d times for 20 concurrent callers, want 1", calls.Load())
	}
}

// The case from the incident: Incus never answers and nothing is cached yet.
func TestResourcesCache_HungFirstFetch_ErrorsWithinWait_ThenBacksOff(t *testing.T) {
	var calls atomic.Int32
	release := make(chan struct{})
	defer close(release)
	rc, _ := testResCache(func() (*SystemResources, error) { calls.Add(1); <-release; return res(8, 1), nil })

	start := time.Now()
	if _, err := rc.get(); err == nil {
		t.Fatal("a hung read with nothing cached must return an error")
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("get() blocked %v; it must return within about its wait budget", took)
	}
	start = time.Now()
	for i := 0; i < 10; i++ {
		if _, err := rc.get(); err == nil {
			t.Fatal("still no value: must error")
		}
	}
	if took := time.Since(start); took > 500*time.Millisecond {
		t.Fatalf("calls inside the back-off window took %v; they must return immediately", took)
	}
	if calls.Load() != 1 {
		t.Fatalf("fetch started %d times; a hung Incus must not accumulate reads", calls.Load())
	}
}

// Hardware-static values must survive an outage: this is what keeps every create off the hardware scan.
func TestResourcesCache_StaticCpuCountSurvivesAnOutage(t *testing.T) {
	var hang atomic.Bool
	release := make(chan struct{})
	defer close(release)
	rc, clk := testResCache(func() (*SystemResources, error) {
		if hang.Load() {
			<-release
		}
		return res(8, 1), nil
	})
	if got, err := rc.get(); err != nil || got.TotalCPUs != 8 {
		t.Fatalf("prime: %v %+v", err, got)
	}
	hang.Store(true)
	for i := 0; i < 5; i++ {
		clk.advance(30 * time.Second) // past fresh AND past back-off, so every call tries to refresh
		got, err := rc.get()
		if err != nil || got.TotalCPUs != 8 {
			t.Fatalf("round %d during the outage: err=%v got=%+v; the cached CPU count must be served", i, err, got)
		}
	}
}

func TestResourcesCache_FailedRefresh_ServesStale_ThenRetriesAfterBackoff(t *testing.T) {
	var fail atomic.Bool
	var calls atomic.Int32
	rc, clk := testResCache(func() (*SystemResources, error) {
		calls.Add(1)
		if fail.Load() {
			return nil, errors.New("incus: boom")
		}
		return res(8, int64(calls.Load())), nil
	})
	_, _ = rc.get()
	fail.Store(true)
	clk.advance(11 * time.Second)
	got, err := rc.get()
	if err != nil || got.TotalCPUs != 8 {
		t.Fatalf("a failed refresh with a cached value must serve it: %v %+v", err, got)
	}
	before := calls.Load()
	for i := 0; i < 5; i++ {
		_, _ = rc.get()
	}
	if calls.Load() != before {
		t.Fatalf("retried %d times inside the back-off window", calls.Load()-before)
	}
	fail.Store(false)
	clk.advance(21 * time.Second)
	got, _ = rc.get()
	if got.UsedMemoryBytes != int64(calls.Load()) || calls.Load() != before+1 {
		t.Fatalf("after the back-off the cache must refetch once and recover: calls=%d used=%d", calls.Load(), got.UsedMemoryBytes)
	}
}

// A read that outlives its waiters still lands: the next call sees the fresh value.
func TestResourcesCache_LateSuccessAfterTimeoutUpdatesTheCache(t *testing.T) {
	release := make(chan struct{})
	rc, _ := testResCache(func() (*SystemResources, error) { <-release; return res(16, 7), nil })
	if _, err := rc.get(); err == nil {
		t.Fatal("first get must time out")
	}
	close(release) // Incus finally answers
	waitFor(t, func() bool { rc.mu.Lock(); defer rc.mu.Unlock(); return rc.val != nil })
	got, err := rc.get()
	if err != nil || got.TotalCPUs != 16 {
		t.Fatalf("after the late answer: %v %+v", err, got)
	}
}

func TestResourcesCache_ReturnedValueIsACopy(t *testing.T) {
	rc, _ := testResCache(func() (*SystemResources, error) { return res(8, 1), nil })
	a, _ := rc.get()
	a.TotalCPUs = 999
	a.GPUs[0].Vendor = "mutated"
	b, _ := rc.get()
	if b.TotalCPUs != 8 || b.GPUs[0].Vendor != "x" {
		t.Fatalf("a caller's mutation leaked into the cache: %+v", b)
	}
}

func TestResourcesCacheFor_OnePerSocketPath(t *testing.T) {
	a1, a2, b := resourcesCacheFor("/tmp/a.sock"), resourcesCacheFor("/tmp/a.sock"), resourcesCacheFor("/tmp/b.sock")
	if a1 != a2 {
		t.Error("the same socket must share one cache (that is what makes the single flight work across callers)")
	}
	if a1 == b {
		t.Error("different sockets must not share a cache")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("condition not reached within 2s")
}
