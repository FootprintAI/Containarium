package incus

import (
	"errors"
	"sync"
	"time"
)

// Bounded, cached system-resource reads (#2325).
//
// Incus' hardware-discovery call (GET /1.0/resources, behind GetServerResources) can stop answering on a heavily
// loaded host. The daemon used to read it through a client with no timeout from the create path (CPU admission),
// GetSystemInfo, ListBackends and the metrics collectors, so every one of them blocked for as long as Incus did: a
// hung scan stopped container creation and the fleet view, silently.
//
// The values it feeds are mostly hardware: the logical CPU count, CPU model, total memory, total disk and GPUs do
// not change while the daemon runs. So the read is cached and bounded:
//
//   - one shared in-flight read, so concurrent callers cost one request and a hung Incus cannot accumulate requests;
//   - the last good value is served as is for a short freshness window;
//   - when a refresh fails or times out, the last good value keeps being served (stale), so the hardware-static
//     fields, notably the CPU count the admission gate needs, stay available through an outage;
//   - after a failure or timeout, callers do not retry for a short back-off, so a hung Incus costs one caller per
//     back-off window the wait budget instead of every create;
//   - if there has never been a successful read, the caller gets an error within the wait budget.
//
// The load averages come from /proc/loadavg, not from Incus, so they are overlaid fresh on every return.
const (
	// resourcesRequestTimeout bounds each HTTP request of one read (resources, pool list, each pool's usage).
	resourcesRequestTimeout = 8 * time.Second
	// resourcesFreshFor is how long a successful read is served without refetching.
	resourcesFreshFor = 10 * time.Second
	// resourcesWait is the longest a caller waits for an in-flight read.
	resourcesWait = 8 * time.Second
	// resourcesBackoff is how long after a failed or timed-out read callers are served the cached value (or an
	// immediate error) instead of waiting on Incus again.
	resourcesBackoff = 20 * time.Second
)

// ErrResourcesUnavailable is returned when Incus did not answer the resources read within the wait budget and no
// earlier value is cached.
var ErrResourcesUnavailable = errors.New("incus: system resources unavailable (read timed out or failed)")

type resourcesCacheConfig struct {
	Fresh, Wait, Backoff time.Duration
	Now                  func() time.Time
}

type resFlight struct {
	done chan struct{}
	val  *SystemResources
	err  error
}

// resourcesCache is the single-flight, last-good, back-off cache described above. Safe for concurrent use.
type resourcesCache struct {
	cfg   resourcesCacheConfig
	fetch func() (*SystemResources, error)

	mu       sync.Mutex
	val      *SystemResources // last good read
	at       time.Time
	failedAt time.Time // zero when the last attempt succeeded
	lastErr  error
	flight   *resFlight
}

func newResourcesCache(fetch func() (*SystemResources, error), cfg resourcesCacheConfig) *resourcesCache {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &resourcesCache{cfg: cfg, fetch: fetch}
}

func cloneResources(v *SystemResources) *SystemResources {
	if v == nil {
		return nil
	}
	c := *v
	c.GPUs = append([]GPUInfo(nil), v.GPUs...)
	return &c
}

// withFreshLoad copies v and overlays the current load averages (a local /proc read, never an Incus call).
func withFreshLoad(v *SystemResources) *SystemResources {
	c := cloneResources(v)
	if l1, l5, l15, err := getCPULoadAvg(); err == nil {
		c.CPULoad1Min, c.CPULoad5Min, c.CPULoad15Min = l1, l5, l15
	}
	return c
}

// get returns the system resources, bounded: it never blocks longer than cfg.Wait.
func (rc *resourcesCache) get() (*SystemResources, error) {
	rc.mu.Lock()
	now := rc.cfg.Now()
	if rc.val != nil && now.Sub(rc.at) < rc.cfg.Fresh {
		v := rc.val
		rc.mu.Unlock()
		return withFreshLoad(v), nil
	}
	if !rc.failedAt.IsZero() && now.Sub(rc.failedAt) < rc.cfg.Backoff {
		v, err := rc.val, rc.lastErr
		rc.mu.Unlock()
		return staleOrErr(v, err)
	}
	f := rc.flight
	if f == nil {
		f = &resFlight{done: make(chan struct{})}
		rc.flight = f
		go rc.run(f)
	}
	rc.mu.Unlock()

	timer := time.NewTimer(rc.cfg.Wait)
	defer timer.Stop()
	select {
	case <-f.done:
		if f.err == nil {
			return withFreshLoad(f.val), nil
		}
	case <-timer.C:
		// The read is still running (a hung Incus). Record the miss so the next callers are not each made to wait,
		// and let the read finish in the background: its result still lands in the cache when it ends.
		rc.mu.Lock()
		if rc.failedAt.IsZero() || rc.cfg.Now().Sub(rc.failedAt) >= rc.cfg.Backoff {
			rc.failedAt, rc.lastErr = rc.cfg.Now(), ErrResourcesUnavailable
		}
		rc.mu.Unlock()
	}
	rc.mu.Lock()
	v, err := rc.val, rc.lastErr
	rc.mu.Unlock()
	return staleOrErr(v, err)
}

func staleOrErr(v *SystemResources, err error) (*SystemResources, error) {
	if v != nil {
		return withFreshLoad(v), nil
	}
	if err == nil {
		err = ErrResourcesUnavailable
	}
	return nil, err
}

func (rc *resourcesCache) run(f *resFlight) {
	val, err := rc.fetch()
	rc.mu.Lock()
	if err == nil {
		rc.val, rc.at, rc.failedAt, rc.lastErr = cloneResources(val), rc.cfg.Now(), time.Time{}, nil
	} else {
		rc.failedAt, rc.lastErr = rc.cfg.Now(), err
	}
	rc.flight = nil
	f.val, f.err = rc.val, err
	rc.mu.Unlock()
	close(f.done)
}

var resourcesCaches sync.Map // socket path -> *resourcesCache

// resourcesCacheFor returns the process-wide cache for a socket, creating it on first use. The fetch uses its own
// short-timeout client, so a hung Incus ends the HTTP request instead of leaking it.
func resourcesCacheFor(socketPath string) *resourcesCache {
	if c, ok := resourcesCaches.Load(socketPath); ok {
		return c.(*resourcesCache)
	}
	rc := newResourcesCache(func() (*SystemResources, error) {
		bounded, err := NewWithSocketAndTimeout(socketPath, resourcesRequestTimeout)
		if err != nil {
			return nil, err
		}
		return bounded.fetchSystemResources()
	}, resourcesCacheConfig{Fresh: resourcesFreshFor, Wait: resourcesWait, Backoff: resourcesBackoff})
	actual, _ := resourcesCaches.LoadOrStore(socketPath, rc)
	return actual.(*resourcesCache)
}
