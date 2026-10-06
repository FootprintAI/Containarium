package server

import (
	"context"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// Local backend liveness (#2317, builds on #920).
//
// Placement and ListBackends ask "may this daemon's own backend take new
// work?". The answer used to be one probe per call that listed EVERY instance
// and then asked Incus for its server info, under a fixed 3s budget, failing
// closed on a timeout. On a host running many instances under CPU pressure the
// instance list alone can outlast 3s, so a slow-but-alive incusd made the whole
// host unplaceable, and every create into the pool failed for as long as the
// load lasted. Each timed-out call also left its goroutine (and Incus
// connection) behind, because the probe client had no timeout.
//
// localHealth fixes the three parts of that:
//
//   - the probe is Incus' own server-info call only, so its cost does not grow
//     with the number of tenants;
//   - one probe runs at a time and concurrent callers share its result, so a
//     burst of placements on a loaded host adds one request, not N, and a wedged
//     incusd holds one goroutine, not one per attempt;
//   - a failed or slow sample does not flip the verdict while Incus has proved
//     itself alive within the grace window; only failures that persist past it
//     (or a host that has never answered) report unhealthy.
//
// It still fails closed: a daemon that really is wedged stops being placeable
// once the grace window has passed.
const (
	// defaultLocalHealthTimeout is how long a caller waits for the probe.
	defaultLocalHealthTimeout = 3 * time.Second
	// minLocalHealthTimeout / maxLocalHealthTimeout bound the operator override
	// (CONTAINARIUM_LOCAL_HEALTH_TIMEOUT) so a typo cannot disable the check or
	// stall every placement for minutes.
	minLocalHealthTimeout = 100 * time.Millisecond
	maxLocalHealthTimeout = 30 * time.Second
	// localHealthGrace is how long one successful probe keeps the verdict
	// healthy while later probes fail or run slow.
	localHealthGrace = 15 * time.Second
	// probeCeilingFactor lets a slow probe finish (and prove Incus alive)
	// after the caller gave up, bounded so the goroutine cannot live forever.
	probeCeilingFactor = 3
	// slowProbeFraction: a successful probe that used more than 1/N of the
	// budget is logged, so saturation is visible before it flips the verdict.
	slowProbeFraction = 4
	slowLogInterval   = 30 * time.Second
)

// localHealthTimeoutFromEnv reads CONTAINARIUM_LOCAL_HEALTH_TIMEOUT (a Go
// duration). Unset, unparsable, non-positive or below the floor values use the
// default; values above the ceiling are capped.
func localHealthTimeoutFromEnv() time.Duration {
	raw := strings.TrimSpace(os.Getenv("CONTAINARIUM_LOCAL_HEALTH_TIMEOUT"))
	if raw == "" {
		return defaultLocalHealthTimeout
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d < minLocalHealthTimeout {
		log.Printf("[health] ignoring CONTAINARIUM_LOCAL_HEALTH_TIMEOUT=%q (want a duration >= %v); using %v",
			raw, minLocalHealthTimeout, defaultLocalHealthTimeout)
		return defaultLocalHealthTimeout
	}
	if d > maxLocalHealthTimeout {
		log.Printf("[health] CONTAINARIUM_LOCAL_HEALTH_TIMEOUT=%v exceeds the maximum; capping at %v", d, maxLocalHealthTimeout)
		return maxLocalHealthTimeout
	}
	return d
}

type healthVerdict int

const (
	verdictUnknown healthVerdict = iota
	verdictHealthy
	verdictUnhealthy
)

type probeCall struct {
	done chan struct{}
	err  error
}

// localHealth is the debounced, single-flight liveness verdict for the local
// Incus backend. Safe for concurrent use.
type localHealth struct {
	// probe is one liveness check. It should return promptly; ctx carries the
	// probe's own ceiling.
	probe   func(ctx context.Context) error
	timeout time.Duration
	grace   time.Duration
	now     func() time.Time
	logf    func(format string, args ...any)

	mu          sync.Mutex
	inflight    *probeCall
	lastOK      time.Time
	verdict     healthVerdict
	lastSlowLog time.Time
}

func newLocalHealth(probe func(ctx context.Context) error, timeout, grace time.Duration) *localHealth {
	return &localHealth{probe: probe, timeout: timeout, grace: grace, now: time.Now, logf: log.Printf}
}

// Healthy reports whether the local backend may take new work. It returns
// within about h.timeout.
func (h *localHealth) Healthy() bool {
	call := h.join()
	timer := time.NewTimer(h.timeout)
	defer timer.Stop()

	var sampleErr error
	sampleOK, timedOut := false, false
	select {
	case <-call.done:
		sampleErr = call.err
		sampleOK = sampleErr == nil
	case <-timer.C:
		timedOut = true
	}
	return h.decide(sampleOK, timedOut, sampleErr)
}

// join returns the probe in flight, starting one if there is none.
func (h *localHealth) join() *probeCall {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.inflight != nil {
		return h.inflight
	}
	call := &probeCall{done: make(chan struct{})}
	h.inflight = call
	go h.run(call)
	return call
}

func (h *localHealth) run(call *probeCall) {
	ctx, cancel := context.WithTimeout(context.Background(), probeCeilingFactor*h.timeout)
	defer cancel()
	start := time.Now()
	err := h.probe(ctx)
	took := time.Since(start)

	h.mu.Lock()
	if err == nil {
		// Even a late answer (the caller may have given up already) proves
		// Incus is alive.
		h.lastOK = h.now()
		if took > h.timeout/slowProbeFraction && h.now().Sub(h.lastSlowLog) >= slowLogInterval {
			h.lastSlowLog = h.now()
			h.logf("[health] local backend probe slow: took %v of a %v budget (host is under pressure)", took.Round(time.Millisecond), h.timeout)
		}
	}
	call.err = err
	h.inflight = nil
	h.mu.Unlock()
	close(call.done)
}

// decide turns one sample into the published verdict and logs transitions.
func (h *localHealth) decide(sampleOK, timedOut bool, sampleErr error) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now()
	sinceOK := time.Duration(-1)
	if !h.lastOK.IsZero() {
		sinceOK = now.Sub(h.lastOK)
	}
	healthy := sampleOK || (sinceOK >= 0 && sinceOK <= h.grace)

	prev := h.verdict
	switch {
	case healthy:
		h.verdict = verdictHealthy
		if prev == verdictUnhealthy {
			h.logf("[health] local backend healthy again")
		}
	default:
		h.verdict = verdictUnhealthy
		if prev != verdictUnhealthy {
			reason := "no answer within " + h.timeout.String()
			if !timedOut && sampleErr != nil {
				reason = "probe failed: " + sampleErr.Error()
			}
			last := "never answered"
			if sinceOK >= 0 {
				last = "last answered " + sinceOK.Round(time.Second).String() + " ago"
			}
			h.logf("[health] local backend unhealthy: %s; %s (grace %v)", reason, last, h.grace)
		}
	}
	return healthy
}

// incusLivenessProbe is the production probe: Incus' own server-info call,
// through a client with a call timeout so a wedged daemon cannot hold the
// goroutine forever. Deliberately does NOT list instances: its cost must not
// grow with the number of tenants on the host.
func incusLivenessProbe(callTimeout time.Duration) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		client, err := incus.NewWithSocketAndTimeout(incus.DefaultSocketPath, callTimeout)
		if err != nil {
			return err
		}
		_, err = client.GetServerInfo()
		return err
	}
}
