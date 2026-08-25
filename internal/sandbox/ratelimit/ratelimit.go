// Package ratelimit implements the per-tenant spawn rate limiter for
// SandboxServer.SpawnSandbox (#1488 Phase 4: "per-tenant rate limit").
//
// A single subject spawning far faster than any legitimate agent inner
// loop would — a bug, a retry storm, or an abusive script — should be
// throttled without touching any other tenant's spawn budget or the
// shared warm pool. This package is pure in-memory Go, no live host or
// external store needed, same scoping as this codebase's other
// internal/sandbox siblings (ipam, pool, dialer).
package ratelimit

import (
	"fmt"
	"strconv"
	"sync"

	"golang.org/x/time/rate"
)

// Limiter is a per-tenant token-bucket rate limiter. The zero value is
// NOT valid — always construct via New, Disabled, Poisoned, or
// NewFromEnv, all of which return a ready-to-use *Limiter so a caller
// never needs its own nil check before calling Allow.
type Limiter struct {
	ratePerSecond float64
	burst         int

	// configErr poisons the limiter: once set, every Allow call returns
	// false regardless of ratePerSecond/burst — a malformed operator
	// config must refuse spawns until fixed, not silently become
	// "unlimited". Same fail-closed posture this codebase already uses
	// for clusterCaps.configErr (internal/server/cluster_caps.go).
	configErr error

	mu      sync.Mutex
	buckets map[string]*rate.Limiter
}

// New builds an enabled Limiter. ratePerSecond and burst must both be
// positive — use Disabled for "no limiting", not New(0, 0).
func New(ratePerSecond float64, burst int) *Limiter {
	return &Limiter{ratePerSecond: ratePerSecond, burst: burst, buckets: make(map[string]*rate.Limiter)}
}

// Disabled returns a Limiter whose Allow always returns true — the
// explicit "no rate limiting configured" value.
func Disabled() *Limiter {
	return &Limiter{}
}

// Poisoned returns a Limiter whose Allow always returns false, with err
// available via Err — the fail-closed value for a malformed operator
// config.
func Poisoned(err error) *Limiter {
	return &Limiter{configErr: err}
}

// NewFromEnv parses ratePerMinute/burst (both optional; both empty =
// Disabled) into a ready-to-use Limiter. A malformed non-empty value
// returns Poisoned plus the error rather than silently disabling
// enforcement — the operator asked for a limit; a typo must not remove
// it. burst defaults to the per-minute rate itself (rounded down, floor
// 1) when left empty, giving a caller a reasonable one-flag config
// (CONTAINARIUM_SANDBOX_SPAWN_RATE_PER_MINUTE alone).
func NewFromEnv(ratePerMinute, burst string) *Limiter {
	if ratePerMinute == "" && burst == "" {
		return Disabled()
	}
	rpm, err := strconv.ParseFloat(ratePerMinute, 64)
	if err != nil || rpm <= 0 {
		return Poisoned(fmt.Errorf("invalid sandbox spawn rate limit %q: must be a positive number of spawns per minute", ratePerMinute))
	}
	b := int(rpm)
	if b < 1 {
		b = 1
	}
	if burst != "" {
		bi, err := strconv.Atoi(burst)
		if err != nil || bi < 1 {
			return Poisoned(fmt.Errorf("invalid sandbox spawn burst %q: must be a positive integer", burst))
		}
		b = bi
	}
	return New(rpm/60.0, b)
}

// Allow reports whether subject may spawn right now, consuming one
// token from its bucket if so. Always true when Disabled, always false
// when Poisoned. Buckets are created lazily per subject and never
// evicted — bounded in practice by the operator's tenant population
// (subject comes from an authenticated token, not unauthenticated
// caller-controlled input), the same non-eviction tradeoff pool.Pool
// accepts for its own per-template maps.
func (l *Limiter) Allow(subject string) bool {
	if l.configErr != nil {
		return false
	}
	if l.ratePerSecond <= 0 {
		return true
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[subject]
	if !ok {
		b = rate.NewLimiter(rate.Limit(l.ratePerSecond), l.burst)
		l.buckets[subject] = b
	}
	return b.Allow()
}

// Err returns the configuration error for a Poisoned limiter, nil
// otherwise.
func (l *Limiter) Err() error {
	return l.configErr
}
