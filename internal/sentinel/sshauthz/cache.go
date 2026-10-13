// Package sshauthz contains the sentinel's SSH authorization support.
// The plugin and HTTP adapter must use the generated contract from #2516;
// this positive cache deliberately has no wire decision or reason types.
package sshauthz

import (
	"sync"
	"time"
)

const DefaultGrace = 5 * time.Minute

// CacheKey scopes an authorization to the exact routed backend and credential.
type CacheKey struct {
	Backend     string
	Login       string
	Fingerprint string
}

// Cache stores only successful authorizations. Denials must invalidate any
// previous positive so an outage cannot resurrect a revoked authorization.
type Cache interface {
	Fresh(CacheKey) (string, bool)
	Grace(CacheKey) (string, bool)
	Put(CacheKey, string, time.Duration)
	Invalidate(CacheKey)
}

type positive struct {
	userID       string
	authorizedAt time.Time
	expiresAt    time.Time
	sequence     uint64
}

// PositiveCache is bounded, concurrent and uses an injectable clock. Fresh
// entries use the server TTL. Expired positives remain available ONLY through
// Grace, which callers may use on transport errors/5xx, never on a live deny.
// Grace is measured from the last successful authorization, not TTL expiry;
// neither reads nor outage fallbacks extend that window.
type PositiveCache struct {
	mu       sync.Mutex
	entries  map[CacheKey]positive
	capacity int
	grace    time.Duration
	now      func() time.Time
	sequence uint64
}

var _ Cache = (*PositiveCache)(nil)

// NewPositiveCache creates a cache. A nonpositive capacity disables storage;
// a nonpositive grace disables outage fallback. A nil clock uses time.Now.
func NewPositiveCache(capacity int, grace time.Duration, now func() time.Time) *PositiveCache {
	if now == nil {
		now = time.Now
	}
	return &PositiveCache{entries: make(map[CacheKey]positive), capacity: capacity, grace: grace, now: now}
}

func (c *PositiveCache) lookup(key CacheKey, grace bool) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.entries[key]
	if !ok {
		return "", false
	}
	now := c.now()
	// A backward clock jump must not lengthen a positive authorization.
	if now.Before(p.authorizedAt) {
		delete(c.entries, key)
		return "", false
	}
	fresh := now.Before(p.expiresAt)
	inGrace := c.grace > 0 && now.Sub(p.authorizedAt) < c.grace
	if !fresh && !inGrace {
		delete(c.entries, key)
	}
	if (grace && inGrace) || (!grace && fresh) {
		return p.userID, true
	}
	return "", false
}

func (c *PositiveCache) Fresh(key CacheKey) (string, bool) { return c.lookup(key, false) }
func (c *PositiveCache) Grace(key CacheKey) (string, bool) { return c.lookup(key, true) }
func (c *PositiveCache) Invalidate(key CacheKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

// Put records a new successful authorization. TTL <= 0 disables fresh hits
// but retains the success for transport-error grace. No default TTL is guessed
// here: the eventual protobuf adapter owns server/default TTL interpretation.
func (c *PositiveCache) Put(key CacheKey, userID string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.capacity <= 0 {
		return
	}
	now := c.now()
	// Remove expired entries before evicting a still-useful success.
	for k, p := range c.entries {
		if now.Before(p.authorizedAt) || (!now.Before(p.expiresAt) && (c.grace <= 0 || now.Sub(p.authorizedAt) >= c.grace)) {
			delete(c.entries, k)
		}
	}
	if _, exists := c.entries[key]; !exists && len(c.entries) >= c.capacity {
		var oldest CacheKey
		var seq uint64
		first := true
		for k, p := range c.entries {
			if first || p.sequence < seq {
				oldest, seq, first = k, p.sequence, false
			}
		}
		delete(c.entries, oldest)
	}
	c.sequence++
	c.entries[key] = positive{userID: userID, authorizedAt: now, expiresAt: now.Add(ttl), sequence: c.sequence}
}
