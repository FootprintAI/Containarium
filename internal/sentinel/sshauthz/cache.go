// Package sshauthz implements the sentinel's audit-only live SSH check.
package sshauthz

import (
	"sync"
	"time"
)

// CacheKey isolates positives by backend, login and offered credential.
type CacheKey struct{ Backend, Login, Fingerprint string }

type positive struct {
	UserID           string
	checked, expires time.Time
}

// Cache retains expired positives for a bounded outage grace window. A grace
// read never refreshes checked: an outage cannot extend itself indefinitely.
type Cache struct {
	mu       sync.Mutex
	entries  map[CacheKey]positive
	now      func() time.Time
	grace    time.Duration
	capacity int
}

func NewCache(grace time.Duration, capacity int, now func() time.Time) *Cache {
	if now == nil {
		now = time.Now
	}
	if capacity <= 0 {
		capacity = 10000
	}
	return &Cache{entries: make(map[CacheKey]positive), now: now, grace: grace, capacity: capacity}
}

func (c *Cache) prune(now time.Time) {
	for k, v := range c.entries {
		if !now.Before(v.expires) && !now.Before(v.checked.Add(c.grace)) {
			delete(c.entries, k)
		}
	}
}

// Get returns a fresh positive, or an expired positive only for outage reads.
func (c *Cache) Get(k CacheKey, outage bool) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	c.prune(now)
	v, ok := c.entries[k]
	if !ok {
		return "", false
	}
	if now.Before(v.expires) || (outage && now.Before(v.checked.Add(c.grace))) {
		return v.UserID, true
	}
	return "", false
}

func (c *Cache) Put(k CacheKey, userID string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	c.prune(now)
	if _, exists := c.entries[k]; !exists && len(c.entries) >= c.capacity {
		var oldest CacheKey
		var checked time.Time
		for key, v := range c.entries {
			if checked.IsZero() || v.checked.Before(checked) {
				oldest, checked = key, v.checked
			}
		}
		delete(c.entries, oldest)
	}
	c.entries[k] = positive{UserID: userID, checked: now, expires: now.Add(ttl)}
}

// Delete invalidates a previous positive on an authoritative denial.
func (c *Cache) Delete(k CacheKey) { c.mu.Lock(); defer c.mu.Unlock(); delete(c.entries, k) }
