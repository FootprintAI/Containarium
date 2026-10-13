package sshauthz

import (
	"sync"
	"time"
)

// cacheKey identifies a unique (backend, login, fingerprint) triple.
// Per-backend isolation means a key registered on one backend does not
// grant cached access on a different one.
type cacheKey struct {
	backendURL  string
	login       string
	fingerprint string
}

// cacheEntry holds a positive Authorize result together with its expiry.
// Only ALLOW results are cached; DENY and APPROVAL_PENDING are never stored.
type cacheEntry struct {
	userID    string
	expiresAt time.Time
}

// Cache is a thread-safe positive-results cache keyed on
// (backendURL, login, fingerprint). The injectable clock lets tests fix
// time without sleeping. Only ALLOW results are stored; callers must not
// call Put for DENY or APPROVAL_PENDING decisions.
type Cache struct {
	now  func() time.Time
	mu   sync.Mutex
	data map[cacheKey]cacheEntry
}

// NewCache returns an empty Cache. now may be nil (→ time.Now).
func NewCache(now func() time.Time) *Cache {
	if now == nil {
		now = time.Now
	}
	return &Cache{now: now, data: make(map[cacheKey]cacheEntry)}
}

// Get looks up (backendURL, login, fingerprint) and returns the cached
// userID and expiry. ok is true only when an entry exists AND has not yet
// expired at the time of the call.
func (c *Cache) Get(backendURL, login, fingerprint string) (userID string, expiresAt time.Time, ok bool) {
	k := cacheKey{backendURL, login, fingerprint}
	c.mu.Lock()
	e, found := c.data[k]
	c.mu.Unlock()
	if !found {
		return "", time.Time{}, false
	}
	if c.now().After(e.expiresAt) {
		// Expired entry — lazily evict.
		c.mu.Lock()
		// Re-check under lock: another goroutine may have refreshed it.
		if cur, ok2 := c.data[k]; ok2 && c.now().After(cur.expiresAt) {
			delete(c.data, k)
		}
		c.mu.Unlock()
		return "", time.Time{}, false
	}
	return e.userID, e.expiresAt, true
}

// Put stores a positive result for (backendURL, login, fingerprint) with a
// fixed expiry time. A zero ttl is a no-op (the caller should not cache).
func (c *Cache) Put(backendURL, login, fingerprint, userID string, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	k := cacheKey{backendURL, login, fingerprint}
	e := cacheEntry{userID: userID, expiresAt: c.now().Add(ttl)}
	c.mu.Lock()
	c.data[k] = e
	c.mu.Unlock()
}

// GraceGet returns the most-recent cached entry for (backendURL, login,
// fingerprint) regardless of whether it has expired, provided it expired
// within the grace window. This is used when the upstream is unavailable:
// a recently-expired positive is honoured rather than hard-denying a user
// whose key was valid moments ago.
//
// ok is true only when an entry exists AND its expiry is within the grace
// window of now (i.e. it expired at most `grace` ago).
func (c *Cache) GraceGet(backendURL, login, fingerprint string, grace time.Duration) (userID string, ok bool) {
	k := cacheKey{backendURL, login, fingerprint}
	c.mu.Lock()
	e, found := c.data[k]
	c.mu.Unlock()
	if !found {
		return "", false
	}
	// Within grace window: either still live OR expired within the grace duration.
	if c.now().Sub(e.expiresAt) <= grace {
		return e.userID, true
	}
	return "", false
}
