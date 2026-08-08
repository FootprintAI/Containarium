package zfskey

import (
	"sync"
	"time"
)

// DefaultTTL is how long an unused key stays cached. Short enough that a
// stopped tenant's key does not linger in daemon memory indefinitely,
// long enough that a stop/start cycle does not hit the KMS.
const DefaultTTL = 15 * time.Minute

// Cache holds resolved keys in process memory for the daemon's lifetime.
//
// Deliberately memory-only, per design §4: operators expect that wiping
// the daemon wipes the keys, and a disk cache would break that. Nothing
// in this type writes to disk. On daemon restart the cache starts empty
// and the next pre-start hook re-fetches from the KeyProvider.
//
// The TTL is on *inactivity*: every hit extends the entry's life, so a
// busy tenant's key stays resident while an idle one ages out.
type Cache struct {
	mu      sync.Mutex
	entries map[string]*cacheEntry
	ttl     time.Duration
	now     func() time.Time
}

type cacheEntry struct {
	key      Key
	lastUsed time.Time
}

// NewCache constructs an empty cache. A non-positive ttl uses DefaultTTL.
func NewCache(ttl time.Duration) *Cache {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Cache{
		entries: make(map[string]*cacheEntry),
		ttl:     ttl,
		now:     time.Now,
	}
}

// Get returns the cached key for a tenant, refreshing its inactivity
// deadline. An expired entry is dropped and reported as a miss.
func (c *Cache) Get(tenantID string) (Key, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.entries[tenantID]
	if !ok {
		return Key{}, false
	}
	now := c.now()
	if now.Sub(e.lastUsed) > c.ttl {
		delete(c.entries, tenantID)
		return Key{}, false
	}
	e.lastUsed = now
	return e.key, true
}

// Put stores a key, starting its inactivity clock.
func (c *Cache) Put(tenantID string, k Key) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[tenantID] = &cacheEntry{key: k, lastUsed: c.now()}
}

// Evict drops a tenant's key immediately — used by the post-stop hook
// once the last container under an encryptionroot goes away.
func (c *Cache) Evict(tenantID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, tenantID)
}

// Len reports how many unexpired keys are resident. For tests and for a
// daemon status endpoint; it reveals a count, never material.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweepLocked()
	return len(c.entries)
}

// sweepLocked drops expired entries. Called from Len so an idle daemon's
// key count reflects reality rather than counting entries that a Get
// would refuse. Caller must hold c.mu.
func (c *Cache) sweepLocked() {
	now := c.now()
	for id, e := range c.entries {
		if now.Sub(e.lastUsed) > c.ttl {
			delete(c.entries, id)
		}
	}
}
