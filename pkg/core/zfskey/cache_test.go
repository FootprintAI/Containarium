package zfskey

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// newTestCache returns a cache on a controllable clock so TTL behaviour
// is tested by advancing time rather than by sleeping.
func newTestCache(ttl time.Duration) (*Cache, func(time.Duration)) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	c := NewCache(ttl)
	c.now = func() time.Time { return now }
	return c, func(d time.Duration) { now = now.Add(d) }
}

func TestCacheStoresAndReturnsKeys(t *testing.T) {
	c, _ := newTestCache(time.Minute)
	k := Key{b: bytes.Repeat([]byte{7}, KeyLen)}

	if _, ok := c.Get("alice"); ok {
		t.Fatal("empty cache reported a hit")
	}

	c.Put("alice", k)
	got, ok := c.Get("alice")
	if !ok {
		t.Fatal("cached key not returned")
	}
	if !bytes.Equal(got.Bytes(), k.Bytes()) {
		t.Error("cache returned different material than it was given")
	}
	if c.Len() != 1 {
		t.Errorf("Len = %d, want 1", c.Len())
	}
}

// AC: the cache evicts on TTL.
func TestCacheExpiresOnTTL(t *testing.T) {
	c, advance := newTestCache(15 * time.Minute)
	c.Put("alice", Key{b: bytes.Repeat([]byte{7}, KeyLen)})

	advance(14 * time.Minute)
	if _, ok := c.Get("alice"); !ok {
		t.Error("key expired early")
	}

	// The hit above refreshed the deadline — inactivity TTL, per design §4.
	advance(14 * time.Minute)
	if _, ok := c.Get("alice"); !ok {
		t.Error("a used key expired despite recent activity")
	}

	advance(16 * time.Minute)
	if _, ok := c.Get("alice"); ok {
		t.Error("key survived past its inactivity TTL")
	}
	if c.Len() != 0 {
		t.Errorf("Len = %d after expiry, want 0", c.Len())
	}
}

// The post-stop hook evicts explicitly once the last container under an
// encryptionroot goes away; it must not wait for the TTL.
func TestCacheEvictIsImmediate(t *testing.T) {
	c, _ := newTestCache(time.Hour)
	c.Put("alice", Key{b: bytes.Repeat([]byte{7}, KeyLen)})
	c.Put("bob", Key{b: bytes.Repeat([]byte{8}, KeyLen)})

	c.Evict("alice")

	if _, ok := c.Get("alice"); ok {
		t.Error("evicted key still cached")
	}
	if _, ok := c.Get("bob"); !ok {
		t.Error("Evict removed the wrong tenant's key")
	}
	if c.Len() != 1 {
		t.Errorf("Len = %d, want 1", c.Len())
	}

	// Evicting an absent tenant is a no-op, not a panic — the post-stop
	// hook runs on unencrypted containers too.
	c.Evict("nobody")
}

// AC: the cache is empty after a simulated daemon restart, and nothing it
// holds is ever written to disk.
func TestCacheIsMemoryOnlyAndEmptyAfterRestart(t *testing.T) {
	// A fresh process gets a fresh cache: that is the restart semantics.
	c, _ := newTestCache(time.Hour)
	c.Put("alice", Key{b: bytes.Repeat([]byte{7}, KeyLen)})
	if c.Len() != 1 {
		t.Fatalf("setup: Len = %d", c.Len())
	}

	restarted := NewCache(time.Hour)
	if restarted.Len() != 0 {
		t.Errorf("cache survived a restart with %d entries", restarted.Len())
	}
	if _, ok := restarted.Get("alice"); ok {
		t.Error("a restarted daemon still had the key — it must re-fetch from the KeyProvider")
	}

	// And prove the package wrote nothing while we exercised it: run the
	// whole cycle with the working directory watched.
	dir := t.TempDir()
	before := dirSnapshot(t, dir)
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	c2 := NewCache(time.Hour)
	c2.Put("alice", Key{b: bytes.Repeat([]byte{7}, KeyLen)})
	_, _ = c2.Get("alice")
	c2.Evict("alice")

	if after := dirSnapshot(t, dir); after != before {
		t.Errorf("cache touched the filesystem: %q -> %q", before, after)
	}
}

func dirSnapshot(t *testing.T, dir string) string {
	t.Helper()
	var out []string
	err := filepath.Walk(dir, func(path string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		out = append(out, path)
		return nil
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	return strings.Join(out, "\n")
}

// The daemon touches the cache from concurrent RPC handlers; the race
// detector should find nothing. Run with -race.
func TestCacheIsConcurrencySafe(t *testing.T) {
	c := NewCache(time.Hour)
	k := Key{b: bytes.Repeat([]byte{7}, KeyLen)}

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tenant := string(rune('a' + i%8))
			c.Put(tenant, k)
			_, _ = c.Get(tenant)
			if i%3 == 0 {
				c.Evict(tenant)
			}
			_ = c.Len()
		}(i)
	}
	wg.Wait()
}
