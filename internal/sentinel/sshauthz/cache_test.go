package sshauthz

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

var testKey = CacheKey{Backend: "backend-a", Login: "alice", Fingerprint: "SHA256:key-a"}

func TestPositiveCacheWindows(t *testing.T) {
	for _, tc := range []struct {
		name                string
		ttl, grace, elapsed time.Duration
		fresh, fallback     bool
	}{
		{"fresh", 30 * time.Second, DefaultGrace, 29 * time.Second, true, true},
		{"ttl boundary", 30 * time.Second, DefaultGrace, 30 * time.Second, false, true},
		{"expired ttl inside grace", 30 * time.Second, DefaultGrace, 4 * time.Minute, false, true},
		{"grace boundary", 30 * time.Second, DefaultGrace, 5 * time.Minute, false, false},
		{"outside grace", 30 * time.Second, DefaultGrace, 6 * time.Minute, false, false},
		{"server ttl exceeds grace", 10 * time.Minute, DefaultGrace, 6 * time.Minute, true, false},
		{"zero ttl", 0, DefaultGrace, 0, false, true},
		{"negative ttl", -time.Second, DefaultGrace, 0, false, true},
		{"disabled grace", time.Minute, 0, 0, true, false},
		{"backward clock", time.Minute, DefaultGrace, -time.Second, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Unix(1000, 0)
			c := NewPositiveCache(2, tc.grace, func() time.Time { return now })
			c.Put(testKey, "user-a", tc.ttl)
			now = now.Add(tc.elapsed)
			for _, check := range []struct {
				name string
				get  func(CacheKey) (string, bool)
				want bool
			}{
				{"fresh", c.Fresh, tc.fresh}, {"grace", c.Grace, tc.fallback},
			} {
				uid, ok := check.get(testKey)
				if ok != check.want || (ok && uid != "user-a") || (!ok && uid != "") {
					t.Fatalf("%s = (%q,%v), want hit=%v", check.name, uid, ok, check.want)
				}
			}
		})
	}
}

func TestPositiveCacheIsolation(t *testing.T) {
	c := NewPositiveCache(8, DefaultGrace, nil)
	c.Put(testKey, "user-a", time.Minute)
	for _, key := range []CacheKey{
		{"backend-b", testKey.Login, testKey.Fingerprint},
		{testKey.Backend, "bob", testKey.Fingerprint},
		{testKey.Backend, testKey.Login, "SHA256:key-b"},
	} {
		if _, ok := c.Fresh(key); ok {
			t.Fatalf("unexpected fresh hit for %v", key)
		}
		if _, ok := c.Grace(key); ok {
			t.Fatalf("unexpected grace hit for %v", key)
		}
	}
	other := testKey
	other.Backend = "backend-b"
	c.Put(other, "user-b", time.Minute)
	c.Invalidate(testKey)
	if _, ok := c.Grace(testKey); ok {
		t.Fatal("invalidated authorization resurrected")
	}
	if uid, ok := c.Fresh(other); !ok || uid != "user-b" {
		t.Fatal("invalidation crossed backend boundary")
	}
}

func TestPositiveCacheDoesNotExtendGrace(t *testing.T) {
	now := time.Unix(1000, 0)
	c := NewPositiveCache(1, DefaultGrace, func() time.Time { return now })
	c.Put(testKey, "user-a", time.Second)
	for i := 0; i < 5; i++ {
		now = now.Add(time.Minute)
		_, ok := c.Grace(testKey)
		if ok != (i < 4) {
			t.Fatalf("minute %d: hit=%v", i+1, ok)
		}
	}
	if len(c.entries) != 0 {
		t.Fatal("fully expired entry not evicted")
	}
}

func TestPositiveCacheEvictionAndRefresh(t *testing.T) {
	now := time.Unix(1000, 0)
	c := NewPositiveCache(2, DefaultGrace, func() time.Time { return now })
	a, b, d := testKey, testKey, testKey
	b.Login = "bob"
	d.Login = "dana"
	c.Put(a, "old", time.Second)
	c.Put(b, "b", time.Minute)
	c.Put(a, "new", time.Minute) // replacing an entry must not evict another
	if _, ok := c.Fresh(b); !ok {
		t.Fatal("replacement evicted another entry")
	}
	c.Put(d, "d", time.Minute)
	if _, ok := c.Grace(b); ok {
		t.Fatal("oldest success not evicted")
	}
	if uid, ok := c.Fresh(a); !ok || uid != "new" {
		t.Fatal("refresh lost identity")
	}
	now = now.Add(DefaultGrace)
	c.Put(b, "b", time.Minute)
	if len(c.entries) != 1 {
		t.Fatal("expired entries not pruned before insertion")
	}
}

func TestPositiveCacheDisabled(t *testing.T) {
	for _, capacity := range []int{0, -1} {
		c := NewPositiveCache(capacity, DefaultGrace, nil)
		c.Put(testKey, "user-a", time.Minute)
		if _, ok := c.Fresh(testKey); ok {
			t.Fatal("disabled cache stored entry")
		}
		if _, ok := c.Grace(testKey); ok {
			t.Fatal("disabled cache retained grace")
		}
	}
}

func TestPositiveCacheConcurrent(t *testing.T) {
	c := NewPositiveCache(16, DefaultGrace, nil)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			k := testKey
			k.Login = fmt.Sprint(i)
			for j := 0; j < 100; j++ {
				c.Put(k, "user", time.Minute)
				c.Fresh(k)
				c.Grace(k)
				c.Invalidate(k)
			}
		}(i)
	}
	wg.Wait()
	if len(c.entries) > 16 {
		t.Fatal("capacity exceeded")
	}
}
