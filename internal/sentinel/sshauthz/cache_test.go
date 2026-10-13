package sshauthz_test

import (
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/sentinel/sshauthz"
	"github.com/stretchr/testify/assert"
)

func TestCacheTTL(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	c := sshauthz.NewCache(clock)

	c.Put("http://backend", "alice", "fp1", "user-42", time.Minute)

	// Before expiry — hit.
	uid, _, ok := c.Get("http://backend", "alice", "fp1")
	assert.True(t, ok, "should be a cache hit before TTL")
	assert.Equal(t, "user-42", uid)

	// Advance past TTL — miss.
	now = now.Add(2 * time.Minute)
	_, _, ok = c.Get("http://backend", "alice", "fp1")
	assert.False(t, ok, "should be a cache miss after TTL expiry")
}

func TestCachePerBackendIsolation(t *testing.T) {
	c := sshauthz.NewCache(nil)

	c.Put("http://backend-a", "alice", "fp1", "user-a", time.Hour)
	c.Put("http://backend-b", "alice", "fp1", "user-b", time.Hour)

	uid, _, ok := c.Get("http://backend-a", "alice", "fp1")
	assert.True(t, ok)
	assert.Equal(t, "user-a", uid, "backend-a entry must not bleed into backend-b")

	uid, _, ok = c.Get("http://backend-b", "alice", "fp1")
	assert.True(t, ok)
	assert.Equal(t, "user-b", uid, "backend-b entry must not bleed into backend-a")
}

func TestCacheZeroTTLNotStored(t *testing.T) {
	c := sshauthz.NewCache(nil)
	// Put with zero TTL should be a no-op.
	c.Put("http://backend", "alice", "fp1", "user-42", 0)

	_, _, ok := c.Get("http://backend", "alice", "fp1")
	assert.False(t, ok, "zero-TTL Put must not store an entry")
}

func TestCacheGraceWindow(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	c := sshauthz.NewCache(clock)

	// Store with 1-minute TTL.
	c.Put("http://backend", "alice", "fp1", "user-42", time.Minute)

	// Advance 2 minutes — normal Get misses but GraceGet (5m window) hits.
	now = now.Add(2 * time.Minute)
	_, _, ok := c.Get("http://backend", "alice", "fp1")
	assert.False(t, ok, "normal Get should miss after TTL")

	uid, ok := c.GraceGet("http://backend", "alice", "fp1", 5*time.Minute)
	assert.True(t, ok, "GraceGet should hit within grace window")
	assert.Equal(t, "user-42", uid)

	// Advance past grace window — GraceGet also misses.
	now = now.Add(10 * time.Minute)
	_, ok = c.GraceGet("http://backend", "alice", "fp1", 5*time.Minute)
	assert.False(t, ok, "GraceGet should miss after grace window")
}

func TestCacheEviction(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	c := sshauthz.NewCache(clock)

	c.Put("http://backend", "alice", "fp1", "user-42", time.Minute)

	// Advance past TTL so the entry is stale.
	now = now.Add(2 * time.Minute)

	// Put a fresh entry — should overwrite the stale one.
	c.Put("http://backend", "alice", "fp1", "user-fresh", time.Hour)
	uid, _, ok := c.Get("http://backend", "alice", "fp1")
	assert.True(t, ok, "fresh entry should be a hit")
	assert.Equal(t, "user-fresh", uid, "fresh entry should overwrite stale one")
}
