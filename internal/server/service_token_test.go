package server

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// mintCounter returns a mint func that hands out "tok-1", "tok-2", … and counts
// calls, so a test can prove exactly when a re-mint happened.
func mintCounter(n *int) func() (string, error) {
	return func() (string, error) {
		*n++
		return fmt.Sprintf("tok-%d", *n), nil
	}
}

func TestServiceTokenSource_CachesAndRenews(t *testing.T) {
	var mints int
	now := time.Unix(0, 0)
	s := newServiceTokenSource(mintCounter(&mints), time.Hour, 10*time.Minute)
	s.now = func() time.Time { return now }

	// First call mints.
	if tok, err := s.Token(); err != nil || tok != "tok-1" {
		t.Fatalf("first Token() = %q,%v; want tok-1,nil", tok, err)
	}
	// Well before the renewal window: cached, no new mint.
	now = now.Add(40 * time.Minute)
	if tok, _ := s.Token(); tok != "tok-1" || mints != 1 {
		t.Fatalf("cached call = %q (mints=%d); want tok-1 (1)", tok, mints)
	}
	// Inside the renewal window (< 10m to expiry): re-mints.
	now = now.Add(15 * time.Minute) // now 55m in, 5m to expiry
	if tok, _ := s.Token(); tok != "tok-2" || mints != 2 {
		t.Fatalf("renewal call = %q (mints=%d); want tok-2 (2)", tok, mints)
	}
	// The fresh token resets the clock: next call is cached again.
	now = now.Add(1 * time.Minute)
	if tok, _ := s.Token(); tok != "tok-2" || mints != 2 {
		t.Fatalf("post-renewal cached = %q (mints=%d); want tok-2 (2)", tok, mints)
	}
}

func TestServiceTokenSource_MintErrorFallsBackToValidCache(t *testing.T) {
	now := time.Unix(0, 0)
	fail := false
	mints := 0
	s := newServiceTokenSource(func() (string, error) {
		if fail {
			return "", errors.New("signer down")
		}
		mints++
		return fmt.Sprintf("tok-%d", mints), nil
	}, time.Hour, 10*time.Minute)
	s.now = func() time.Time { return now }

	if _, err := s.Token(); err != nil { // mints tok-1
		t.Fatalf("seed mint failed: %v", err)
	}
	// Enter the renewal window and make minting fail: the cached token is still
	// valid (not past expiry), so it must be returned rather than an error.
	now = now.Add(55 * time.Minute)
	fail = true
	if tok, err := s.Token(); err != nil || tok != "tok-1" {
		t.Fatalf("renewal-with-failing-mint = %q,%v; want tok-1,nil (fall back to valid cache)", tok, err)
	}
	// Past expiry with minting still broken: no valid cache to fall back on → error.
	now = now.Add(10 * time.Minute) // now 65m in, token (expiry 60m) is dead
	if tok, err := s.Token(); err == nil {
		t.Fatalf("expired cache + failing mint should error, got %q", tok)
	}
}

func TestServiceTokenSource_EmptyCacheSurfacesMintError(t *testing.T) {
	s := newServiceTokenSource(func() (string, error) { return "", errors.New("nope") }, time.Hour, time.Minute)
	if _, err := s.Token(); err == nil {
		t.Fatal("first mint failure with empty cache must return the error")
	}
}

func TestServiceTokenSource_ConcurrentSafe(t *testing.T) {
	var mints int
	s := newServiceTokenSource(mintCounter(&mints), time.Hour, time.Minute)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Token(); err != nil {
				t.Errorf("Token() error: %v", err)
			}
		}()
	}
	wg.Wait()
}
