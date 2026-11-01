package auth

import (
	"bytes"
	"context"
	"log"
	"strings"
	"sync"
	"testing"
	"time"
)

// #3328: the revocation store can arrive after startup (a degraded start
// installs it once Postgres answers), so it is swapped in while requests are
// being validated. Every read goes through a race-safe accessor; while it is
// absent but expected, tokens are validated (the recorded Q8 decision) and
// the skip is logged once per state change, never silently and never per
// request.

// captureLog redirects the standard logger for the test.
func captureLog(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	prev := log.Writer()
	log.SetOutput(buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return buf
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) count(substr string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Count(s.b.String(), substr)
}

const revocationSkipLog = "tokens are validated WITHOUT the revocation check"

// The store is swapped in while other goroutines validate: run with -race.
func TestTokenManager_RevocationStoreSwapIsRaceSafe(t *testing.T) {
	tm := newTestTM(t)
	tok, _ := tm.GenerateToken("alice", []string{"user"}, time.Hour)

	var wg, started sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		started.Add(1)
		go func() {
			defer wg.Done()
			first := true
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, _ = tm.ValidateToken(tok)
				if first {
					started.Done()
					first = false
				}
			}
		}()
	}
	started.Wait() // every validator is in its loop before the swaps begin
	for i := 0; i < 200; i++ {
		tm.SetRevocationStore(newMemRevStore())
		time.Sleep(50 * time.Microsecond)
	}
	close(stop)
	wg.Wait()
}

// While the store is pending, a valid token is accepted and the degraded
// state is logged once; once the store arrives a token revoked before the
// window is rejected with no restart, and a later pending state logs again.
func TestTokenManager_RevocationPendingValidatesLogsOnceThenEnforces(t *testing.T) {
	logs := captureLog(t)
	tm := newTestTM(t)
	tm.SetRevocationPending()

	tok, _ := tm.GenerateToken("alice", []string{"user"}, time.Hour)
	for i := 0; i < 3; i++ {
		if _, err := tm.ValidateToken(tok); err != nil {
			t.Fatalf("validate %d while the store is pending: %v (Q8: tokens are validated)", i, err)
		}
	}
	if n := logs.count(revocationSkipLog); n != 1 {
		t.Fatalf("degraded-state log lines = %d, want exactly 1 (once per state change, not per request)", n)
	}

	// The token was revoked in Postgres before the outage: the store that
	// installs late already holds the row.
	claims, err := tm.ValidateToken(tok)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	store := newMemRevStore()
	if err := store.Revoke(context.Background(), claims.ID, claims.ExpiresAt.Time, "before the window"); err != nil {
		t.Fatalf("seed revocation: %v", err)
	}
	tm.SetRevocationStore(store)
	if _, err := tm.ValidateToken(tok); err == nil {
		t.Fatal("revoked token accepted after the store installed; want it rejected without a restart")
	}

	// A new degraded period is a new state change: logged once more.
	tm.SetRevocationStore(nil)
	tm.SetRevocationPending()
	other, _ := tm.GenerateToken("bob", []string{"user"}, time.Hour)
	_, _ = tm.ValidateToken(other)
	_, _ = tm.ValidateToken(other)
	if n := logs.count(revocationSkipLog); n != 2 {
		t.Fatalf("degraded-state log lines after a second degraded period = %d, want 2", n)
	}
}

// A TokenManager never told to expect a store (tests, minimal deployments)
// keeps today's behaviour: no check and no degraded-state log.
func TestTokenManager_NoRevocationExpectedLogsNothing(t *testing.T) {
	logs := captureLog(t)
	tm := newTestTM(t)
	tok, _ := tm.GenerateToken("alice", []string{"user"}, time.Hour)
	if _, err := tm.ValidateToken(tok); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if n := logs.count(revocationSkipLog); n != 0 {
		t.Fatalf("degraded-state log lines = %d, want 0 when no store is expected", n)
	}
}
