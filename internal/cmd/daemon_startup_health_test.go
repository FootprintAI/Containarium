//go:build !windows && !containarium_client

package cmd

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// #3130: the daemon bound its HTTP port only after waiting up to two minutes
// for the core containers and two more for Postgres, so for ~4 minutes the
// backend looked dead. It now binds first and reports "degraded" with the
// reason while it waits.

type startupHealthBody struct {
	Status string `json:"status"`
	Reason string `json:"reason"`
}

func fetchStartupHealth(t *testing.T, addr string) startupHealthBody {
	t.Helper()
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + addr + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/health status code = %d, want 200 (degraded is live, not down)", resp.StatusCode)
	}
	var b startupHealthBody
	if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
		t.Fatalf("decode /health: %v", err)
	}
	return b
}

func waitForReason(t *testing.T, addr, want string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		got := fetchStartupHealth(t, addr)
		if got.Status == "degraded" && got.Reason == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("/health = %+v, want degraded with reason %q within %s", got, want, within)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// unreachablePostgresDSN points at a closed local port, so every ping fails
// fast with "connection refused".
func unreachablePostgresDSN(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return "postgres://u:p@127.0.0.1:" + strconv.Itoa(port) + "/db?connect_timeout=1&sslmode=disable"
}

// Acceptance test: with an unreachable Postgres and no core containers, the
// health endpoint answers within a few seconds with the degraded state.
func TestStartupHealth_DegradedWhileCoreContainersAndPostgresWaitsRun(t *testing.T) {
	sp := bindStartupHealth(true, "127.0.0.1", 0)
	if sp.listener == nil {
		t.Fatal("bindStartupHealth did not bind the HTTP port")
	}
	t.Cleanup(sp.Close)
	addr := sp.listener.Addr().String()

	// "No core containers": the core-container wait blocks until released.
	releaseCore := make(chan struct{})
	coreDone := make(chan struct{})
	go func() {
		sp.SetReason(startupReasonCoreContainers)
		<-releaseCore
		close(coreDone)
	}()

	start := time.Now()
	waitForReason(t, addr, startupReasonCoreContainers, 3*time.Second)
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("/health took %s to answer, want a few seconds", d)
	}

	close(releaseCore)
	<-coreDone

	// Postgres wait against an unreachable DSN.
	pgDone := make(chan bool, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		pgDone <- waitForPostgres(ctx, unreachablePostgresDSN(t), 100*time.Millisecond, sp.SetReason)
	}()
	waitForReason(t, addr, startupReasonPostgres, 3*time.Second)

	select {
	case reachable := <-pgDone:
		if reachable {
			t.Fatal("waitForPostgres reported an unreachable DSN as reachable")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waitForPostgres did not respect its deadline")
	}
	sp.SetReason(startupReasonInitialising)
	waitForReason(t, addr, startupReasonInitialising, time.Second)
}

func TestWaitForPostgres_ReachableDoesNotReportUnavailable(t *testing.T) {
	var reasons []string
	var pings atomic.Int32
	ping := func(context.Context, string) error { pings.Add(1); return nil }
	ok := waitForPostgresWith(context.Background(), "dsn", time.Millisecond, func(r string) { reasons = append(reasons, r) }, ping)
	if !ok {
		t.Fatal("reachable Postgres reported unreachable")
	}
	if pings.Load() != 1 {
		t.Errorf("pings = %d, want 1", pings.Load())
	}
	// The core-container reason must not linger while Postgres is checked,
	// and "unavailable" is only reported after a ping actually failed.
	if len(reasons) != 1 || reasons[0] != startupReasonWaitPostgres {
		t.Errorf("reasons = %q, want only %q", reasons, startupReasonWaitPostgres)
	}
}

func TestBindStartupHealth(t *testing.T) {
	if sp := bindStartupHealth(false, "127.0.0.1", 0); sp.listener != nil {
		sp.Close()
		t.Error("bound the HTTP port although REST is disabled")
	}

	// Port taken: startup carries on without the early listener; the
	// gateway reports the bind error later, exactly as before #3130.
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	sp := bindStartupHealth(true, "127.0.0.1", taken.Addr().(*net.TCPAddr).Port)
	if sp.listener != nil {
		sp.Close()
		t.Error("listener non-nil although the port was taken")
	}
	sp.SetReason("x") // nil-safe
	sp.Close()        // nil-safe
}

// The persisted daemon config can change the HTTP port or turn REST off. The
// early listener must then be released so the gateway binds the right port.
func TestStartupHealth_ReleaseUnlessServing(t *testing.T) {
	sp := bindStartupHealth(true, "127.0.0.1", 0)
	port := sp.listener.Addr().(*net.TCPAddr).Port
	if got := sp.releaseUnlessServing(true, port); got == nil {
		t.Fatal("released the listener although REST and the port are unchanged")
	}

	if got := sp.releaseUnlessServing(true, port+1); got != nil {
		t.Error("kept the listener although the HTTP port changed")
	}
	if _, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port)); err == nil {
		t.Error("port still accepting after release")
	}

	sp2 := bindStartupHealth(true, "127.0.0.1", 0)
	if got := sp2.releaseUnlessServing(false, sp2.listener.Addr().(*net.TCPAddr).Port); got != nil {
		t.Error("kept the listener although REST was turned off")
	}
}
