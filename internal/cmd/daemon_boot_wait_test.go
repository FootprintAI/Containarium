//go:build !windows && !containarium_client

package cmd

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// Issue #1483: on a byoc node, `containarium.service` reports `active`
// forever while permanently stuck at "Waiting for core containers to be
// ready..." after boot. waitForCoreContainers already re-resolves each
// core container's address on every 2-second poll (it does not latch a
// stale IP) and already wraps its loop in a 2-minute context.WithTimeout.
// But that outer bound is only checked at the top of each loop iteration
// — it does nothing to bound a single incusClient.FindContainerByRole
// call *inside* one iteration. When the incus.Client passed in has no
// per-call HTTP timeout (the shared, long-lived client every other daemon
// code path uses), a slow-to-answer incusd can park the goroutine inside
// one such call for up to the SDK transport's own 3600s
// ResponseHeaderTimeout — 30x past the outer bound — and the loop never
// gets to retry.
//
// These tests exercise waitForCoreContainers directly against a fake
// Incus API server that answers the connection-probe endpoint
// (GetServer, "/1.0") quickly but never answers the instance-lookup
// endpoints FindContainerByRole's ListContainers hits ("/1.0/instances",
// "/1.0/instances/<name>") — standing in for an incusd that is alive and
// reachable (the daemon already connected to it successfully at startup)
// but too busy (e.g. mounting storage) to service that particular request
// yet. They prove both halves of the fix: a client built with
// incus.NewWithSocketAndTimeout lets the loop actually retry and still
// respects the outer bound / "proceed anyway" contract, while the old
// unbounded incus.NewWithSocket client — every other daemon code path's
// client — gets stuck on the very first such call, past the outer bound,
// which is exactly why daemon.go must use a second, short-timeout client
// for this one call site rather than reusing the shared one.

// startFakeIncusServer starts a minimal fake Incus API server listening
// on a unix socket. It answers "/1.0" (the GetServer() call
// incus.ConnectIncusUnix makes to test the connection) immediately with a
// valid empty response, so client construction itself never blocks; every
// "/1.0/instances" / "/1.0/instances/..." request (GetInstanceNames /
// GetInstance — what ListContainers, and so FindContainerByRole, call)
// is counted and then left to hang until the request's own context is
// canceled, which happens when the server is closed on test cleanup — so
// no handler goroutine leaks past the test that started it.
func startFakeIncusServer(t *testing.T) (sockPath string, instanceCallCount *int64) {
	t.Helper()

	// Unix socket paths have a short max length; use a short-prefixed
	// temp dir rather than t.TempDir() (which embeds the full test name
	// and can blow past that for a long subtest name) — same fix as
	// internal/hypervisor/provider_test.go's shortTempDir.
	dir, err := os.MkdirTemp("", "cmd-to")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	sockPath = filepath.Join(dir, "incus.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to listen on fake incus socket: %v", err)
	}

	instanceCallCount = new(int64)

	mux := http.NewServeMux()
	mux.HandleFunc("/1.0", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"type":"sync","status":"Success","status_code":200,"metadata":{}}`))
	})
	hang := func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(instanceCallCount, 1)
		<-r.Context().Done() // never respond; unblocked only by the server closing
	}
	mux.HandleFunc("/1.0/instances", hang)
	mux.HandleFunc("/1.0/instances/", hang)

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	return sockPath, instanceCallCount
}

// TestWaitForCoreContainers_BoundedTimeoutClientRetriesWithinOuterBound
// proves the fix end-to-end: fed a client whose per-call HTTP timeout is
// much shorter than the outer wait timeout, waitForCoreContainers keeps
// retrying (each FindContainerByRole call fails fast rather than hanging)
// and still returns once the outer bound elapses — the same "timeout
// waiting for core containers" + proceed-anyway contract daemon.go
// already relies on, now actually reachable across more than one loop
// iteration instead of getting stuck on the very first call.
func TestWaitForCoreContainers_BoundedTimeoutClientRetriesWithinOuterBound(t *testing.T) {
	sockPath, instanceCallCount := startFakeIncusServer(t)

	const perCallTimeout = 20 * time.Millisecond
	// Long enough to span more than one of waitForCoreContainers's
	// hardcoded 2s inter-iteration sleeps, so this actually proves
	// multiple full loop iterations happened, not just multiple calls
	// within a single one.
	const outerTimeout = 3500 * time.Millisecond

	client, err := incus.NewWithSocketAndTimeout(sockPath, perCallTimeout)
	if err != nil {
		t.Fatalf("NewWithSocketAndTimeout against a server that answers /1.0: %v", err)
	}

	start := time.Now()
	err = waitForCoreContainers(client, outerTimeout)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected waitForCoreContainers to report the timeout (core containers never became ready against a server that never answers instance lookups)")
	}
	// Generous slack over the outer bound plus one more inter-iteration
	// sleep — must return close to the outer bound, not hang well past
	// it.
	if elapsed > outerTimeout+3*time.Second {
		t.Fatalf("waitForCoreContainers(outerTimeout=%s) took %s — did not respect its outer bound", outerTimeout, elapsed)
	}

	// The real assertion: waitForCoreContainers checks 3 roles
	// (postgres, caddy, victoriametrics) per iteration, so a single
	// iteration alone already makes 3 calls. Requiring more than that
	// proves a second full loop iteration happened — i.e. the per-call
	// timeout let the loop come back around and retry instead of
	// parking inside the first hung call for the whole outer window.
	if got := atomic.LoadInt64(instanceCallCount); got < 4 {
		t.Fatalf("expected waitForCoreContainers to retry across more than one loop iteration (>3 instance-lookup attempts) within %s using a %s per-call timeout, got %d attempt(s)", outerTimeout, perCallTimeout, got)
	}
}

// TestWaitForCoreContainers_UnboundedClientCanStallPastOuterBound
// documents the actual bug mechanism: waitForCoreContainers's outer
// context.WithTimeout cannot interrupt a call already in flight. Fed the
// same unbounded client every other daemon code path uses
// (incus.NewWithSocket, nil ConnectionArgs, no HTTP timeout) against a
// server that answers the connection probe but never answers instance
// lookups, the very first FindContainerByRole call inside the loop's
// first iteration blocks indefinitely — well past the outer bound —
// proving the daemon can appear to hang far beyond the timeout it
// supposedly waits with. This is exactly why daemon.go must not reuse the
// shared unbounded client for this call site. The background goroutine is
// not waited on to completion here; the fake server's cleanup force-closes
// it so it cannot leak past this test.
func TestWaitForCoreContainers_UnboundedClientCanStallPastOuterBound(t *testing.T) {
	sockPath, instanceCallCount := startFakeIncusServer(t)

	const outerTimeout = 300 * time.Millisecond

	done := make(chan error, 1)
	go func() {
		client, err := incus.NewWithSocket(sockPath)
		if err != nil {
			done <- err
			return
		}
		done <- waitForCoreContainers(client, outerTimeout)
	}()

	select {
	case err := <-done:
		t.Fatalf("expected waitForCoreContainers (unbounded client) to still be blocked well past its %s outer timeout — a single FindContainerByRole call should be hung inside the loop's first iteration, but it returned (err=%v); this no longer reproduces the hang this issue is about", outerTimeout, err)
	case <-time.After(2 * time.Second):
		// Still blocked, 2s past a 300ms outer bound: exactly the
		// "active forever" symptom from #1483. Confirm it's parked
		// inside the instance-lookup call, not still connecting.
		if got := atomic.LoadInt64(instanceCallCount); got < 1 {
			t.Fatalf("expected the unbounded client to have reached (and be stuck on) at least one instance-lookup call by now, got %d", got)
		}
	}
}
