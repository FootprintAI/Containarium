package dialer

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/agentbox"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// These run against a real agent-box SpawnService listener on a real unix
// socket in a temp dir — per the design note's own scoping for this
// package's tests, no live Incus/container host is needed: the thing
// under test is socket/connection behavior, which a plain local process
// exercises just as faithfully as a container would.

func TestDialer_ReusesConnectionAcrossCalls(t *testing.T) {
	d := New()
	t.Cleanup(func() { _ = d.Close() })

	socketPath := filepath.Join(t.TempDir(), "spawn.sock")
	srv, err := agentbox.StartSpawnListener(socketPath)
	if err != nil {
		t.Fatalf("StartSpawnListener: %v", err)
	}
	t.Cleanup(srv.GracefulStop)

	const n = 5
	for i := 0; i < n; i++ {
		if _, err := d.Client(socketPath); err != nil {
			t.Fatalf("Client call %d: %v", i, err)
		}
	}

	d.mu.Lock()
	got := len(d.conns)
	d.mu.Unlock()
	if got != 1 {
		t.Errorf("cached connections for one path = %d, want 1 (dialed once, reused across %d calls)", got, n)
	}
}

func TestDialer_KeysByPath(t *testing.T) {
	d := New()
	t.Cleanup(func() { _ = d.Close() })

	pathA := filepath.Join(t.TempDir(), "a.sock")
	pathB := filepath.Join(t.TempDir(), "b.sock")
	srvA, err := agentbox.StartSpawnListener(pathA)
	if err != nil {
		t.Fatalf("StartSpawnListener a: %v", err)
	}
	t.Cleanup(srvA.GracefulStop)
	srvB, err := agentbox.StartSpawnListener(pathB)
	if err != nil {
		t.Fatalf("StartSpawnListener b: %v", err)
	}
	t.Cleanup(srvB.GracefulStop)

	if _, err := d.Client(pathA); err != nil {
		t.Fatalf("Client a: %v", err)
	}
	if _, err := d.Client(pathB); err != nil {
		t.Fatalf("Client b: %v", err)
	}

	d.mu.Lock()
	got := len(d.conns)
	d.mu.Unlock()
	if got != 2 {
		t.Errorf("cached connections for two distinct paths = %d, want 2", got)
	}
}

func TestDialer_ClientWorksAgainstRealSocket(t *testing.T) {
	d := New()
	t.Cleanup(func() { _ = d.Close() })

	socketPath := filepath.Join(t.TempDir(), "spawn.sock")
	srv, err := agentbox.StartSpawnListener(socketPath)
	if err != nil {
		t.Fatalf("StartSpawnListener: %v", err)
	}
	t.Cleanup(srv.GracefulStop)

	client, err := d.Client(socketPath)
	if err != nil {
		t.Fatalf("Client: %v", err)
	}
	resp, err := client.Exec(context.Background(), &pb.AgentExecRequest{Command: "echo via-dialer"})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if resp.Stdout != "via-dialer\n" {
		t.Errorf("stdout = %q", resp.Stdout)
	}
}

// TestDialer_DeadSocketReconnects pins the design note's own test
// requirement: "dead socket -> reconnect and succeed." The Dialer's cached
// *grpc.ClientConn survives the original listener going away; a second
// agent-box process taking over the same socket path is enough for a call
// through the SAME cached client to eventually succeed again — this is
// grpc-go's own reconnect behavior working through the cache, not custom
// retry logic in this package.
func TestDialer_DeadSocketReconnects(t *testing.T) {
	d := New()
	t.Cleanup(func() { _ = d.Close() })

	socketPath := filepath.Join(t.TempDir(), "spawn.sock")
	srv1, err := agentbox.StartSpawnListener(socketPath)
	if err != nil {
		t.Fatalf("StartSpawnListener (1st): %v", err)
	}

	client, err := d.Client(socketPath)
	if err != nil {
		t.Fatalf("Client: %v", err)
	}
	if _, err := client.Exec(context.Background(), &pb.AgentExecRequest{Command: "true"}); err != nil {
		t.Fatalf("Exec against 1st listener: %v", err)
	}

	srv1.GracefulStop()

	srv2, err := agentbox.StartSpawnListener(socketPath)
	if err != nil {
		t.Fatalf("StartSpawnListener (2nd, same path): %v", err)
	}
	t.Cleanup(srv2.GracefulStop)

	// grpc-go's reconnect backoff isn't instant — poll instead of asserting
	// on the first attempt.
	deadline := time.Now().Add(5 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		_, lastErr = client.Exec(ctx, &pb.AgentExecRequest{Command: "true"})
		cancel()
		if lastErr == nil {
			return // reconnected and succeeded — test passes
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("did not reconnect through the same cached client within 5s; last error: %v", lastErr)
}

// TestDialer_RespectsCallerDeadlineAgainstUnreachableSocket pins the
// design note's other test requirement: "reconnect budget bounded so a
// wedged member cannot consume the caller's deadline." Nothing is
// listening on socketPath at all — a call through it must return within
// the caller's own context deadline, not hang waiting indefinitely for a
// connection that will never come.
//
// Verified by mutation: adding grpc.WithDefaultCallOptions(WaitForReady
// (true)) to Client() does NOT make this test fail — grpc-go still honors
// the call's context deadline either way, waiting-and-retrying up to it
// rather than failing on the first unready state. That's the real
// guarantee this package depends on and this test protects: the caller's
// deadline is always respected, not that failure is instantaneous.
func TestDialer_RespectsCallerDeadlineAgainstUnreachableSocket(t *testing.T) {
	d := New()
	t.Cleanup(func() { _ = d.Close() })

	socketPath := filepath.Join(t.TempDir(), "nothing-listening.sock")
	client, err := d.Client(socketPath)
	if err != nil {
		t.Fatalf("Client: %v", err) // dialing itself is lazy and must not fail here
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, execErr := client.Exec(ctx, &pb.AgentExecRequest{Command: "true"})
	elapsed := time.Since(start)

	if execErr == nil {
		t.Fatal("Exec against an unreachable socket unexpectedly succeeded")
	}
	if elapsed > 2*time.Second {
		t.Errorf("Exec took %s to fail, want well under the caller's ~500ms deadline budget (a wedged/unreachable member must not consume more than that)", elapsed)
	}
}

func TestDialer_Forget_ClosesAndEvicts(t *testing.T) {
	d := New()
	t.Cleanup(func() { _ = d.Close() })

	socketPath := filepath.Join(t.TempDir(), "spawn.sock")
	srv, err := agentbox.StartSpawnListener(socketPath)
	if err != nil {
		t.Fatalf("StartSpawnListener: %v", err)
	}
	t.Cleanup(srv.GracefulStop)

	if _, err := d.Client(socketPath); err != nil {
		t.Fatalf("Client: %v", err)
	}
	if err := d.Forget(socketPath); err != nil {
		t.Fatalf("Forget: %v", err)
	}

	d.mu.Lock()
	_, stillCached := d.conns[socketPath]
	d.mu.Unlock()
	if stillCached {
		t.Error("connection still cached after Forget")
	}

	// Forgetting an already-forgotten (or never-dialed) path is a no-op,
	// not an error — a caller destroying a pool member shouldn't have to
	// track whether it ever actually claimed a connection.
	if err := d.Forget(socketPath); err != nil {
		t.Errorf("Forget on an absent entry returned %v, want nil", err)
	}
}

func TestDialer_Close_ClosesAllAndResets(t *testing.T) {
	d := New()

	pathA := filepath.Join(t.TempDir(), "a.sock")
	pathB := filepath.Join(t.TempDir(), "b.sock")
	srvA, err := agentbox.StartSpawnListener(pathA)
	if err != nil {
		t.Fatalf("StartSpawnListener a: %v", err)
	}
	t.Cleanup(srvA.GracefulStop)
	srvB, err := agentbox.StartSpawnListener(pathB)
	if err != nil {
		t.Fatalf("StartSpawnListener b: %v", err)
	}
	t.Cleanup(srvB.GracefulStop)

	if _, err := d.Client(pathA); err != nil {
		t.Fatalf("Client a: %v", err)
	}
	if _, err := d.Client(pathB); err != nil {
		t.Fatalf("Client b: %v", err)
	}

	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	d.mu.Lock()
	got := len(d.conns)
	d.mu.Unlock()
	if got != 0 {
		t.Errorf("cached connections after Close = %d, want 0", got)
	}
}
