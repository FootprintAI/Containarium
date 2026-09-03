package agentbox

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// These exercise SpawnServer directly (no socket) for the RPC-logic cases,
// and go through a real StartSpawnListener + a real dialed gRPC client for
// the contract/transport cases — no live Incus host or container needed
// for any of it: a resident unix-socket gRPC server with real fork/exec is
// fully testable in a plain Linux dev environment (#1488 Phase 2's own
// scoping note).

func TestSpawnServer_Spawn_ReturnsPidAndReaps(t *testing.T) {
	t.Cleanup(setProcessLogDirForTest(t.TempDir()))
	t.Cleanup(func() { killAllAndReset(t) })
	s := NewSpawnServer()

	resp, err := s.Spawn(context.Background(), &pb.SpawnRequest{
		Command: "sleep 0.05",
		Name:    "reap-test",
	})
	if err != nil {
		t.Fatalf("Spawn: %v", err)
	}
	if resp.Pid <= 0 {
		t.Fatalf("pid = %d, want > 0", resp.Pid)
	}
	if resp.Name != "reap-test" || resp.LogPath == "" {
		t.Errorf("resp = %+v", resp)
	}

	// isAlive(pid) via kill(pid, 0) stays true for a zombie — a still-valid
	// PID slot the kernel hasn't freed yet — so it flipping to false is
	// specifically evidence cmd.Wait() completed and reaped the child, not
	// just that the sleep finished running.
	deadline := time.Now().Add(2 * time.Second)
	for isAlive(int(resp.Pid)) {
		if time.Now().After(deadline) {
			t.Fatalf("pid %d was not reaped within 2s (still alive / zombied)", resp.Pid)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestSpawnServer_Spawn_FramedCaptureMode is the #1674 contract-change AC:
// capture_mode must land on SpawnRequest so the gRPC transport isn't
// asymmetric with the MCP tool over the same shared core.
func TestSpawnServer_Spawn_FramedCaptureMode(t *testing.T) {
	dir := t.TempDir()
	t.Cleanup(setProcessLogDirForTest(dir))
	t.Cleanup(func() { killAllAndReset(t) })
	s := NewSpawnServer()

	resp, err := s.Spawn(context.Background(), &pb.SpawnRequest{
		Command:     "echo hi",
		Name:        "framed-grpc",
		CaptureMode: pb.CaptureMode_CAPTURE_MODE_FRAMED,
	})
	if err != nil {
		t.Fatalf("Spawn: %v", err)
	}

	record, found, err := readRunRecord(resp.Name)
	if err != nil || !found {
		t.Fatalf("readRunRecord: found=%v err=%v", found, err)
	}
	if record.CaptureMode != CaptureFramed {
		t.Errorf("record.CaptureMode = %q, want %q", record.CaptureMode, CaptureFramed)
	}
}

func TestSpawnServer_Spawn_RejectsEmptyCommand(t *testing.T) {
	s := NewSpawnServer()
	_, err := s.Spawn(context.Background(), &pb.SpawnRequest{Name: "no-command"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
	}
}

func TestSpawnServer_Spawn_DuplicateNameIsAlreadyExists(t *testing.T) {
	t.Cleanup(setProcessLogDirForTest(t.TempDir()))
	t.Cleanup(func() { killAllAndReset(t) })
	s := NewSpawnServer()

	if _, err := s.Spawn(context.Background(), &pb.SpawnRequest{Command: "sleep 1", Name: "dup-grpc"}); err != nil {
		t.Fatalf("first Spawn: %v", err)
	}
	_, err := s.Spawn(context.Background(), &pb.SpawnRequest{Command: "sleep 1", Name: "dup-grpc"})
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("code = %v, want AlreadyExists", status.Code(err))
	}
}

// TestSpawnServer_Spawn_ConcurrentSpawnsAreIndependent pins the design
// note's own test requirement: "concurrent spawns are independent."
func TestSpawnServer_Spawn_ConcurrentSpawnsAreIndependent(t *testing.T) {
	t.Cleanup(setProcessLogDirForTest(t.TempDir()))
	t.Cleanup(func() { killAllAndReset(t) })
	s := NewSpawnServer()

	const n = 10
	var wg sync.WaitGroup
	pids := make([]int64, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, err := s.Spawn(context.Background(), &pb.SpawnRequest{
				Command: "sleep 0.2",
				Name:    fmt.Sprintf("concurrent-%d", i),
			})
			errs[i] = err
			if resp != nil {
				pids[i] = resp.Pid
			}
		}(i)
	}
	wg.Wait()

	seen := make(map[int64]bool, n)
	for i, err := range errs {
		if err != nil {
			t.Errorf("spawn %d: %v", i, err)
			continue
		}
		if pids[i] <= 0 {
			t.Errorf("spawn %d: pid = %d", i, pids[i])
			continue
		}
		if seen[pids[i]] {
			t.Errorf("spawn %d: pid %d collided with an earlier spawn", i, pids[i])
		}
		seen[pids[i]] = true
	}
}

func TestSpawnServer_Exec_CapturesOutputAndExitCode(t *testing.T) {
	s := NewSpawnServer()
	resp, err := s.Exec(context.Background(), &pb.AgentExecRequest{
		Command: "echo hi; exit 3",
	})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if resp.Stdout != "hi\n" || resp.ExitCode != 3 {
		t.Errorf("resp = %+v, want stdout=%q exit_code=3", resp, "hi\n")
	}
}

func TestSpawnServer_Exec_RejectsEmptyCommand(t *testing.T) {
	s := NewSpawnServer()
	_, err := s.Exec(context.Background(), &pb.AgentExecRequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
	}
}

func TestSpawnServer_Exec_RespectsTimeout(t *testing.T) {
	s := NewSpawnServer()
	start := time.Now()
	resp, err := s.Exec(context.Background(), &pb.AgentExecRequest{
		Command:        "sleep 5",
		TimeoutSeconds: 1,
	})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("Exec took %s, want well under the 5s sleep (timeout should have killed it around 1s)", elapsed)
	}
	if resp.Stderr == "" {
		t.Error("expected a timeout note in stderr")
	}
}

// TestStartSpawnListener_RealClientOverRealSocket is the contract test the
// design note calls for: daemon-side client and box-side server both
// exercised through the generated stubs, over a real unix socket in a
// real temp dir — no mock. Proto drift here fails a test, not production.
func TestStartSpawnListener_RealClientOverRealSocket(t *testing.T) {
	t.Cleanup(setProcessLogDirForTest(t.TempDir()))
	t.Cleanup(func() { killAllAndReset(t) })
	socketPath := filepath.Join(t.TempDir(), "spawn.sock")

	srv, err := StartSpawnListener(socketPath)
	if err != nil {
		t.Fatalf("StartSpawnListener: %v", err)
	}
	t.Cleanup(srv.GracefulStop)

	conn, err := grpc.NewClient("unix:"+socketPath, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := pb.NewSpawnServiceClient(conn)

	execResp, err := client.Exec(context.Background(), &pb.AgentExecRequest{Command: "echo over-the-socket"})
	if err != nil {
		t.Fatalf("Exec over socket: %v", err)
	}
	if execResp.Stdout != "over-the-socket\n" {
		t.Errorf("Exec stdout = %q", execResp.Stdout)
	}

	spawnResp, err := client.Spawn(context.Background(), &pb.SpawnRequest{Command: "true", Name: "socket-spawn"})
	if err != nil {
		t.Fatalf("Spawn over socket: %v", err)
	}
	if spawnResp.Pid <= 0 {
		t.Errorf("Spawn over socket: pid = %d", spawnResp.Pid)
	}
}

// TestStartSpawnListener_RemovesStaleSocket pins that a leftover socket
// file from a killed previous process doesn't block a fresh bind.
func TestStartSpawnListener_RemovesStaleSocket(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "spawn.sock")

	// A real leftover socket file, the way a killed previous agent-box
	// process would leave one behind (os.WriteFile is enough — the OS
	// doesn't care that this isn't a real socket inode for the purpose of
	// "a file already exists at this path").
	if err := os.WriteFile(socketPath, nil, 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	srv, err := StartSpawnListener(socketPath)
	if err != nil {
		t.Fatalf("StartSpawnListener should remove the stale file and succeed: %v", err)
	}
	srv.GracefulStop()
}
