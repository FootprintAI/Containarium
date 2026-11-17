package cmd

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	grpcinsecure "google.golang.org/grpc/credentials/insecure"

	"github.com/footprintai/containarium/internal/guardrail"
	"github.com/footprintai/containarium/internal/guardraildropin"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// shortSocketDir is a short temporary directory: a socket path has a small
// length limit.
func shortSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ge")
	must(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// `guardrail engine serve` answers GuardrailEngineService.Scan with the
// reference engine on a unix socket of mode 0660, tells systemd it is ready
// only once it listens, and stops cleanly.
func TestGuardrailEngineServe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix socket modes")
	}
	dir := shortSocketDir(t)
	sock := filepath.Join(dir, "e.sock")

	notify, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: filepath.Join(dir, "n.sock"), Net: "unixgram"})
	must(t, err)
	defer func() { _ = notify.Close() }()
	t.Setenv("NOTIFY_SOCKET", notify.LocalAddr().String())

	// A socket left by a run that was killed must not stop the next one.
	stale, err := net.Listen("unix", sock)
	must(t, err)
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = stale.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveGuardrailEngine(ctx, "unix://"+sock) }()

	buf := make([]byte, 64)
	_ = notify.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := notify.Read(buf)
	if err != nil || string(buf[:n]) != "READY=1" {
		t.Fatalf("readiness notification: %q, %v", buf[:n], err)
	}
	// Ready means listening, with the final mode.
	st, err := os.Stat(sock)
	must(t, err)
	if st.Mode()&os.ModeSocket == 0 || st.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode = %v, want a socket of 0660", st.Mode())
	}

	conn, err := grpc.NewClient("unix://"+sock, grpc.WithTransportCredentials(grpcinsecure.NewCredentials()))
	must(t, err)
	defer func() { _ = conn.Close() }()
	scanCtx, scanCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer scanCancel()
	resp, err := guardrail.NewGRPCEngine(conn).Scan(scanCtx, &pb.GuardrailScanRequest{
		Units: []*pb.GuardrailTextUnit{{UnitId: "u", Text: "write to someone@example.com"}},
		Kinds: []pb.GuardrailKind{pb.GuardrailKind_GUARDRAIL_KIND_PII},
	})
	must(t, err)
	if resp.GetEngineId() != guardrail.RulesEngineID || len(resp.GetFindings()) != 1 || resp.GetFindings()[0].GetType() != "EMAIL" {
		t.Fatalf("scan through the socket: %v", resp)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve returned %v after a clean stop", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not stop")
	}
}

func TestGuardrailEngineServeRefusesAnythingButAUnixSocket(t *testing.T) {
	for _, listen := range []string{"", "127.0.0.1:9091", "unix://relative.sock", "relative.sock", "tcp://0.0.0.0:9091"} {
		if err := serveGuardrailEngine(context.Background(), listen); err == nil || !strings.Contains(err.Error(), "--listen") {
			t.Errorf("--listen %q: err = %v", listen, err)
		}
	}
}

// The service runs inside a box, as a system user with no home and no
// platform credentials: the root command's hook, which resolves a server
// and reads the credentials file, must not run for it.
func TestGuardrailEngineServeNeedsNoServerOrCredentials(t *testing.T) {
	if guardrailEngineServeCmd.PersistentPreRunE == nil {
		t.Fatal("serve inherits the root command's PersistentPreRunE")
	}
	t.Setenv("HOME", "/nonexistent")
	if err := guardrailEngineServeCmd.PersistentPreRunE(guardrailEngineServeCmd, nil); err != nil {
		t.Fatal(err)
	}
}

// The unit the daemon installs runs exactly this command, and the daemon's
// install smoke test looks for the hook's usage line in the same binary.
func TestInstalledUnitRunsACommandThisBinaryHas(t *testing.T) {
	unit := string(guardraildropin.RenderEngineUnit())
	_, after, ok := strings.Cut(unit, "ExecStart="+guardraildropin.HookBinaryPath+" ")
	if !ok {
		t.Fatalf("no ExecStart for the pinned binary:\n%s", unit)
	}
	args := strings.Fields(strings.SplitN(after, "\n", 2)[0])
	found, rest, err := rootCmd.Find(args)
	if err != nil || found != guardrailEngineServeCmd {
		t.Fatalf("ExecStart args %v resolve to %v, %v", args, found, err)
	}
	if err := found.ParseFlags(rest); err != nil {
		t.Fatalf("ExecStart flags %v: %v", rest, err)
	}
	if got := found.Flag("listen").Value.String(); got != guardraildropin.ReferenceEngineAddr {
		t.Fatalf("--listen = %q", got)
	}
	_ = found.Flag("listen").Value.Set("")
}
