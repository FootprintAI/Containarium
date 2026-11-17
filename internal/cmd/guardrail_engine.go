package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	"github.com/footprintai/containarium/internal/guardrail"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// `containarium guardrail engine serve`: the in-tree reference rules engine
// behind GuardrailEngineService on a unix socket, so the hooks in a box have
// an engine process to call (#3767; docs/architecture/guardrail.md,
// "Built-in engine service"). The daemon installs it as a systemd unit of
// the box, run from the pinned binary. It talks to no server and reads no
// credential, so it is in the client build as well as the server's.
var guardrailEngineCmd = &cobra.Command{
	Use:   "engine",
	Short: "Run the reference detection engine as a local service",
}

var guardrailEngineServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Serve the reference rules engine on a unix socket",
	Long: `Serve GuardrailEngineService.Scan on a unix socket with the in-tree
reference rules engine: a handful of regular expressions for proving the
flow, not a detector to rely on. A production engine is a separate process
behind the same RPC.

The socket is created with mode 0660: whoever may open it is decided by the
socket's group and its directory, which are the caller's to set up (the
daemon's unit uses RuntimeDirectory= and Group=). Nothing is opened but
that socket: no network listener, no outbound connection, no file.

Under systemd (Type=notify) readiness is reported once the socket listens.
SIGTERM or SIGINT stops the service after the scans in flight.

Example:
  containarium guardrail engine serve --listen unix:///run/containarium-guardrail-reference/engine.sock`,
	Args: cobra.NoArgs,
	// Replaces the root command's hook, which resolves a server address and
	// reads the platform credentials file. This command talks to no server.
	PersistentPreRunE: func(*cobra.Command, []string) error { return nil },
	RunE: func(cmd *cobra.Command, _ []string) error {
		cmd.SilenceUsage = true
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return serveGuardrailEngine(ctx, guardrailEngineListen)
	},
}

var guardrailEngineListen string

// guardrailEngineSocketMode is the mode of the listening socket. Access is
// by group; the mode is never wider.
const guardrailEngineSocketMode = 0o660

func init() {
	guardrailCmd.AddCommand(guardrailEngineCmd)
	guardrailEngineCmd.AddCommand(guardrailEngineServeCmd)
	guardrailEngineServeCmd.Flags().StringVar(&guardrailEngineListen, "listen", "", "Where to listen: unix://<absolute path>, or an absolute socket path (required)")
}

// guardrailReferenceEngineServer is the reference engine behind the RPC.
type guardrailReferenceEngineServer struct {
	pb.UnimplementedGuardrailEngineServiceServer
}

func (guardrailReferenceEngineServer) Scan(ctx context.Context, req *pb.GuardrailScanRequest) (*pb.GuardrailScanResponse, error) {
	return guardrail.RulesEngine{}.Scan(ctx, req)
}

// serveGuardrailEngine listens on a unix socket and serves until ctx is done.
func serveGuardrailEngine(ctx context.Context, listen string) error {
	sock := strings.TrimPrefix(listen, "unix://")
	if !strings.HasPrefix(sock, "/") {
		return fmt.Errorf("--listen %q: want unix://<absolute path> (the engine listens on a unix socket only)", listen)
	}
	// A socket left behind by a run that was killed. Anything else at the
	// path is not ours to remove, and the listen below fails on it.
	if st, err := os.Lstat(sock); err == nil && st.Mode()&os.ModeSocket != 0 {
		_ = os.Remove(sock)
	}
	lis, err := net.Listen("unix", sock)
	if err != nil {
		return fmt.Errorf("--listen %s: %w", listen, err)
	}
	if err := os.Chmod(sock, guardrailEngineSocketMode); err != nil {
		_ = lis.Close()
		return fmt.Errorf("--listen %s: %w", listen, err)
	}
	srv := grpc.NewServer()
	pb.RegisterGuardrailEngineServiceServer(srv, guardrailReferenceEngineServer{})
	served := make(chan error, 1)
	go func() { served <- srv.Serve(lis) }()
	if err := notifySystemdReady(); err != nil {
		srv.Stop()
		return err
	}
	select {
	case err := <-served:
		return err
	case <-ctx.Done():
		srv.GracefulStop()
		if err := <-served; err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			return err
		}
		return nil
	}
}

// notifySystemdReady sends READY=1 to the socket systemd names in
// NOTIFY_SOCKET (sd_notify(3)); a no-op when not run as a Type=notify unit.
func notifySystemdReady() error {
	path := os.Getenv("NOTIFY_SOCKET")
	if path == "" {
		return nil
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return fmt.Errorf("notify systemd: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte("READY=1")); err != nil {
		return fmt.Errorf("notify systemd: %w", err)
	}
	return nil
}
