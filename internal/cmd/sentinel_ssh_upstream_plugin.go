//go:build !windows && !containarium_client

package cmd

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/footprintai/containarium/internal/sentinel/sshcontrol"
	"github.com/footprintai/containarium/internal/sentinel/sshupstream"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
	"github.com/tg123/sshpiper/libplugin"
	"github.com/tg123/sshpiper/libplugin/ioconn"
	"google.golang.org/grpc"
	grpcinsecure "google.golang.org/grpc/credentials/insecure"
)

// init exposes the selected-routing adapter in the existing daemon artifact.
func init() { sentinelCmd.AddCommand(newSSHUpstreamPluginCommand()) }

// newSSHUpstreamPluginCommand delegates routing to an explicitly selected child
// and owns its lifecycle; stdout is reserved for the plugin protocol.
func newSSHUpstreamPluginCommand() *cobra.Command {
	var executable, controlSocket, listener string
	var args []string
	c := &cobra.Command{Use: "ssh-upstream-plugin", Short: "sshpiperd routing adapter with shared backend admission", Args: cobra.NoArgs}
	c.Flags().StringVar(&executable, "plugin", "", "Routing plugin executable")
	c.Flags().StringArrayVar(&args, "plugin-arg", nil, "Argument passed verbatim to the routing plugin; repeatable")
	c.Flags().StringVar(&controlSocket, "upstream-control-socket", "", "Shared private upstream controller socket")
	c.Flags().StringVar(&listener, "listener", "main", "Listener identity: main or anonymous")
	c.RunE = func(cmd *cobra.Command, _ []string) error {
		if executable == "" {
			return fmt.Errorf("routing plugin executable is required")
		}
		ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()
		var options []sshupstream.Option
		if controlSocket != "" {
			kind, err := sshUpstreamListener(listener)
			if err != nil {
				return err
			}
			peer, err := sshcontrol.DialPeer(controlSocket, kind)
			if err != nil {
				return err
			}
			defer func() { _ = peer.Close() }()
			options = append(options, sshupstream.WithControl(peer))
		}
		// #nosec G204 -- executable/argv are explicit local operator configuration
		// for a same-UID plugin. SSH metadata and routing replies never enter argv;
		// exec receives separate arguments and does not invoke a shell.
		child := exec.CommandContext(ctx, executable, args...)
		transport, stderr, err := ioconn.DialCmd(child)
		if err != nil {
			return err
		}
		exited := make(chan struct{})
		var childErr error
		go func() {
			childErr = child.Wait()
			close(exited)
		}()
		defer func() {
			stopRoutingChild(cancel, transport, stderr, exited)
		}()
		go func() { _, _ = io.Copy(os.Stderr, stderr) }()
		var used atomic.Bool
		conn, err := grpc.NewClient("passthrough:///routing-child", grpc.WithTransportCredentials(grpcinsecure.NewCredentials()),
			grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
				if used.Swap(true) {
					return nil, fmt.Errorf("routing child transport closed")
				}
				return transport, nil
			}))
		if err != nil {
			return err
		}
		defer func() { _ = conn.Close() }()
		cfg, err := sshupstream.NewAdapter(ctx, libplugin.NewSshPiperPluginClient(conn), func(ctx context.Context, a sshupstream.Attempt) (net.Conn, error) {
			u, err := url.Parse(a.URI)
			if err != nil {
				return nil, err
			}
			dialer := net.Dialer{Timeout: 2 * time.Second}
			return dialer.DialContext(ctx, "tcp", u.Host)
		}, options...)
		if err != nil {
			return err
		}
		plugin, err := libplugin.NewFromStdio(cfg)
		if err != nil {
			return err
		}
		plugin.SetConfigLoggerCallback(libplugin.ConfigLoggerSlog)
		done := make(chan error, 1)
		go func() { done <- plugin.Serve() }()
		select {
		case err := <-done:
			return err
		case <-exited:
			return fmt.Errorf("routing child exited: %v", childErr)
		case <-ctx.Done():
			return nil
		}
	}
	return c
}

// stopRoutingChild reaps a child even when it ignores its closed stdio transport.
func stopRoutingChild(cancel context.CancelFunc, transport, stderr io.Closer, exited <-chan struct{}) {
	cancel()
	_ = transport.Close()
	_ = stderr.Close()
	<-exited
}

// sshUpstreamListener validates the shared controller's explicit listener scope.
func sshUpstreamListener(listener string) (pb.SSHBanListener, error) {
	switch listener {
	case "main":
		return pb.SSHBanListener_SSH_BAN_LISTENER_MAIN, nil
	case "anonymous":
		return pb.SSHBanListener_SSH_BAN_LISTENER_ANONYMOUS, nil
	default:
		return 0, fmt.Errorf("invalid listener %q", listener)
	}
}
