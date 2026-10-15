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

	"github.com/footprintai/containarium/internal/sentinel/sshupstream"
	"github.com/spf13/cobra"
	"github.com/tg123/sshpiper/libplugin"
	"github.com/tg123/sshpiper/libplugin/ioconn"
	"google.golang.org/grpc"
	grpcinsecure "google.golang.org/grpc/credentials/insecure"
)

// init exposes the transport spike without changing either deployed listener.
func init() { sentinelCmd.AddCommand(newSSHUpstreamPluginCommand()) }

// newSSHUpstreamPluginCommand delegates routing to an explicitly selected child
// and owns its lifecycle; stdout is reserved for the plugin protocol.
func newSSHUpstreamPluginCommand() *cobra.Command {
	var executable string
	var args []string
	c := &cobra.Command{Use: "ssh-upstream-plugin", Short: "Experimental sshpiperd routing transport adapter", Args: cobra.NoArgs}
	c.Flags().StringVar(&executable, "plugin", "", "Routing plugin executable")
	c.Flags().StringArrayVar(&args, "plugin-arg", nil, "Argument passed verbatim to the routing plugin; repeatable")
	c.RunE = func(cmd *cobra.Command, _ []string) error {
		if executable == "" {
			return fmt.Errorf("routing plugin executable is required")
		}
		ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()
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
			_ = transport.Close()
			_ = stderr.Close()
			<-exited
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
		})
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
