//go:build !windows && !containarium_client

package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/footprintai/containarium/internal/sentinel/sshban"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
	"github.com/tg123/sshpiper/libplugin"
)

// init makes the ban plugin part of the existing daemon release artifact.
func init() { sentinelCmd.AddCommand(newSSHBanPluginCommand()) }

// newSSHBanPluginCommand isolates configuration per invocation and validates it
// before opening the stdio protocol or its privileged control socket.
func newSSHBanPluginCommand() *cobra.Command {
	var listener, socket string
	var maximum, capacity uint32
	var duration time.Duration
	var ignore []string
	c := &cobra.Command{Use: "ssh-ban-plugin", Short: "sshpiperd plugin: enforce and inspect source-IP failure budgets", Args: cobra.NoArgs}
	c.Flags().StringVar(&listener, "listener", "main", "Listener identity: main or anonymous")
	c.Flags().StringVar(&socket, "control-socket", "", "Private Unix control socket (default per listener)")
	c.Flags().Uint32Var(&maximum, "max-failures", 100, "Failed callbacks before blocking a source IP")
	c.Flags().DurationVar(&duration, "ban-duration", 5*time.Minute, "Fixed failure window from the first connection")
	c.Flags().Uint32Var(&capacity, "max-entries", 65536, "Maximum live source-IP entries")
	c.Flags().StringSliceVar(&ignore, "ignore-ip", nil, "CIDR exemptions from IP banning; key authentication still applies")
	c.RunE = func(cmd *cobra.Command, _ []string) error {
		kind := pb.SSHBanListener_SSH_BAN_LISTENER_MAIN
		switch listener {
		case "main":
		case "anonymous":
			kind = pb.SSHBanListener_SSH_BAN_LISTENER_ANONYMOUS
		default:
			return fmt.Errorf("invalid listener %q", listener)
		}
		logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
		g, err := sshban.New(sshban.Config{Listener: kind, MaxFailures: maximum, Duration: duration, IgnoreCIDRs: ignore, MaxEntries: capacity,
			Emit: func(e sshban.Event) {
				logger.Warn("ssh_ban_policy", "event", e.Kind, "source_ip", e.IP, "failures", e.Failures, "expires_at", e.ExpiresAt, "reason", e.Reason)
			},
		})
		if err != nil {
			return err
		}
		if socket == "" {
			socket = sshban.DefaultSocket(kind)
		}
		state, err := g.GetSSHBan(cmd.Context(), &pb.GetSSHBanRequest{Listener: kind, Ip: "127.0.0.1"})
		if err != nil {
			return err
		}
		logger = logger.With("listener", listener, "generation", state.Generation, "policy_hash", state.Policy.Hash, "max_failures", maximum)
		stop, err := sshban.ListenControl(socket, g)
		if err != nil {
			return err
		}
		defer stop()
		logger.Info("ssh_ban_policy", "event", "policy_loaded", "window", duration, "ignore_cidrs", ignore, "max_entries", capacity)
		plugin, err := libplugin.NewFromStdio(g.PluginConfig())
		if err != nil {
			return err
		}
		plugin.SetConfigLoggerCallback(libplugin.ConfigLoggerSlog)
		signals := make(chan os.Signal, 1)
		// SIGHUP never clears unrelated IPs. Ignore it for log rotation; bans are
		// cleared only through the targeted control operation or process restart.
		signal.Ignore(syscall.SIGHUP)
		signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(signals)
		done := make(chan error, 1)
		go func() { done <- plugin.Serve() }()
		select {
		case err := <-done:
			return err
		case <-signals:
			return nil
		case <-cmd.Context().Done():
			return cmd.Context().Err()
		}
	}
	return c
}
