//go:build !windows && !containarium_client

package cmd

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/footprintai/containarium/internal/sentinel/sshauthz"
	"github.com/spf13/cobra"
	"github.com/tg123/sshpiper/libplugin"
)

var (
	sentinelSSHAuthzSocket       string
	sentinelSSHAuthzPluginSocket string
	sentinelSSHAuthzGrace        time.Duration
	sentinelSSHAuthzTimeout      time.Duration
)

var sentinelSSHAuthzPluginCmd = &cobra.Command{
	Use:   "ssh-authz-plugin",
	Short: "sshpiperd plugin: audit live SSH authorization before ssh-session-plugin",
	Long: `Run as the first sshpiperd chained plugin, before ssh-session-plugin and
yaml. Every offered raw key is checked against its routed backend through the
sentinel manager's private Unix socket. The manager signs the daemon request.
Certificates and unknown logins defer. ALLOW, DENY and approval-pending results
are logged and passed to ssh-session-plugin; every result defers in audit-only
mode. Positive cache TTL comes from the daemon, and outage grace never renews
the last successful authorization. There is no enforcement flag in this version.`,
	RunE: runSentinelSSHAuthzPlugin,
}

func init() {
	sentinelCmd.AddCommand(sentinelSSHAuthzPluginCmd)
	sentinelCmd.Flags().StringVar(&sentinelSSHAuthzSocket, "ssh-authz-socket", sshauthz.DefaultSocket, "Private Unix socket serving the ssh-authz-plugin (empty disables)")
	sentinelSSHAuthzPluginCmd.Flags().StringVar(&sentinelSSHAuthzPluginSocket, "ssh-authz-socket", sshauthz.DefaultSocket, "Sentinel manager's private authorization socket")
	sentinelSSHAuthzPluginCmd.Flags().DurationVar(&sentinelSSHAuthzGrace, "ssh-authz-grace", sshauthz.DefaultGrace, "Maximum age of a successful authorization reused during an outage")
	sentinelSSHAuthzPluginCmd.Flags().DurationVar(&sentinelSSHAuthzTimeout, "ssh-authz-timeout", sshauthz.DefaultTimeout, "Deadline for resolving and authorizing one offered key")
}

func runSentinelSSHAuthzPlugin(cmd *cobra.Command, args []string) error {
	if sentinelSSHAuthzGrace < 0 || sentinelSSHAuthzTimeout <= 0 || sentinelSSHAuthzPluginSocket == "" {
		return fmt.Errorf("ssh authz: socket and positive timeout required; grace must be non-negative")
	}
	bridge := sshauthz.NewBridgeClient(sentinelSSHAuthzPluginSocket)
	plugin, err := sshauthz.New(sshauthz.Config{Resolver: bridge, Authorizer: bridge, Cache: sshauthz.NewCache(sentinelSSHAuthzGrace, 0, nil), Timeout: sentinelSSHAuthzTimeout, Logf: log.Printf})
	if err != nil {
		return err
	}
	piper, err := libplugin.NewFromStdio(plugin.PluginConfig())
	if err != nil {
		return fmt.Errorf("create ssh authz plugin: %w", err)
	}
	piper.SetConfigLoggerCallback(libplugin.ConfigLoggerSlog)
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigc)
	done := make(chan error, 1)
	go func() { done <- piper.Serve() }()
	select {
	case err := <-done:
		return err
	case <-sigc:
		return nil
	}
}
