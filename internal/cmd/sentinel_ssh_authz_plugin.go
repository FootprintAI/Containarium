//go:build !windows && !containarium_client

package cmd

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/footprintai/containarium/internal/sentinel"
	"github.com/footprintai/containarium/internal/sentinel/sshauthz"
	"github.com/spf13/cobra"
	"github.com/tg123/sshpiper/libplugin"
)

var (
	sshAuthzRoutesFile string
	sshAuthzGrace      time.Duration
	sshAuthzTimeout    time.Duration
	sshAuthzSentinelID string
)
var sentinelSSHAuthzPluginCmd = &cobra.Command{
	Use:   "ssh-authz-plugin",
	Short: "sshpiperd plugin: audit live SSH authorization and always defer (#2518)",
	Long: `Run over sshpiperd's stdio plugin protocol, before ssh-session-plugin and yaml.
All outcomes, including DENY and APPROVAL_PENDING, defer to the next plugin.
No enforcement flag is provided. The sentinel manager publishes login/backend
routing to --ssh-authz-routes; the plugin uses the same sentinel signing
credentials as keysync, without a new JWT or cloud credential.`,
	RunE: runSentinelSSHAuthzPlugin,
}

func init() {
	sentinelCmd.AddCommand(sentinelSSHAuthzPluginCmd)
	sentinelSSHAuthzPluginCmd.Flags().StringVar(&sshAuthzRoutesFile, "ssh-authz-routes", sshauthz.DefaultRoutesFile, "Sentinel keysync's login/backend/HTTP endpoint snapshot")
	sentinelSSHAuthzPluginCmd.Flags().DurationVar(&sshAuthzGrace, "ssh-authz-grace", sshauthz.DefaultGrace, "Maximum age of a positive authorization used on transport failures")
	sentinelSSHAuthzPluginCmd.Flags().DurationVar(&sshAuthzTimeout, "ssh-authz-timeout", sshauthz.DefaultTimeout, "Deadline for one signed authorization request")
	sentinelSSHAuthzPluginCmd.Flags().StringVar(&sshAuthzSentinelID, "sentinel-id", "", "Informational sentinel identifier sent to the backend")
}
func runSentinelSSHAuthzPlugin(_ *cobra.Command, _ []string) error {
	if sshAuthzGrace < 0 || sshAuthzTimeout <= 0 {
		return fmt.Errorf("SSH authorization grace must be nonnegative and timeout must be positive")
	}
	resolver := sshauthz.FileBackendResolver{Path: sshAuthzRoutesFile}
	plugin := &sshauthz.Plugin{
		Resolver:   resolver,
		Cache:      sshauthz.NewPositiveCache(4096, sshAuthzGrace, nil),
		Authorizer: &sshauthz.HTTPAuthorizer{BackendURL: resolver.BackendURL, Sign: sentinel.SignBodyRequest, Timeout: sshAuthzTimeout},
		Timeout:    sshAuthzTimeout, SentinelID: sshAuthzSentinelID,
		Logf: func(format string, args ...any) { slog.Info(fmt.Sprintf(format, args...)) },
	}
	piper, err := libplugin.NewFromStdio(plugin.Config())
	if err != nil {
		return fmt.Errorf("create SSH authorization plugin: %w", err)
	}
	piper.SetConfigLoggerCallback(libplugin.ConfigLoggerSlog)
	return piper.Serve()
}
