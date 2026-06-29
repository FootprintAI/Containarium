package cmd

import (
	"log"
	"time"

	"github.com/footprintai/containarium/internal/server"
	"github.com/spf13/cobra"
)

var (
	watchdogBinaryPath string
	watchdogHealthURL  string
)

var upgradeWatchdogCmd = &cobra.Command{
	Use:    "upgrade-watchdog",
	Hidden: true,
	Short:  "Post-upgrade liveness watchdog — restores .old binary if daemon doesn't come up (#507)",
	Long: `upgrade-watchdog is launched by the daemon itself before it triggers a
systemctl restart after a successful binary swap. It runs detached from the
daemon process group so it survives the restart, then polls the health endpoint
until the new binary is confirmed healthy or a timeout expires.

If the daemon fails to become healthy within the timeout AND a .old binary is
present, the watchdog atomically restores .old and restarts the service.

Not meant to be called directly by operators.`,
	RunE: runUpgradeWatchdog,
}

func init() {
	rootCmd.AddCommand(upgradeWatchdogCmd)
	upgradeWatchdogCmd.Flags().StringVar(&watchdogBinaryPath, "binary-path",
		"/usr/local/bin/containarium", "Path to the binary being watched")
	upgradeWatchdogCmd.Flags().StringVar(&watchdogHealthURL, "health-url",
		"http://localhost:8080/health", "URL to poll for daemon health")
}

func runUpgradeWatchdog(cmd *cobra.Command, args []string) error {
	log.SetFlags(log.Ltime)
	log.SetPrefix("[upgrade-watchdog] ")
	return server.RunUpgradeWatchdog(
		watchdogBinaryPath,
		watchdogHealthURL,
		90*time.Second,
		10*time.Second,
		5*time.Second,
		false,
	)
}
