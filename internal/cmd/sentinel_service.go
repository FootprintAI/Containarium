//go:build !windows

package cmd

import (
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

const sentinelSystemdServicePath = "/etc/systemd/system/containarium-sentinel.service"

var (
	sentinelSvcSpotVM  string
	sentinelSvcZone    string
	sentinelSvcProject string
)

var sentinelServiceCmd = &cobra.Command{
	Use:   "service",
	Short: "Manage the Containarium sentinel systemd service",
}

var sentinelServiceInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install the sentinel systemd service file and enable it",
	Long: `Install the Containarium sentinel systemd service to /etc/systemd/system/.

The sentinel service monitors a backend spot VM and forwards traffic via iptables DNAT.
When the backend is unavailable, it serves a maintenance page.

Requires root privileges.`,
	RunE: runSentinelServiceInstall,
}

var sentinelServiceUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Stop and remove the sentinel systemd service",
	RunE:  runSentinelServiceUninstall,
}

var sentinelServiceStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the sentinel systemd service status",
	RunE:  runSentinelServiceStatus,
}

func init() {
	sentinelCmd.AddCommand(sentinelServiceCmd)
	sentinelServiceCmd.AddCommand(sentinelServiceInstallCmd)
	sentinelServiceCmd.AddCommand(sentinelServiceUninstallCmd)
	sentinelServiceCmd.AddCommand(sentinelServiceStatusCmd)

	sentinelServiceInstallCmd.Flags().StringVar(&sentinelSvcSpotVM, "spot-vm", "", "Name of the backend spot VM instance (required)")
	sentinelServiceInstallCmd.Flags().StringVar(&sentinelSvcZone, "zone", "", "GCP zone (required)")
	sentinelServiceInstallCmd.Flags().StringVar(&sentinelSvcProject, "project", "", "GCP project ID (required)")
}

func runSentinelServiceInstall(cmd *cobra.Command, args []string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command requires root privileges (use sudo)")
	}

	if sentinelSvcSpotVM == "" || sentinelSvcZone == "" || sentinelSvcProject == "" {
		return fmt.Errorf("--spot-vm, --zone, and --project are required")
	}

	serviceContent := fmt.Sprintf(`[Unit]
Description=Containarium Sentinel (HA Proxy)
Documentation=https://github.com/footprintai/Containarium
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/usr/local/bin/containarium sentinel \
  --spot-vm %s \
  --zone %s \
  --project %s
Restart=always
RestartSec=5s
User=root
Group=root

StandardOutput=journal
StandardError=journal
SyslogIdentifier=containarium-sentinel

LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`, sentinelSvcSpotVM, sentinelSvcZone, sentinelSvcProject)

	if err := os.WriteFile(sentinelSystemdServicePath, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("failed to write service file: %w", err)
	}
	log.Printf("Service file written: %s", sentinelSystemdServicePath)

	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("failed to reload systemd: %w", err)
	}

	if err := exec.Command("systemctl", "enable", "containarium-sentinel").Run(); err != nil {
		return fmt.Errorf("failed to enable service: %w", err)
	}
	log.Printf("Service enabled")

	if err := exec.Command("systemctl", "start", "containarium-sentinel").Run(); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}
	log.Printf("Service started")

	fmt.Println()
	fmt.Println("Containarium sentinel service installed and running.")
	fmt.Println()
	fmt.Println("  Status:  sudo systemctl status containarium-sentinel")
	fmt.Println("  Logs:    sudo journalctl -u containarium-sentinel -f")
	fmt.Println("  Stop:    sudo systemctl stop containarium-sentinel")
	fmt.Println("  Restart: sudo systemctl restart containarium-sentinel")

	return nil
}

func runSentinelServiceUninstall(cmd *cobra.Command, args []string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command requires root privileges (use sudo)")
	}

	_ = exec.Command("systemctl", "stop", "containarium-sentinel").Run()
	_ = exec.Command("systemctl", "disable", "containarium-sentinel").Run()

	if err := os.Remove(sentinelSystemdServicePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove service file: %w", err)
	}

	_ = exec.Command("systemctl", "daemon-reload").Run()

	log.Printf("Sentinel service stopped, disabled, and removed")
	return nil
}

func runSentinelServiceStatus(cmd *cobra.Command, args []string) error {
	out, err := exec.Command("systemctl", "status", "containarium-sentinel", "--no-pager").CombinedOutput()
	fmt.Print(string(out))
	if err != nil {
		return nil
	}
	return nil
}
