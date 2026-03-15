package cmd

import (
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

const systemdServicePath = "/etc/systemd/system/containarium.service"

// systemdServiceTemplate is the canonical systemd service file.
// The daemon self-bootstraps from PostgreSQL so only --rest and --jwt-secret-file are needed.
const systemdServiceTemplate = `[Unit]
Description=Containarium Container Management Daemon
Documentation=https://github.com/footprintai/Containarium
After=network.target incus.service
Requires=incus.service
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/usr/local/bin/containarium daemon \
  --rest \
  --jwt-secret-file /etc/containarium/jwt.secret
Restart=on-failure
RestartSec=5s
User=root
Group=root

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=false
ReadWritePaths=/var/lib/incus /etc/containarium /etc /home /var/lock /run/lock /opt/containarium

StandardOutput=journal
StandardError=journal
SyslogIdentifier=containarium

LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
`

var serviceCmd = &cobra.Command{
	Use:   "service",
	Short: "Manage the Containarium systemd service",
}

var serviceInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install the systemd service file and enable the daemon",
	Long: `Install the Containarium systemd service file to /etc/systemd/system/.

The service is configured with minimal flags (--rest --jwt-secret-file) because
the daemon auto-detects PostgreSQL and Caddy from Incus containers, and loads
persisted config (base-domain, ports, etc.) from the daemon_config table in PostgreSQL.

Requires root privileges.`,
	RunE: runServiceInstall,
}

var serviceUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Stop and remove the systemd service",
	RunE:  runServiceUninstall,
}

var serviceStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the systemd service status",
	RunE:  runServiceStatus,
}

func init() {
	rootCmd.AddCommand(serviceCmd)
	serviceCmd.AddCommand(serviceInstallCmd)
	serviceCmd.AddCommand(serviceUninstallCmd)
	serviceCmd.AddCommand(serviceStatusCmd)
}

func runServiceInstall(cmd *cobra.Command, args []string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command requires root privileges (use sudo)")
	}

	// Ensure JWT secret file exists
	jwtPath := "/etc/containarium/jwt.secret"
	if _, err := os.Stat(jwtPath); os.IsNotExist(err) {
		// Create directory and generate a secret
		if err := os.MkdirAll("/etc/containarium", 0700); err != nil {
			return fmt.Errorf("failed to create config directory: %w", err)
		}
		secret := generateRandomSecret()
		if err := os.WriteFile(jwtPath, []byte(secret), 0600); err != nil {
			return fmt.Errorf("failed to write JWT secret: %w", err)
		}
		log.Printf("Generated JWT secret: %s", jwtPath)
	} else {
		log.Printf("JWT secret already exists: %s", jwtPath)
	}

	// Write service file
	if err := os.WriteFile(systemdServicePath, []byte(systemdServiceTemplate), 0644); err != nil {
		return fmt.Errorf("failed to write service file: %w", err)
	}
	log.Printf("Service file written: %s", systemdServicePath)

	// Reload systemd
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("failed to reload systemd: %w", err)
	}

	// Enable service
	if err := exec.Command("systemctl", "enable", "containarium").Run(); err != nil {
		return fmt.Errorf("failed to enable service: %w", err)
	}
	log.Printf("Service enabled")

	// Start service
	if err := exec.Command("systemctl", "start", "containarium").Run(); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}
	log.Printf("Service started")

	fmt.Println()
	fmt.Println("Containarium service installed and running.")
	fmt.Println()
	fmt.Println("  Status:  sudo systemctl status containarium")
	fmt.Println("  Logs:    sudo journalctl -u containarium -f")
	fmt.Println("  Stop:    sudo systemctl stop containarium")
	fmt.Println("  Restart: sudo systemctl restart containarium")

	return nil
}

func runServiceUninstall(cmd *cobra.Command, args []string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command requires root privileges (use sudo)")
	}

	_ = exec.Command("systemctl", "stop", "containarium").Run()
	_ = exec.Command("systemctl", "disable", "containarium").Run()

	if err := os.Remove(systemdServicePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove service file: %w", err)
	}

	_ = exec.Command("systemctl", "daemon-reload").Run()

	log.Printf("Service stopped, disabled, and removed")
	return nil
}

func runServiceStatus(cmd *cobra.Command, args []string) error {
	out, err := exec.Command("systemctl", "status", "containarium", "--no-pager").CombinedOutput()
	fmt.Print(string(out))
	if err != nil {
		// systemctl status returns non-zero when service is not running
		return nil
	}
	return nil
}
