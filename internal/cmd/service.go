//go:build !windows

package cmd

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
)

const systemdServicePath = "/etc/systemd/system/containarium.service"

// systemdServiceTemplate is the canonical systemd service file.
// The daemon self-bootstraps from PostgreSQL so only --rest and --jwt-secret-file are needed.
const systemdServiceTemplate = `[Unit]
Description=Containarium Container Management Daemon
Documentation=https://github.com/footprintai/Containarium
After=network.target incus.service
# Wants=, not Requires=. A Requires= dependency that fails takes this unit's
# start job down with it, and a *job* failure is not something Restart=on-failure
# retries -- so a single transient incus hiccup at boot leaves the daemon dead
# until someone notices, which on a pool member means silently dropping out of
# the pool. After= still guarantees ordering, and Restart=on-failure covers the
# "incus not ready yet" case by retrying the daemon itself.
Wants=incus.service
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/usr/local/bin/containarium daemon \
  --rest \
  --jwt-secret-file /etc/containarium/jwt.secret
Restart=on-failure
# Keep retrying forever (StartLimitIntervalSec=0 above), but not at full
# speed. A persistent start failure used to retry every 5s indefinitely:
# one production host crash-looped 1655 times in ~4 hours, pinning a core
# and — because each cycle rewrites the bundled monitoring config —
# restarting alertmanager and vmalert every 7 seconds, so alerting could
# not have fired during the incident, including on the incident itself
# (#1152).
#
# "Never give up" and "retry at full speed" are separable. RestartSteps
# interpolates the delay geometrically from RestartSec to
# RestartMaxDelaySec, so a transient incus hiccup at boot still recovers
# in seconds while a persistent failure settles to one attempt every 5
# minutes. That same 4-hour outage would cost ~50 attempts, not 1655.
#
# Requires systemd 254+. The documented host floor is Ubuntu 24.04 LTS
# ("or later", README), which ships 255. On an older host systemd warns
# and continues, degrading to the previous fixed-interval behaviour
# rather than failing to start — so this cannot brick a host that
# predates the directives.
RestartSec=5s
RestartSteps=6
RestartMaxDelaySec=5min
User=root
Group=root

# Memory accounting only — deliberately no MemoryMax here (#1350).
#
# The sentinel unit caps its memory, because it is a pure forwarder whose
# working set is small and well understood (~82 MB) and whose host is 1-2 GB.
# The daemon is not that: it manages containers, ZFS datasets and gRPC traffic,
# and its legitimate peak is workload-dependent. A guessed cap on the busiest
# component risks restart loops under normal load, which is a worse failure
# than the slow leak a cap guards against.
#
# Accounting is the prerequisite either way: it costs nothing, exposes the
# cgroup memory statistics, and is what makes the working set measurable so a
# cap can later be chosen from data instead of guessed. #1349 went unnoticed
# for 27 days precisely because nothing was measuring.
MemoryAccounting=yes

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=false
ReadWritePaths=-/var/lib/containarium /var/lib/incus /etc/containarium /etc /home /var/lock /run/lock -/opt/containarium /var/log -/mnt/incus-data

# StateDirectory= makes systemd create /var/lib/containarium (0750, root) before
# the daemon starts and grants it write access. The backup service writes there
# on every destination -- pkg/core/backup stages the dump and its sidecar index
# under /var/lib/containarium/backups even for GCS -- and nothing else on the
# host creates that directory, so without this ProtectSystem=strict makes those
# writes fail EROFS. The "-" on the ReadWritePaths entry above keeps that
# (now redundant) grant from ever being the thing that fails namespace setup.
StateDirectory=containarium
StateDirectoryMode=0750

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

	if err := ensureDaemonUnitAndSecret(); err != nil {
		return err
	}

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

// daemonOwnedDirs are the unit's ReadWritePaths entries that Containarium owns
// rather than inherits from the base system, so they may not exist on a fresh
// host. Everything else the unit grants (/var/lib/incus, /etc, /home, /var/log,
// /var/lock, /run/lock) already exists or is created by incus.
//
// Two reasons these must be created at install time:
//
//   - ProtectSystem=strict makes systemd build the mount namespace from
//     ReadWritePaths= *before* the daemon executes, and a missing listed path
//     fails that setup with status=226/NAMESPACE — an opaque crashloop naming
//     neither the path nor the setting.
//   - They are in hostcheck.DaemonWritablePaths, which the doctor treats as
//     Required. `pool join` runs its capability self-check after this function,
//     so creating them here is what lets that check pass on a fresh host
//     instead of aborting the join.
//
// StateDirectory= in the unit covers /var/lib/containarium at runtime too, but
// only once the unit starts — which is after the doctor has already run.
var daemonOwnedDirs = []string{"/opt/containarium", "/var/lib/containarium"}

// ensureDaemonOwnedDirs creates the Containarium-owned directories the unit
// sandbox and the doctor both expect. root is prepended to each path so tests
// can exercise this without touching the real filesystem; callers pass "/".
func ensureDaemonOwnedDirs(root string) error {
	for _, dir := range daemonOwnedDirs {
		// 0750: every consumer is root (the daemon, the Terraform startup
		// scripts' markers, logrotate, the backup sidecar index).
		if err := os.MkdirAll(filepath.Join(root, dir), 0o750); err != nil {
			return fmt.Errorf("failed to create %s: %w", dir, err)
		}
	}
	return nil
}

// ensureDaemonUnitAndSecret makes the daemon's JWT secret and the canonical
// hardened systemd unit exist (idempotent). Shared by `service install` and
// `pool join` so the daemon unit is authored in exactly ONE place
// (correct-by-construction caps/ReadWritePaths — the capability trap the
// byo-compute-pool-join PRD calls out). Does NOT reload/enable/start.
func ensureDaemonUnitAndSecret() error {
	jwtPath := "/etc/containarium/jwt.secret"
	if _, err := os.Stat(jwtPath); os.IsNotExist(err) {
		if err := os.MkdirAll("/etc/containarium", 0700); err != nil {
			return fmt.Errorf("failed to create config directory: %w", err)
		}
		if err := os.WriteFile(jwtPath, []byte(generateRandomSecret()), 0600); err != nil {
			return fmt.Errorf("failed to write JWT secret: %w", err)
		}
		log.Printf("Generated JWT secret: %s", jwtPath)
	} else {
		log.Printf("JWT secret already exists: %s", jwtPath)
	}
	if err := ensureDaemonOwnedDirs("/"); err != nil {
		return err
	}
	// #nosec G306 -- systemd unit, world-readable config by convention; no secrets
	if err := os.WriteFile(systemdServicePath, []byte(systemdServiceTemplate), 0644); err != nil {
		return fmt.Errorf("failed to write service file: %w", err)
	}
	log.Printf("Service file written: %s", systemdServicePath)
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
