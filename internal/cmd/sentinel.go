package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/footprintai/containarium/internal/sentinel"
	"github.com/spf13/cobra"
)

var (
	sentinelProvider           string
	sentinelSpotVM             string
	sentinelZone               string
	sentinelProject            string
	sentinelBackendAddr        string
	sentinelHealthPort         int
	sentinelCheckInterval      time.Duration
	sentinelHTTPPort           int
	sentinelHTTPSPort          int
	sentinelForwardedPorts     string
	sentinelHealthyThreshold   int
	sentinelUnhealthyThreshold int
	sentinelBinaryPort         int
	sentinelRecoveryTimeout    time.Duration
	sentinelCertSyncInterval   time.Duration
	sentinelKeySyncInterval    time.Duration
)

var sentinelCmd = &cobra.Command{
	Use:   "sentinel",
	Short: "Run as an HA sentinel that proxies traffic to a spot VM",
	Long: `Run Containarium in sentinel mode. The sentinel sits on a tiny always-on VM,
owns the static IP, and forwards traffic to the backend spot VM via iptables DNAT.

When the backend is healthy (TCP check passes), traffic is forwarded transparently.
When the backend is unhealthy, the sentinel serves a maintenance page and attempts
to restart the backend VM.

Examples:
  # GCP mode (production)
  containarium sentinel --spot-vm my-spot-vm --zone us-central1-a --project my-project

  # Local testing (no cloud, no iptables)
  containarium sentinel --provider=none --backend-addr=127.0.0.1 --health-port 8080 --http-port 9090`,
	RunE: runSentinel,
}

func init() {
	rootCmd.AddCommand(sentinelCmd)

	sentinelCmd.Flags().StringVar(&sentinelProvider, "provider", "gcp", "Cloud provider: \"gcp\" or \"none\" (for local testing)")
	sentinelCmd.Flags().StringVar(&sentinelSpotVM, "spot-vm", "", "Name of the backend VM instance (required for gcp provider)")
	sentinelCmd.Flags().StringVar(&sentinelZone, "zone", "", "Cloud zone (required for gcp provider)")
	sentinelCmd.Flags().StringVar(&sentinelProject, "project", "", "Cloud project ID (required for gcp provider)")
	sentinelCmd.Flags().StringVar(&sentinelBackendAddr, "backend-addr", "", "Direct backend IP/host (for local testing with provider=none)")
	sentinelCmd.Flags().IntVar(&sentinelHealthPort, "health-port", 8080, "TCP port to health-check on backend")
	sentinelCmd.Flags().DurationVar(&sentinelCheckInterval, "check-interval", 15*time.Second, "Health check interval")
	sentinelCmd.Flags().IntVar(&sentinelHTTPPort, "http-port", 80, "Maintenance page HTTP port")
	sentinelCmd.Flags().IntVar(&sentinelHTTPSPort, "https-port", 443, "Maintenance page HTTPS port")
	sentinelCmd.Flags().StringVar(&sentinelForwardedPorts, "forwarded-ports", "80,443", "Comma-separated ports to DNAT forward (port 22 handled by sshpiper)")
	sentinelCmd.Flags().IntVar(&sentinelHealthyThreshold, "healthy-threshold", 2, "Consecutive healthy checks before switching to proxy")
	sentinelCmd.Flags().IntVar(&sentinelUnhealthyThreshold, "unhealthy-threshold", 2, "Consecutive unhealthy checks before switching to maintenance")
	sentinelCmd.Flags().IntVar(&sentinelBinaryPort, "binary-port", 8888, "Port to serve containarium binary for spot VM downloads (0 to disable)")
	sentinelCmd.Flags().DurationVar(&sentinelRecoveryTimeout, "recovery-timeout", 10*time.Minute, "Warn if recovery takes longer than this (0 to disable)")
	sentinelCmd.Flags().DurationVar(&sentinelCertSyncInterval, "cert-sync-interval", 6*time.Hour, "Interval for syncing TLS certificates from backend (0 to use default 6h)")
	sentinelCmd.Flags().DurationVar(&sentinelKeySyncInterval, "key-sync-interval", 2*time.Minute, "Interval for syncing SSH keys from backend for sshpiper (0 to use default 2m)")
}

func runSentinel(cmd *cobra.Command, args []string) error {
	// Parse forwarded ports
	ports, err := parseForwardedPorts(sentinelForwardedPorts)
	if err != nil {
		return fmt.Errorf("invalid forwarded-ports: %w", err)
	}

	// Create cloud provider
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var provider sentinel.CloudProvider

	switch sentinelProvider {
	case "gcp":
		if sentinelSpotVM == "" || sentinelZone == "" || sentinelProject == "" {
			return fmt.Errorf("--spot-vm, --zone, and --project are required for gcp provider")
		}
		gcpProvider, err := sentinel.NewGCPProvider(ctx, sentinelProject, sentinelZone, sentinelSpotVM)
		if err != nil {
			return fmt.Errorf("failed to create GCP provider: %w", err)
		}
		defer gcpProvider.Close()
		provider = gcpProvider

	case "none":
		if sentinelBackendAddr == "" {
			return fmt.Errorf("--backend-addr is required for provider=none")
		}
		provider = sentinel.NewNoOpProvider(sentinelBackendAddr)

	default:
		return fmt.Errorf("unknown provider: %q (supported: gcp, none)", sentinelProvider)
	}

	config := sentinel.Config{
		HealthPort:         sentinelHealthPort,
		CheckInterval:      sentinelCheckInterval,
		HTTPPort:           sentinelHTTPPort,
		HTTPSPort:          sentinelHTTPSPort,
		ForwardedPorts:     ports,
		HealthyThreshold:   sentinelHealthyThreshold,
		UnhealthyThreshold: sentinelUnhealthyThreshold,
		BinaryPort:         sentinelBinaryPort,
		RecoveryTimeout:    sentinelRecoveryTimeout,
		CertSyncInterval:   sentinelCertSyncInterval,
		KeySyncInterval:    sentinelKeySyncInterval,
	}

	manager := sentinel.NewManager(config, provider)

	// Graceful shutdown on signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Printf("[sentinel] received signal: %v", sig)
		cancel()
	}()

	return manager.Run(ctx)
}

func parseForwardedPorts(s string) ([]int, error) {
	parts := strings.Split(s, ",")
	ports := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		port, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %w", p, err)
		}
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("port %d out of range (1-65535)", port)
		}
		ports = append(ports, port)
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("at least one port is required")
	}
	return ports, nil
}
