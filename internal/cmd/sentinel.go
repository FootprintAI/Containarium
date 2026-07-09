//go:build !windows

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

	"github.com/footprintai/containarium/internal/config"
	"github.com/footprintai/containarium/internal/sentinel"
	"github.com/spf13/cobra"
)

var (
	sentinelProvider               string
	sentinelSpotVM                 string
	sentinelZone                   string
	sentinelProject                string
	sentinelBackendAddr            string
	sentinelHealthPort             int
	sentinelCheckInterval          time.Duration
	sentinelHTTPPort               int
	sentinelHTTPSPort              int
	sentinelForwardedPorts         string
	sentinelHealthyThreshold       int
	sentinelUnhealthyThreshold     int
	sentinelBinaryPort             int
	sentinelRecoveryTimeout        time.Duration
	sentinelRecoveryBackoffInitial time.Duration
	sentinelRecoveryBackoffMax     time.Duration
	sentinelCertSyncInterval       time.Duration
	sentinelKeySyncInterval        time.Duration
	sentinelTunnelToken            string
	sentinelTunnelTokenPolicies    []string
	sentinelProxyProtocol          bool
	sentinelAlertWebhookURL        string
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
  containarium sentinel --provider=none --backend-addr=127.0.0.1 --health-port 8080 --http-port 9090

  # Tunnel mode (accept reverse tunnel connections from firewalled spots on port 443)
  containarium sentinel --provider=tunnel --tunnel-token SECRET`,
	RunE: runSentinel,
}

func init() {
	rootCmd.AddCommand(sentinelCmd)

	sentinelCmd.Flags().StringVar(&sentinelProvider, "provider", "gcp", "Cloud provider: \"gcp\", \"none\" (local testing), or \"tunnel\" (reverse tunnel)")
	sentinelCmd.Flags().StringVar(&sentinelTunnelToken, "tunnel-token", "", "Pre-shared token for tunnel authentication, allowed for any pool (legacy; use --tunnel-token-policy for pool-restricted tokens, or CONTAINARIUM_TUNNEL_TOKEN env)")
	sentinelCmd.Flags().StringSliceVar(&sentinelTunnelTokenPolicies, "tunnel-token-policy", nil, "Pool-restricted token in the form 'token=pool1,pool2'. Repeatable. Use '*' to mean any pool. Combined with --tunnel-token if both are provided.")
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
	sentinelCmd.Flags().DurationVar(&sentinelRecoveryBackoffInitial, "recovery-backoff-initial", 30*time.Second, "Initial interval between StartInstance retries while a backend is down (#514)")
	sentinelCmd.Flags().DurationVar(&sentinelRecoveryBackoffMax, "recovery-backoff-max", 5*time.Minute, "Max interval between StartInstance retries (exponential backoff cap)")
	sentinelCmd.Flags().DurationVar(&sentinelCertSyncInterval, "cert-sync-interval", 6*time.Hour, "Interval for syncing TLS certificates from backend (0 to use default 6h)")
	sentinelCmd.Flags().DurationVar(&sentinelKeySyncInterval, "key-sync-interval", 2*time.Minute, "Interval for syncing SSH keys from backend for sshpiper (0 to use default 2m)")
	sentinelCmd.Flags().BoolVar(&sentinelProxyProtocol, "proxy-protocol", false, "Prepend a PROXY v2 header to forwarded HTTPS streams so the backend Caddy sees the real client IP (requires Caddy with proxy_protocol listener wrapper trusting the sentinel)")
	sentinelCmd.Flags().StringVar(&sentinelAlertWebhookURL, "alert-webhook-url", os.Getenv(config.EnvSentinelAlertWebhook), "Webhook POSTed on spot preempted/recovered (always-on alert path; the on-spot vmalert dies with the VM). Falls back to $CONTAINARIUM_SENTINEL_ALERT_WEBHOOK (#514)")
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
		defer func() { _ = gcpProvider.Close() }()
		provider = gcpProvider

		// Hybrid mode: GCP + tunnel if --tunnel-token OR
		// --tunnel-token-policy is provided. Issue #337 — previously
		// gated on --tunnel-token alone, which contradicted the
		// --help text labeling --tunnel-token as "legacy; use
		// --tunnel-token-policy for pool-restricted tokens." Operators
		// following the documented rotation pattern (stage NEW via
		// policy, drop legacy) silently lost the tunnel-server when
		// they finished step 2.
		tunnelToken := sentinelTunnelToken
		if tunnelToken == "" {
			tunnelToken = os.Getenv("CONTAINARIUM_TUNNEL_TOKEN")
		}
		if tunnelToken != "" || len(sentinelTunnelTokenPolicies) > 0 {
			// Hybrid mode: GCP + tunnel on the same port 443 via ConnMux.
			// The ConnMux peeks the first byte to route tunnel ({) vs HTTPS (0x16).
			// HTTPS is proxied as raw TCP to the spot VM (Caddy handles TLS via SNI).
			log.Printf("[sentinel] hybrid mode: GCP + tunnel (ConnMux on port %d)", sentinelHTTPSPort)

			config := sentinel.Config{
				HealthPort:             sentinelHealthPort,
				CheckInterval:          sentinelCheckInterval,
				HTTPPort:               sentinelHTTPPort,
				HTTPSPort:              sentinelHTTPSPort,
				ForwardedPorts:         ports,
				HealthyThreshold:       sentinelHealthyThreshold,
				UnhealthyThreshold:     sentinelUnhealthyThreshold,
				BinaryPort:             sentinelBinaryPort,
				RecoveryTimeout:        sentinelRecoveryTimeout,
				RecoveryBackoffInitial: sentinelRecoveryBackoffInitial,
				RecoveryBackoffMax:     sentinelRecoveryBackoffMax,
				CertSyncInterval:       sentinelCertSyncInterval,
				KeySyncInterval:        sentinelKeySyncInterval,
				HybridMode:             true,
				ProxyProtocol:          sentinelProxyProtocol,
				AlertWebhookURL:        sentinelAlertWebhookURL,
			}

			manager := sentinel.NewManager(config, gcpProvider)

			// Start ConnMux on port 443 — multiplexes tunnel and HTTPS
			muxAddr := fmt.Sprintf(":%d", sentinelHTTPSPort)
			connMux, err := sentinel.NewConnMux(muxAddr)
			if err != nil {
				return fmt.Errorf("failed to start ConnMux on %s: %w", muxAddr, err)
			}
			defer func() { _ = connMux.Close() }()

			registry := sentinel.NewTunnelRegistry()
			// Issue #337 §"Related observations" — drain the registry
			// on shutdown so per-spot loopback aliases (127.0.0.x)
			// get removed. Without this, restarting the sentinel
			// inherits stale aliases that block fresh allocations
			// and force a manual `ip addr del`.
			defer registry.UnregisterAll()
			tunnelPolicy, polErr := sentinel.PolicyFromCLI(tunnelToken, sentinelTunnelTokenPolicies)
			if polErr != nil {
				return polErr
			}
			tunnelServer := sentinel.NewTunnelServer("", tunnelPolicy, registry)
			tunnelServer.OnConnect = manager.OnTunnelConnect
			tunnelServer.OnDisconnect = manager.OnTunnelDisconnect
			manager.SetTunnelRegistry(registry)
			manager.SetTunnelPolicy(tunnelPolicy)
			manager.SetHTTPSListener(connMux.HTTPSChanListener())

			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				sig := <-sigChan
				log.Printf("[sentinel] received signal: %v", sig)
				cancel()
			}()

			go connMux.Run()
			go func() {
				if err := tunnelServer.Serve(ctx, connMux.TunnelListener()); err != nil {
					log.Printf("[sentinel] tunnel server error: %v", err)
				}
			}()

			return manager.Run(ctx)
		}

	case "none":
		if sentinelBackendAddr == "" {
			return fmt.Errorf("--backend-addr is required for provider=none")
		}
		provider = sentinel.NewNoOpProvider(sentinelBackendAddr)

	case "tunnel":
		tunnelToken := sentinelTunnelToken
		if tunnelToken == "" {
			tunnelToken = os.Getenv("CONTAINARIUM_TUNNEL_TOKEN")
		}
		// Issue #337 — accept --tunnel-token-policy as a sufficient
		// enablement signal too. The --help text frames --tunnel-token
		// as "legacy; use --tunnel-token-policy for pool-restricted
		// tokens", so requiring both is a contradiction.
		if tunnelToken == "" && len(sentinelTunnelTokenPolicies) == 0 {
			return fmt.Errorf("--tunnel-token, --tunnel-token-policy, or CONTAINARIUM_TUNNEL_TOKEN is required for tunnel provider")
		}
		registry := sentinel.NewTunnelRegistry()
		// Issue #337 §"Related observations" — drain on shutdown so
		// per-spot 127.0.0.x aliases get removed (else the next start
		// inherits them and has to ip-addr-del them by hand).
		defer registry.UnregisterAll()
		provider = sentinel.NewTunnelProvider(registry, "")

		config := sentinel.Config{
			HealthPort:             sentinelHealthPort,
			CheckInterval:          sentinelCheckInterval,
			HTTPPort:               sentinelHTTPPort,
			HTTPSPort:              sentinelHTTPSPort,
			ForwardedPorts:         ports,
			HealthyThreshold:       sentinelHealthyThreshold,
			UnhealthyThreshold:     sentinelUnhealthyThreshold,
			BinaryPort:             sentinelBinaryPort,
			RecoveryTimeout:        sentinelRecoveryTimeout,
			RecoveryBackoffInitial: sentinelRecoveryBackoffInitial,
			RecoveryBackoffMax:     sentinelRecoveryBackoffMax,
			CertSyncInterval:       sentinelCertSyncInterval,
			KeySyncInterval:        sentinelKeySyncInterval,
			TunnelMode:             true,
			ProxyProtocol:          sentinelProxyProtocol,
			AlertWebhookURL:        sentinelAlertWebhookURL,
		}

		manager := sentinel.NewManager(config, provider)

		// Start ConnMux on port 443 — multiplexes tunnel handshakes and HTTPS
		// on the same port. No extra firewall port needed.
		muxAddr := fmt.Sprintf(":%d", sentinelHTTPSPort)
		connMux, err := sentinel.NewConnMux(muxAddr)
		if err != nil {
			return fmt.Errorf("failed to start ConnMux on %s: %w", muxAddr, err)
		}
		defer func() { _ = connMux.Close() }()

		// Wire up: tunnel connections → tunnel server, HTTPS → manager
		tunnelPolicy, polErr := sentinel.PolicyFromCLI(tunnelToken, sentinelTunnelTokenPolicies)
		if polErr != nil {
			return polErr
		}
		tunnelServer := sentinel.NewTunnelServer("", tunnelPolicy, registry)
		tunnelServer.OnConnect = manager.OnTunnelConnect
		tunnelServer.OnDisconnect = manager.OnTunnelDisconnect
		manager.SetTunnelRegistry(registry)
		manager.SetTunnelPolicy(tunnelPolicy)
		manager.SetHTTPSListener(connMux.HTTPSChanListener())

		// Graceful shutdown on signals
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

		go func() {
			sig := <-sigChan
			log.Printf("[sentinel] received signal: %v", sig)
			cancel()
		}()

		// Start ConnMux, tunnel server, and manager
		go connMux.Run()
		go func() {
			if err := tunnelServer.Serve(ctx, connMux.TunnelListener()); err != nil {
				log.Printf("[sentinel] tunnel server error: %v", err)
			}
		}()

		return manager.Run(ctx)

	default:
		return fmt.Errorf("unknown provider: %q (supported: gcp, none, tunnel)", sentinelProvider)
	}

	config := sentinel.Config{
		HealthPort:             sentinelHealthPort,
		CheckInterval:          sentinelCheckInterval,
		HTTPPort:               sentinelHTTPPort,
		HTTPSPort:              sentinelHTTPSPort,
		ForwardedPorts:         ports,
		HealthyThreshold:       sentinelHealthyThreshold,
		UnhealthyThreshold:     sentinelUnhealthyThreshold,
		BinaryPort:             sentinelBinaryPort,
		RecoveryTimeout:        sentinelRecoveryTimeout,
		RecoveryBackoffInitial: sentinelRecoveryBackoffInitial,
		RecoveryBackoffMax:     sentinelRecoveryBackoffMax,
		CertSyncInterval:       sentinelCertSyncInterval,
		KeySyncInterval:        sentinelKeySyncInterval,
		ProxyProtocol:          sentinelProxyProtocol,
		AlertWebhookURL:        sentinelAlertWebhookURL,
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
