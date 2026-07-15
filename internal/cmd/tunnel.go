//go:build !windows

package cmd

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/footprintai/containarium/internal/sentinel"
	"github.com/spf13/cobra"
)

var (
	tunnelSentinelAddr      string
	tunnelToken             string
	tunnelSpotID            string
	tunnelPorts             string
	tunnelPool              string
	tunnelPublicHostname    string
	tunnelPublicAliases     []string
	tunnelPublicBaseDomains []string
	tunnelPublicPort        int
	tunnelForward           []string
)

var tunnelCmd = &cobra.Command{
	Use:   "tunnel",
	Short: "Connect to a sentinel via reverse tunnel (for firewalled spot VMs)",
	Long: `Run the tunnel client on a spot VM that is behind a firewall.
The client connects outbound to the sentinel's public IP and establishes a reverse
tunnel. The sentinel can then forward traffic through the tunnel to this spot VM.

The spot VM must be running its normal services (containarium daemon on port 8080,
sshd on port 22, etc.) on localhost. The tunnel client proxies these ports through
to the sentinel.

Examples:
  containarium tunnel --sentinel-addr sentinel.example.com:9443 \
                      --token SECRET \
                      --spot-id my-remote-spot \
                      --ports 22,80,443,8080`,
	RunE: runTunnel,
}

func init() {
	rootCmd.AddCommand(tunnelCmd)

	tunnelCmd.Flags().StringVar(&tunnelSentinelAddr, "sentinel-addr", "", "Sentinel address (host:port) to connect to (required)")
	tunnelCmd.Flags().StringVar(&tunnelToken, "token", "", "Pre-shared authentication token (or CONTAINARIUM_TUNNEL_TOKEN env)")
	tunnelCmd.Flags().StringVar(&tunnelSpotID, "spot-id", "", "Unique identifier for this spot instance (required)")
	tunnelCmd.Flags().StringVar(&tunnelPorts, "ports", "22,80,443,3389,8080", "Comma-separated local ports to expose through the tunnel")
	tunnelCmd.Flags().StringVar(&tunnelPool, "pool", "", "Pool name to register this peer in (optional; empty = unpooled)")
	tunnelCmd.Flags().StringVar(&tunnelPublicHostname, "public-hostname", "", "If set, sentinel registers this tunnel as the primary for its pool, serving the named hostname (requires --pool and --public-port)")
	tunnelCmd.Flags().StringSliceVar(&tunnelPublicAliases, "public-aliases", nil, "Additional hostnames the primary's Caddy serves (e.g. api.example.com,voice.example.com)")
	tunnelCmd.Flags().StringSliceVar(&tunnelPublicBaseDomains, "public-base-domain", nil, "Suffix-match anchor advertised to the sentinel — inbound SNI of the form <anything>.<public-base-domain> routes through this tunnel without each subdomain being a registered alias. Repeatable: list multiple to host workloads under different parent domains on the same backend. See docs/PER-POOL-BASE-DOMAIN.md.")
	tunnelCmd.Flags().IntVar(&tunnelPublicPort, "public-port", 0, "Public TLS port the sentinel forwards to via this tunnel (typically 443; required with --public-hostname)")
	tunnelCmd.Flags().StringSliceVar(&tunnelForward, "forward", nil, "Override the local dial target for an advertised port: PORT=HOST:PORT (repeatable). Use on a K8s node to point its gateway port at the in-cluster sshpiper Service's reachable address, e.g. --forward 32022=10.0.0.5:32022, since NodePorts aren't reliably reachable on 127.0.0.1.")
}

func runTunnel(cmd *cobra.Command, args []string) error {
	if tunnelSentinelAddr == "" {
		return fmt.Errorf("--sentinel-addr is required")
	}
	if tunnelSpotID == "" {
		return fmt.Errorf("--spot-id is required")
	}

	token := tunnelToken
	if token == "" {
		token = os.Getenv("CONTAINARIUM_TUNNEL_TOKEN")
	}
	if token == "" {
		return fmt.Errorf("--token or CONTAINARIUM_TUNNEL_TOKEN is required")
	}

	ports, err := parseForwardedPorts(tunnelPorts)
	if err != nil {
		return fmt.Errorf("invalid ports: %w", err)
	}

	forward, err := parseForwardMap(tunnelForward)
	if err != nil {
		return fmt.Errorf("invalid --forward: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Printf("[tunnel] received signal: %v", sig)
		cancel()
	}()

	client := &sentinel.TunnelClient{
		SentinelAddr:      tunnelSentinelAddr,
		Token:             token,
		SpotID:            tunnelSpotID,
		Ports:             ports,
		Pool:              sentinel.Pool(tunnelPool),
		PublicHostname:    tunnelPublicHostname,
		PublicAliases:     tunnelPublicAliases,
		PublicBaseDomains: tunnelPublicBaseDomains,
		PublicPort:        tunnelPublicPort,
		Forward:           forward,
	}

	log.Printf("[tunnel] connecting to sentinel at %s as %q (ports: %v, pool: %q, primary_host: %q)", tunnelSentinelAddr, tunnelSpotID, ports, tunnelPool, tunnelPublicHostname)
	return client.Run(ctx)
}

// parseForwardMap parses repeated "PORT=HOST:PORT" entries into a
// map[advertisedPort]dialTarget for TunnelClient.Forward. Empty input
// yields a nil map (default 127.0.0.1:port dialing).
func parseForwardMap(entries []string) (map[int]string, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	m := make(map[int]string, len(entries))
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		key, target, ok := strings.Cut(e, "=")
		if !ok {
			return nil, fmt.Errorf("entry %q is not PORT=HOST:PORT", e)
		}
		port, err := strconv.Atoi(strings.TrimSpace(key))
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("entry %q: invalid port %q", e, key)
		}
		target = strings.TrimSpace(target)
		if _, _, err := net.SplitHostPort(target); err != nil {
			return nil, fmt.Errorf("entry %q: invalid target %q (want HOST:PORT)", e, target)
		}
		m[port] = target
	}
	return m, nil
}
