//go:build !windows

package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/footprintai/containarium/internal/egressproxy"
	"github.com/spf13/cobra"
)

var (
	egressRelayListen   string
	egressRelayUpstream string
	egressRelayAllow    []string
)

var egressRelayCmd = &cobra.Command{
	Use:   "egress-relay",
	Short: "Bridge a box to a host-reachable SOCKS proxy (egress via client, #808)",
	Long: `Run a source-restricted TCP relay that lets a box egress through a
host-reachable upstream — typically the operator's SOCKS proxy reachable from
this host (e.g. over Tailscale). This is the host-side ("Phase 2a") piece of
"egress via client".

Why it's needed: a box runs in its own network namespace and can reach the
host's bridge gateway, but not a host-side ssh -R listener (host loopback) or an
off-box network directly. Bind --listen on a bridge-gateway address the box can
reach; the relay forwards to --upstream and accepts ONLY --allow source IPs (the
target box), which is the multi-tenant boundary. The box's apps point at the
relay as their SOCKS proxy (the SOCKS handshake passes straight through).

Example (box 10.100.0.156, bridge gw 10.100.0.1, operator SOCKS on a tailnet IP):

  containarium egress-relay \
    --listen 10.100.0.1:18080 \
    --upstream 100.124.9.5:1080 \
    --allow 10.100.0.156

  # then inside the box:  curl --proxy socks5h://10.100.0.1:18080 https://ifconfig.me
  # (or Chrome --proxy-server=socks5://10.100.0.1:18080)

Runs in the foreground until interrupted.`,
	RunE: runEgressRelay,
}

func init() {
	rootCmd.AddCommand(egressRelayCmd)
	egressRelayCmd.Flags().StringVar(&egressRelayListen, "listen", "", "host bind address the box can reach, e.g. 10.100.0.1:18080 (required)")
	egressRelayCmd.Flags().StringVar(&egressRelayUpstream, "upstream", "", "host-reachable SOCKS proxy to forward to, e.g. 100.124.9.5:1080 (required)")
	egressRelayCmd.Flags().StringArrayVar(&egressRelayAllow, "allow", nil, "permitted source IP or CIDR (the target box); repeatable; required (empty = deny all)")
}

func runEgressRelay(cmd *cobra.Command, args []string) error {
	if egressRelayListen == "" || egressRelayUpstream == "" {
		return fmt.Errorf("--listen and --upstream are required")
	}
	if len(egressRelayAllow) == 0 {
		return fmt.Errorf("--allow is required (a relay with no allowed source forwards for no one)")
	}

	r, err := egressproxy.New(egressRelayListen, egressRelayUpstream, egressRelayAllow, log.Printf)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return r.Serve(ctx)
}
