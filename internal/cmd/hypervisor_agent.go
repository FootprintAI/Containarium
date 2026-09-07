//go:build !windows

package cmd

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/footprintai/containarium/internal/hypervisor"
	"github.com/footprintai/containarium/internal/sentinel"
	"github.com/spf13/cobra"
)

var (
	hvSentinelAddr string
	hvTunnelToken  string
	hvSpotID       string
	hvConsolePort  int
	hvConsoleToken string
	hvVBoxDir      string
)

var hypervisorAgentCmd = &cobra.Command{
	Use:   "hypervisor-agent",
	Short: "Serve console access to VirtualBox-hosted BYOC guests from their physical host",
	Long: `Run on the PHYSICAL machine hosting VirtualBox VMs — not inside any guest.

A guest hung at BIOS POST, in its bootloader, or panicked before its own
network stack comes up has nothing running that could serve SSH or the
tunnel client's own port-forwards (both live inside the guest). This agent
runs on the hypervisor host instead, dialing outbound to the sentinel with
its own identity via the existing tunnel client (unmodified — this is one
more advertised port, not a protocol change), and serves a small
console-multiplex protocol on that port: present a token and a guest name,
get back a raw byte relay to that guest's serial console.

Reaching this agent from outside the sentinel's own host requires the
sentinel-side console router (see FootprintAI/Containarium#1756) — not yet
built. This command is independently useful without it for anyone with
direct network access to the sentinel.

The guest's serial port must already be redirected to a UNIX socket at
--vbox-console-dir/<guest-name>.sock — VirtualBox only accepts UART
changes while the VM is powered off:

  VBoxManage modifyvm <vm> --uart1 0x3F8 4 --uartmode1 server /path/to.sock

Examples:
  containarium hypervisor-agent --sentinel-addr sentinel.example.com:9443 \
                                --token SECRET \
                                --spot-id lab-vbox-host-1 \
                                --console-token CONSOLE_SECRET \
                                --vbox-console-dir /var/lib/containarium/consoles`,
	RunE: runHypervisorAgent,
}

func init() {
	rootCmd.AddCommand(hypervisorAgentCmd)

	hypervisorAgentCmd.Flags().StringVar(&hvSentinelAddr, "sentinel-addr", "", "Sentinel address (host:port) to connect to (required)")
	hypervisorAgentCmd.Flags().StringVar(&hvTunnelToken, "token", "", "Pre-shared tunnel registration token (or CONTAINARIUM_TUNNEL_TOKEN env) — authorizes joining the tunnel, distinct from --console-token")
	hypervisorAgentCmd.Flags().StringVar(&hvSpotID, "spot-id", "", "Unique identifier for this hypervisor host (required) — its own identity, not any guest's")
	hypervisorAgentCmd.Flags().IntVar(&hvConsolePort, "console-port", 8082, "Local port to advertise through the tunnel and listen on for console requests")
	hypervisorAgentCmd.Flags().StringVar(&hvConsoleToken, "console-token", "", "Pre-shared token a caller must present to open a console (or CONTAINARIUM_CONSOLE_TOKEN env) — a separate, narrower credential from --token")
	hypervisorAgentCmd.Flags().StringVar(&hvVBoxDir, "vbox-console-dir", "", "Base directory containing one <guest-name>.sock UNIX socket per VirtualBox guest, set up via VBoxManage --uartmode1 server (required)")
}

func runHypervisorAgent(cmd *cobra.Command, args []string) error {
	if hvSentinelAddr == "" {
		return fmt.Errorf("--sentinel-addr is required")
	}
	if hvSpotID == "" {
		return fmt.Errorf("--spot-id is required")
	}
	if hvVBoxDir == "" {
		return fmt.Errorf("--vbox-console-dir is required")
	}

	tunnelToken := hvTunnelToken
	if tunnelToken == "" {
		tunnelToken = os.Getenv("CONTAINARIUM_TUNNEL_TOKEN")
	}
	if tunnelToken == "" {
		return fmt.Errorf("--token or CONTAINARIUM_TUNNEL_TOKEN is required")
	}

	consoleToken := hvConsoleToken
	if consoleToken == "" {
		consoleToken = os.Getenv("CONTAINARIUM_CONSOLE_TOKEN")
	}
	if consoleToken == "" {
		return fmt.Errorf("--console-token or CONTAINARIUM_CONSOLE_TOKEN is required")
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", hvConsolePort))
	if err != nil {
		return fmt.Errorf("failed to listen on 127.0.0.1:%d: %w", hvConsolePort, err)
	}
	defer func() { _ = ln.Close() }()

	agent := &hypervisor.Agent{
		Token:    consoleToken,
		Provider: hypervisor.NewVirtualBoxProvider(hvVBoxDir),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		log.Printf("[hypervisor-agent] received signal: %v", sig)
		cancel()
		_ = ln.Close()
	}()

	go func() {
		if err := agent.Serve(ctx, ln); err != nil {
			log.Printf("[hypervisor-agent] serve error: %v", err)
		}
	}()

	tunnel := &sentinel.TunnelClient{
		SentinelAddr: hvSentinelAddr,
		Token:        tunnelToken,
		SpotID:       hvSpotID,
		Ports:        []int{hvConsolePort},
	}

	log.Printf("[hypervisor-agent] connecting to sentinel at %s as %q, serving consoles from %s on port %d", hvSentinelAddr, hvSpotID, hvVBoxDir, hvConsolePort)
	return tunnel.Run(ctx)
}
