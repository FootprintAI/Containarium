package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	passthroughRouteAddPort        int
	passthroughRouteAddTargetIP    string
	passthroughRouteAddTargetPort  int
	passthroughRouteAddProtocol    string
	passthroughRouteAddContainer   string
	passthroughRouteAddDescription string
)

var passthroughRouteAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a daemon-level TCP/UDP passthrough route",
	Long: `Add a new TCP/UDP passthrough route on the Containarium daemon.

Forwards an external port on the daemon's host directly to a container's
IP:port without TLS termination.

Examples:
  # Forward port 50051 to a container
  containarium passthrough-route add --port 50051 --target-ip 10.0.3.150 --target-port 50051 --server <host:port>

  # Forward external port 9443 to container port 50051, with metadata
  containarium passthrough-route add --port 9443 --target-ip 10.0.3.150 --target-port 50051 \
    --container myapp-container --description "mTLS gRPC" --server <host:port>

  # Add a UDP passthrough
  containarium passthrough-route add --port 53 --target-ip 10.0.3.150 --target-port 53 --protocol udp --server <host:port>`,
	RunE: runPassthroughRouteAdd,
}

func init() {
	passthroughRouteCmd.AddCommand(passthroughRouteAddCmd)

	passthroughRouteAddCmd.Flags().IntVar(&passthroughRouteAddPort, "port", 0, "External port to expose (required)")
	passthroughRouteAddCmd.Flags().StringVar(&passthroughRouteAddTargetIP, "target-ip", "", "Target container IP address (required)")
	passthroughRouteAddCmd.Flags().IntVar(&passthroughRouteAddTargetPort, "target-port", 0, "Target port on the container (required)")
	passthroughRouteAddCmd.Flags().StringVar(&passthroughRouteAddProtocol, "protocol", "tcp", "Protocol: tcp or udp")
	passthroughRouteAddCmd.Flags().StringVarP(&passthroughRouteAddContainer, "container", "c", "", "Associated container name (optional)")
	passthroughRouteAddCmd.Flags().StringVarP(&passthroughRouteAddDescription, "description", "d", "", "Route description (optional)")

	_ = passthroughRouteAddCmd.MarkFlagRequired("port")
	_ = passthroughRouteAddCmd.MarkFlagRequired("target-ip")
	_ = passthroughRouteAddCmd.MarkFlagRequired("target-port")
}

func runPassthroughRouteAdd(cmd *cobra.Command, args []string) error {
	if serverAddr == "" {
		return fmt.Errorf("--server is required")
	}
	if passthroughRouteAddPort <= 0 || passthroughRouteAddPort > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	if passthroughRouteAddTargetPort <= 0 || passthroughRouteAddTargetPort > 65535 {
		return fmt.Errorf("target-port must be between 1 and 65535")
	}
	if passthroughRouteAddTargetIP == "" {
		return fmt.Errorf("target-ip is required")
	}
	protocol, err := parsePassthroughRouteProtocol(passthroughRouteAddProtocol)
	if err != nil {
		return err
	}

	apiClient, err := newRouteClient()
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer func() { _ = apiClient.Close() }()

	route, err := apiClient.AddPassthroughRoute(
		int32(passthroughRouteAddPort),
		int32(passthroughRouteAddTargetPort),
		passthroughRouteAddTargetIP,
		protocol,
		passthroughRouteAddContainer,
		passthroughRouteAddDescription,
	)
	if err != nil {
		return fmt.Errorf("failed to add passthrough route: %w", err)
	}

	fmt.Printf("Passthrough route added successfully!\n")
	fmt.Printf("  Protocol: %s\n", passthroughRouteAddProtocol)
	fmt.Printf("  External: %d\n", route.GetExternalPort())
	fmt.Printf("  Target:   %s:%d\n", route.GetTargetIp(), route.GetTargetPort())
	if passthroughRouteAddContainer != "" {
		fmt.Printf("  Container: %s\n", passthroughRouteAddContainer)
	}

	return nil
}
