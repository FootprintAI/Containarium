package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	passthroughRouteRemovePort     int
	passthroughRouteRemoveProtocol string
)

var passthroughRouteRemoveCmd = &cobra.Command{
	Use:   "remove",
	Short: "Remove a daemon-level TCP/UDP passthrough route",
	Long: `Remove a TCP/UDP passthrough route from the Containarium daemon by its
external port and protocol.

Examples:
  # Remove a TCP passthrough route
  containarium passthrough-route remove --port 9443 --server <host:port>

  # Remove a UDP passthrough route
  containarium passthrough-route remove --port 53 --protocol udp --server <host:port>`,
	Aliases: []string{"rm", "delete"},
	RunE:    runPassthroughRouteRemove,
}

func init() {
	passthroughRouteCmd.AddCommand(passthroughRouteRemoveCmd)

	passthroughRouteRemoveCmd.Flags().IntVar(&passthroughRouteRemovePort, "port", 0, "External port to remove (required)")
	passthroughRouteRemoveCmd.Flags().StringVar(&passthroughRouteRemoveProtocol, "protocol", "tcp", "Protocol: tcp or udp")

	_ = passthroughRouteRemoveCmd.MarkFlagRequired("port")
}

func runPassthroughRouteRemove(cmd *cobra.Command, args []string) error {
	if serverAddr == "" {
		return fmt.Errorf("--server is required")
	}
	if passthroughRouteRemovePort <= 0 || passthroughRouteRemovePort > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	protocol, err := parsePassthroughRouteProtocol(passthroughRouteRemoveProtocol)
	if err != nil {
		return err
	}

	apiClient, err := newRouteClient()
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer func() { _ = apiClient.Close() }()

	if err := apiClient.DeletePassthroughRoute(int32(passthroughRouteRemovePort), protocol); err != nil {
		return fmt.Errorf("failed to remove passthrough route: %w", err)
	}

	fmt.Printf("Passthrough route removed: %s:%d\n", passthroughRouteRemoveProtocol, passthroughRouteRemovePort)

	return nil
}
