package cmd

import (
	"context"
	"fmt"

	"github.com/footprintai/containarium/pkg/core/expose"
	"github.com/spf13/cobra"
)

var (
	exposePortPort        int
	exposePortDomain      string
	exposePortDescription string
)

var exposePortCmd = &cobra.Command{
	Use:   "expose-port <username>",
	Short: "Expose a container's port on a public hostname",
	Long: `Resolve a container's current LAN IP and register a domain → IP:port
mapping in the sentinel reverse proxy. After this completes,
https://<domain>/ reaches the container.

This is a friendlier wrapper around 'containarium route add' that
auto-resolves the container's IP from its name. Both this command and
the platform MCP's expose_port tool delegate to the same Go function
in pkg/core/expose so the behavior can never drift.

Example:
  containarium expose-port alice \
      --container-port 8080 \
      --domain blog.example.com \
      --server <host:port>`,
	Args: cobra.ExactArgs(1),
	RunE: runExposePort,
}

func init() {
	rootCmd.AddCommand(exposePortCmd)

	exposePortCmd.Flags().IntVar(&exposePortPort, "container-port", 0,
		"Port the app listens on inside the container (required)")
	exposePortCmd.Flags().StringVar(&exposePortDomain, "domain", "",
		"Public hostname to route from, e.g. blog.example.com (required)")
	exposePortCmd.Flags().StringVar(&exposePortDescription, "description", "",
		"Optional human-readable note (shown in 'route list')")

	_ = exposePortCmd.MarkFlagRequired("container-port")
	_ = exposePortCmd.MarkFlagRequired("domain")
}

func runExposePort(cmd *cobra.Command, args []string) error {
	if serverAddr == "" {
		return fmt.Errorf("--server is required")
	}

	apiClient, err := newRouteClient()
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer func() { _ = apiClient.Close() }()

	res, err := expose.Run(context.Background(), &exposeAdapter{c: apiClient}, expose.Options{
		Username:      args[0],
		ContainerPort: exposePortPort,
		Domain:        exposePortDomain,
		Description:   exposePortDescription,
	})
	if err != nil {
		return err
	}

	fmt.Printf("✓ Exposed %s:%d → %s\n", args[0], exposePortPort, res.Domain)
	fmt.Printf("  Domain:    %s\n", res.Domain)
	fmt.Printf("  Target:    %s:%d\n", res.ContainerIP, res.Port)
	if res.ContainerName != "" {
		fmt.Printf("  Container: %s\n", res.ContainerName)
	}
	if res.Message != "" {
		fmt.Printf("\n%s\n", res.Message)
	}
	fmt.Printf("\nNext: confirm DNS for %s points at the sentinel,\n", res.Domain)
	fmt.Printf("then `curl https://%s/` should reach the app.\n", res.Domain)
	return nil
}

// The expose.APIClient adapter (exposeAdapter) and transport selection
// (newRouteClient) live in route_client.go and are shared with the
// route add/list/delete verbs so all of them honor --http (#909).
