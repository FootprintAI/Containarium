package cmd

import (
	"context"
	"fmt"

	"github.com/footprintai/containarium/internal/client"
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

	grpcClient, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer func() { _ = grpcClient.Close() }()

	res, err := expose.Run(context.Background(), &grpcExposeAdapter{c: grpcClient}, expose.Options{
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

// grpcExposeAdapter implements expose.APIClient against the gRPC client.
// LookupContainer is implemented via ListContainers + linear scan because
// the gRPC surface doesn't expose a "by-name" lookup; this is fine for
// the typical scale (tens of containers) and saves us a new RPC.
type grpcExposeAdapter struct{ c *client.GRPCClient }

func (a *grpcExposeAdapter) LookupContainer(_ context.Context, username string) (string, string, string, error) {
	containers, err := a.c.ListContainers()
	if err != nil {
		return "", "", "", err
	}
	for _, ci := range containers {
		// Container names follow the "<username>-container" convention
		// per internal/cmd/list.go; accept either the full name or the
		// bare username for ergonomic ergonomics.
		if ci.Name == username || ci.Name == username+"-container" {
			return ci.Name, ci.IPAddress, ci.State, nil
		}
	}
	return "", "", "", fmt.Errorf("container %q not found", username)
}

func (a *grpcExposeAdapter) CreateRoute(_ context.Context, p expose.AddRouteParams) (*expose.RouteResult, error) {
	route, err := a.c.AddRoute(p.Domain, p.TargetIP, p.TargetPort, p.ContainerName, p.Description)
	if err != nil {
		return nil, err
	}
	// The proto's ProxyRoute response doesn't echo ContainerName or
	// the request's Domain field (it carries FullDomain); fall back to
	// what the caller asked for so the result is always populated.
	domain := route.FullDomain
	if domain == "" {
		domain = p.Domain
	}
	return &expose.RouteResult{
		Domain:        domain,
		ContainerName: p.ContainerName,
		ContainerIP:   route.ContainerIp,
		Port:          route.Port,
	}, nil
}
