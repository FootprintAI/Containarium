package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// `containarium compose <verb>` — daemon-side driver for the
// compose-autostart ops that live as MCP tools inside agent-box.
//
// CLI-first per CLAUDE.md: every operation an agent can do via the
// platform MCP, a human can do via this verb. The MCP tools in
// internal/mcp/ delegate to the same underlying ComposeAutostartService
// client below.

var composeCmd = &cobra.Command{
	Use:   "compose",
	Short: "Drive compose-autostart inside a tenant's container",
	Long: `Operator-side commands for the systemd-user compose-autostart units
that survive reboots. Mirrors the in-box agent-box MCP tools.

All four subcommands take <username> as their first positional and
exec 'agent-box compose <verb>' inside that tenant's LXC via the
daemon.`,
}

// ---- discover ------------------------------------------------------

var (
	composeDiscoverRoot     string
	composeDiscoverMaxDepth int
	composeDiscoverSkip     []string
	composeDiscoverNoSkip   bool
)

var composeDiscoverCmd = &cobra.Command{
	Use:   "discover <username>",
	Short: "List compose stacks discovered inside the tenant's LXC",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, close, err := newComposeClient()
		if err != nil {
			return err
		}
		defer close()
		resp, err := c.Discover(context.Background(), &pb.DiscoverRequest{
			Username: args[0],
			Root:     composeDiscoverRoot,
			MaxDepth: int32(composeDiscoverMaxDepth),
			Skip:     composeDiscoverSkip,
			NoSkip:   composeDiscoverNoSkip,
		})
		if err != nil {
			return err
		}
		return printJSON(resp)
	},
}

// ---- enable --------------------------------------------------------

var (
	composeEnableDir   string
	composeEnableForce bool
)

var composeEnableCmd = &cobra.Command{
	Use:   "enable <username>",
	Short: "Install + enable the systemd-user autostart unit for one compose dir",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, close, err := newComposeClient()
		if err != nil {
			return err
		}
		defer close()
		resp, err := c.Enable(context.Background(), &pb.EnableRequest{
			Username: args[0],
			Dir:      composeEnableDir,
			Force:    composeEnableForce,
		})
		if err != nil {
			return err
		}
		return printJSON(resp)
	},
}

// ---- disable -------------------------------------------------------

var composeDisableDir string

var composeDisableCmd = &cobra.Command{
	Use:   "disable <username>",
	Short: "Stop + disable the systemd-user autostart unit for one compose dir",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, close, err := newComposeClient()
		if err != nil {
			return err
		}
		defer close()
		resp, err := c.Disable(context.Background(), &pb.DisableRequest{
			Username: args[0],
			Dir:      composeDisableDir,
		})
		if err != nil {
			return err
		}
		return printJSON(resp)
	},
}

// ---- status --------------------------------------------------------

var composeStatusDir string

var composeStatusCmd = &cobra.Command{
	Use:   "status <username>",
	Short: "Show the autostart + service-count status of one compose dir",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, close, err := newComposeClient()
		if err != nil {
			return err
		}
		defer close()
		resp, err := c.Status(context.Background(), &pb.StatusRequest{
			Username: args[0],
			Dir:      composeStatusDir,
		})
		if err != nil {
			return err
		}
		return printJSON(resp)
	},
}

// ---- shared helpers ------------------------------------------------

func init() {
	rootCmd.AddCommand(composeCmd)

	composeCmd.AddCommand(composeDiscoverCmd, composeEnableCmd, composeDisableCmd, composeStatusCmd)

	composeDiscoverCmd.Flags().StringVar(&composeDiscoverRoot, "root", "",
		"Root dir to walk inside the LXC (default: tenant's $HOME)")
	composeDiscoverCmd.Flags().IntVar(&composeDiscoverMaxDepth, "max-depth", 0,
		"Max directory depth (0 = use agent-box default)")
	composeDiscoverCmd.Flags().StringSliceVar(&composeDiscoverSkip, "skip", nil,
		"Extra directory name to skip (repeatable)")
	composeDiscoverCmd.Flags().BoolVar(&composeDiscoverNoSkip, "no-skip", false,
		"Bypass the default skip set (node_modules, .git, …)")

	composeEnableCmd.Flags().StringVar(&composeEnableDir, "dir", "", "Compose directory (required)")
	composeEnableCmd.Flags().BoolVar(&composeEnableForce, "force", false,
		"Re-install the unit even if already enabled")
	_ = composeEnableCmd.MarkFlagRequired("dir")

	composeDisableCmd.Flags().StringVar(&composeDisableDir, "dir", "", "Compose directory (required)")
	_ = composeDisableCmd.MarkFlagRequired("dir")

	composeStatusCmd.Flags().StringVar(&composeStatusDir, "dir", "", "Compose directory (required)")
	_ = composeStatusCmd.MarkFlagRequired("dir")
}

// newComposeClient dials the daemon's gRPC server and returns a typed
// ComposeAutostartService client + a close func the caller MUST defer.
// Centralizes the --server / --insecure plumbing so the four
// subcommands stay focused on their own flags.
func newComposeClient() (pb.ComposeAutostartServiceClient, func(), error) {
	if serverAddr == "" {
		return nil, nil, fmt.Errorf("--server is required")
	}
	grpcClient, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return nil, nil, fmt.Errorf("connect to %s: %w", serverAddr, err)
	}
	c := pb.NewComposeAutostartServiceClient(grpcClient.Conn())
	return c, func() { _ = grpcClient.Close() }, nil
}

// printJSON marshals the response with stable indentation to stdout.
// Used uniformly so callers (humans + scripts) get the same shape
// regardless of which verb ran.
func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
