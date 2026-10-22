package cmd

import (
	"fmt"
	"io"
	"strings"

	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

// toolAccessLevelNames are the CLI spellings of the levels a caller may set,
// in increasing order of what an unattended run is allowed to do.
var toolAccessLevelNames = []struct {
	name  string
	level pb.ToolAccessLevel
}{
	{"none", pb.ToolAccessLevel_TOOL_ACCESS_LEVEL_NONE},
	{"build-tools", pb.ToolAccessLevel_TOOL_ACCESS_LEVEL_BUILD_TOOLS},
	{"full-sudo", pb.ToolAccessLevel_TOOL_ACCESS_LEVEL_FULL_SUDO},
}

const toolAccessLevelList = "none, build-tools, full-sudo"

// parseToolAccessLevel accepts the CLI spelling case-insensitively, with
// underscores treated as hyphens (so the proto-style BUILD_TOOLS also works).
func parseToolAccessLevel(s string) (pb.ToolAccessLevel, error) {
	norm := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(s)), "_", "-")
	for _, l := range toolAccessLevelNames {
		if l.name == norm {
			return l.level, nil
		}
	}
	return pb.ToolAccessLevel_TOOL_ACCESS_LEVEL_UNSPECIFIED, fmt.Errorf("invalid tool-access level %q (expected one of: %s)", s, toolAccessLevelList)
}

// toolAccessLevelName is the CLI spelling for a level. UNSPECIFIED (which the
// REST gateway sends for a zero enum) reads as "none", matching the daemon.
func toolAccessLevelName(l pb.ToolAccessLevel) string {
	for _, n := range toolAccessLevelNames {
		if n.level == l {
			return n.name
		}
	}
	return "none"
}

// toolAccessAPI is the slice of the daemon client these verbs use; both the
// gRPC and HTTP clients satisfy it.
type toolAccessAPI interface {
	GetToolAccessLevel(username string) (*pb.GetToolAccessLevelResponse, error)
	SetToolAccessLevel(username string, level pb.ToolAccessLevel) (*pb.SetToolAccessLevelResponse, error)
}

var toolAccessCmd = &cobra.Command{
	Use:   "tool-access",
	Short: "Show or set a box's tool-access level for unattended agent runs",
	Long: `Show or set the tool-access level that bounds what an unattended
(headless) coding-agent run may do on a box.

Levels:
  none         (default) nothing that needs approval
  build-tools  the platform's managed build/test toolchains
  full-sudo    unrestricted passwordless sudo; an explicit per-box choice

This command records the level. Applying it on the box (the agent's
allow list and sudoers) is not wired up yet, so changing the level does
not yet change what a run can do.

Examples:
  containarium tool-access get alice
  containarium tool-access set alice build-tools
  containarium tool-access set alice none`,
}

var toolAccessGetCmd = &cobra.Command{
	Use:   "get <username>",
	Short: "Show a box's tool-access level",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		api, closeFn, err := openToolAccessAPI()
		if err != nil {
			return err
		}
		defer closeFn()
		return runToolAccessGet(cmd.OutOrStdout(), api, args[0])
	},
}

var toolAccessSetCmd = &cobra.Command{
	Use:   "set <username> <level>",
	Short: "Set a box's tool-access level (" + toolAccessLevelList + ")",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Validate before dialing the daemon.
		if _, err := parseToolAccessLevel(args[1]); err != nil {
			return err
		}
		api, closeFn, err := openToolAccessAPI()
		if err != nil {
			return err
		}
		defer closeFn()
		return runToolAccessSet(cmd.OutOrStdout(), api, args[0], args[1])
	},
}

func init() {
	rootCmd.AddCommand(toolAccessCmd)
	toolAccessCmd.AddCommand(toolAccessGetCmd)
	toolAccessCmd.AddCommand(toolAccessSetCmd)
}

// openToolAccessAPI dials the daemon over whichever transport the global
// flags select, mirroring the ttl verbs.
func openToolAccessAPI() (toolAccessAPI, func(), error) {
	if serverAddr == "" {
		return nil, nil, fmt.Errorf("--server is required (tool-access levels are stored by the daemon)")
	}
	if httpMode {
		hc, err := client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return nil, nil, err
		}
		return hc, func() { _ = hc.Close() }, nil
	}
	gc, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return nil, nil, err
	}
	return gc, func() { _ = gc.Close() }, nil
}

func runToolAccessGet(w io.Writer, api toolAccessAPI, username string) error {
	resp, err := api.GetToolAccessLevel(username)
	if err != nil {
		return fmt.Errorf("failed to get tool-access level: %w", err)
	}
	_, err = fmt.Fprintf(w, "%s: %s\n", username, toolAccessLevelName(resp.GetLevel()))
	return err
}

func runToolAccessSet(w io.Writer, api toolAccessAPI, username, levelArg string) error {
	level, err := parseToolAccessLevel(levelArg)
	if err != nil {
		return err
	}
	resp, err := api.SetToolAccessLevel(username, level)
	if err != nil {
		return fmt.Errorf("failed to set tool-access level: %w", err)
	}
	name := toolAccessLevelName(resp.GetLevel())
	if _, err := fmt.Fprintf(w, "✓ tool-access level for %s recorded as %s (not yet applied on the box)\n", username, name); err != nil {
		return err
	}
	if resp.GetLevel() == pb.ToolAccessLevel_TOOL_ACCESS_LEVEL_FULL_SUDO {
		_, err = fmt.Fprintln(w, "  full-sudo means unrestricted sudo for unattended runs; software installed that way is yours to maintain.")
	}
	return err
}
