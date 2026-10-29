package cmd

import (
	"fmt"
	"strings"

	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/internal/toolaccess"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

// The tool-access verbs record, per box, what a platform-started (unattended,
// headless) agent run may do (#2944), via the SetContainerToolAccess RPC
// (POST /v1/containers/{name}/tool-access), which stamps
// user.containarium.tool_access on the Incus container. Only platform-started
// runs are governed; the owner's own login and `containarium code run` over SSH
// are unaffected. The level is read back from the container view (like
// `ttl get`), so there is no separate get RPC.
//
// This change only RECORDS the level; applying it to the run path lands
// separately, so setting one has no effect on a run yet.

var toolAccessCmd = &cobra.Command{
	Use:   "tool-access",
	Short: "Record the tool-access level for platform-started runs on a box",
}

var toolAccessSetCmd = &cobra.Command{
	Use:   "set <username> <none|build-tools|full-sudo>",
	Short: "Record a box's tool-access level",
	Long: `Record what a platform-started (unattended) agent run on this box may do (#2944):

  none         nothing that needs approval
  build-tools  the platform-managed build and test toolchains
  full-sudo    passwordless sudo for the unprivileged run user (an explicit,
               per-box choice; software installed this way is the owner's to maintain)

Only platform-started runs are governed; the owner's own login is unaffected.
Use 'containarium tool-access clear' to remove a recorded level.

Examples:
  containarium tool-access set alice build-tools
  containarium tool-access get alice`,
	Args: cobra.ExactArgs(2),
	RunE: runToolAccessSet,
}

var toolAccessClearCmd = &cobra.Command{
	Use:   "clear <username>",
	Short: "Remove a box's recorded tool-access level",
	Args:  cobra.ExactArgs(1),
	RunE:  runToolAccessClear,
}

var toolAccessGetCmd = &cobra.Command{
	Use:   "get <username>",
	Short: "Show a box's recorded tool-access level",
	Args:  cobra.ExactArgs(1),
	RunE:  runToolAccessGet,
}

var toolAccessRunUserCmd = &cobra.Command{
	Use:   "run-user <username>",
	Short: "Show whether a box's run user is signed in",
	Long: `Show whether the unprivileged run user (#2944) on a box has a usable agent
sign-in: the same check 'StartBoxRun' applies before it refuses a platform run,
without starting one (#3274). Prints the credential source's name only, never a
value, and does not create the run user.

States: interactive and api-key mean a run would proceed; none means the run
user has never signed in (or does not exist yet); expired means it must sign in
again. A box with no tool-access level recorded runs as its owner, so there is
no run user to check.

Examples:
  containarium tool-access run-user alice`,
	Args: cobra.ExactArgs(1),
	RunE: runToolAccessRunUser,
}

func init() {
	toolAccessCmd.AddCommand(toolAccessSetCmd, toolAccessClearCmd, toolAccessGetCmd, toolAccessRunUserCmd)
	rootCmd.AddCommand(toolAccessCmd)
}

// parseToolAccess maps a CLI level name to the proto enum. UNSPECIFIED is not
// a level a caller names; clearing has its own verb.
func parseToolAccess(s string) (pb.BoxToolAccess, error) {
	switch strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), "_", "-")) {
	case "none":
		return pb.BoxToolAccess_BOX_TOOL_ACCESS_NONE, nil
	case "build-tools":
		return pb.BoxToolAccess_BOX_TOOL_ACCESS_BUILD_TOOLS, nil
	case "full-sudo":
		return pb.BoxToolAccess_BOX_TOOL_ACCESS_FULL_SUDO, nil
	}
	return pb.BoxToolAccess_BOX_TOOL_ACCESS_UNSPECIFIED, fmt.Errorf("unknown level %q (want none, build-tools or full-sudo)", s)
}

// toolAccessName is the CLI spelling of a level, "(none recorded)" for UNSPECIFIED.
func toolAccessName(a pb.BoxToolAccess) string {
	switch a {
	case pb.BoxToolAccess_BOX_TOOL_ACCESS_NONE:
		return "none"
	case pb.BoxToolAccess_BOX_TOOL_ACCESS_BUILD_TOOLS:
		return "build-tools"
	case pb.BoxToolAccess_BOX_TOOL_ACCESS_FULL_SUDO:
		return "full-sudo"
	}
	return "(none recorded)"
}

func runToolAccessSet(cmd *cobra.Command, args []string) error {
	level, err := parseToolAccess(args[1])
	if err != nil {
		return err
	}
	return setToolAccess(args[0], level, fmt.Sprintf("✓ %s: tool access recorded as %s (for platform-started runs only)\n", args[0], toolAccessName(level)))
}

func runToolAccessClear(cmd *cobra.Command, args []string) error {
	return setToolAccess(args[0], pb.BoxToolAccess_BOX_TOOL_ACCESS_UNSPECIFIED, fmt.Sprintf("✓ %s: recorded tool access cleared\n", args[0]))
}

func setToolAccess(username string, level pb.BoxToolAccess, okMsg string) error {
	if serverAddr == "" {
		return fmt.Errorf("--server is required (tool access is a server-side feature)")
	}
	err := setContainerToolAccessViaServer(username, level)
	if isUnimplemented(err) {
		fmt.Printf("⚠ Tool access not yet supported by this server (daemon does not implement SetContainerToolAccess); nothing changed on %s.\n", username)
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to set tool access on %s: %w", username, err)
	}
	fmt.Print(okMsg)
	return nil
}

func runToolAccessGet(cmd *cobra.Command, args []string) error {
	username := args[0]
	if serverAddr == "" {
		return fmt.Errorf("--server is required (tool access is a server-side feature)")
	}
	var info *incus.ContainerInfo
	var err error
	if httpMode {
		hc, e := client.NewHTTPClient(serverAddr, authToken)
		if e != nil {
			return e
		}
		defer func() { _ = hc.Close() }()
		info, err = hc.GetContainer(username)
	} else {
		gc, e := client.NewGRPCClient(serverAddr, certsDir, insecure)
		if e != nil {
			return e
		}
		defer func() { _ = gc.Close() }()
		info, err = gc.GetContainer(username)
	}
	if err != nil {
		return fmt.Errorf("failed to get %s: %w", username, err)
	}
	level := pb.BoxToolAccess_BOX_TOOL_ACCESS_UNSPECIFIED
	if info != nil {
		level = toolaccess.FromConfig(info.ToolAccess)
	}
	fmt.Printf("%s: %s\n", username, toolAccessName(level))
	return nil
}

// setContainerToolAccessViaServer dispatches over grpc or http per the global
// httpMode flag, mirroring setContainerDeletePolicyViaServer.
func setContainerToolAccessViaServer(username string, level pb.BoxToolAccess) error {
	if httpMode {
		hc, err := client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return err
		}
		defer func() { _ = hc.Close() }()
		_, err = hc.SetContainerToolAccess(username, level)
		return err
	}
	gc, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return err
	}
	defer func() { _ = gc.Close() }()
	_, err = gc.SetContainerToolAccess(username, level)
	return err
}

func runToolAccessRunUser(cmd *cobra.Command, args []string) error {
	username := args[0]
	if serverAddr == "" {
		return fmt.Errorf("--server is required (tool access is a server-side feature)")
	}
	var resp *pb.GetBoxRunUserStatusResponse
	var err error
	if httpMode {
		hc, e := client.NewHTTPClient(serverAddr, authToken)
		if e != nil {
			return e
		}
		defer func() { _ = hc.Close() }()
		resp, err = hc.GetBoxRunUserStatus(username)
	} else {
		gc, e := client.NewGRPCClient(serverAddr, certsDir, insecure)
		if e != nil {
			return e
		}
		defer func() { _ = gc.Close() }()
		resp, err = gc.GetBoxRunUserStatus(username)
	}
	if isUnimplemented(err) {
		fmt.Printf("⚠ Run-user status not yet supported by this server (daemon does not implement GetBoxRunUserStatus).\n")
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to get the run user status of %s: %w", username, err)
	}
	fmt.Print(renderRunUserStatus(username, resp))
	return nil
}

// renderRunUserStatus is the human form of the run-user status: one line, the
// credential source's name only.
func renderRunUserStatus(username string, r *pb.GetBoxRunUserStatusResponse) string {
	if !r.GetToolAccessRecorded() {
		return fmt.Sprintf("%s: no tool-access level recorded; platform runs use the owner's identity (no run user)\n", username)
	}
	if !r.GetRunUserExists() {
		return fmt.Sprintf("%s: run user %s does not exist yet (created by the first platform run); sign-in: %s\n", username, r.GetRunUser(), credentialSourceDisplay(r.GetState()))
	}
	return fmt.Sprintf("%s: run user %s sign-in: %s\n", username, r.GetRunUser(), credentialSourceDisplay(r.GetState()))
}
