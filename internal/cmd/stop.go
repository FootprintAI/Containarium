package cmd

import (
	"fmt"
	"io"

	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

var (
	stopHold  bool
	stopForce bool
)

var stopCmd = &cobra.Command{
	Use:   "stop <box>",
	Short: "Stop a box; --hold keeps it stopped until it is started explicitly",
	Long: `Stop a box.

With --hold the box is put on an operator hold: the daemon will not start it
on its own (not when the host or Incus restarts, not for an HTTP request to
one of its routes, not for a skill or crew run) until it is started
explicitly by an operator (admin role) with 'containarium wake <box>', which
lifts the hold; a tenant token cannot start or release a held box. The hold is
stored on the box, so it survives a daemon or host restart. --hold also works
on a box that is already stopped.`,
	Args: cobra.ExactArgs(1),
	RunE: runStop,
}

func init() {
	rootCmd.AddCommand(stopCmd)
	stopCmd.Flags().BoolVar(&stopHold, "hold", false, "keep the box stopped until an explicit start (survives daemon and host restarts)")
	stopCmd.Flags().BoolVar(&stopForce, "force", false, "kill the box instead of a graceful shutdown")
}

// containerStopper is the client call the stop command needs; the gRPC and
// HTTP clients both provide it.
type containerStopper interface {
	StopContainer(username string, force, hold bool) (*pb.StopContainerResponse, error)
}

func runStop(cmd *cobra.Command, args []string) error {
	if serverAddr == "" {
		return fmt.Errorf("--server is required")
	}
	if httpMode {
		httpClient, err := client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return err
		}
		defer func() { _ = httpClient.Close() }()
		return stopBox(cmd.OutOrStdout(), httpClient, args[0], stopForce, stopHold)
	}
	grpcClient, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return err
	}
	defer func() { _ = grpcClient.Close() }()
	return stopBox(cmd.OutOrStdout(), grpcClient, args[0], stopForce, stopHold)
}

// stopBox stops the box and, with hold, checks that the daemon reports it
// held: a daemon that ignored the field must not read as a successful hold.
func stopBox(w io.Writer, c containerStopper, username string, force, hold bool) error {
	resp, err := c.StopContainer(username, force, hold)
	if err != nil {
		return err
	}
	if !hold {
		fmt.Fprintf(w, "✓ Box %s is stopped (%s)\n", escapeControl(username), escapeControl(resp.GetMessage()))
		return nil
	}
	if !resp.GetContainer().GetHeld() {
		return fmt.Errorf("the daemon did not report box %s as held (%s); it may not support --hold, or the box is on a backend that does not", username, resp.GetMessage())
	}
	fmt.Fprintf(w, "✓ Box %s is stopped and held (%s)\n  It stays stopped until: containarium wake %s\n",
		escapeControl(username), escapeControl(resp.GetMessage()), escapeControl(username))
	return nil
}
