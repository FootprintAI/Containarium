package cmd

import (
	"fmt"

	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

// The protect/unprotect verbs set a container's delete policy (#284) via the
// SetContainerDeletePolicy RPC (POST /v1/containers/{name}/delete-policy),
// which stamps user.containarium.delete_policy on the Incus container — the
// exact key the daemon's ttlsweeper auto-reap and `containarium prune` consult
// to SKIP a box. Protecting a box guards it against an unattended "clean up
// leaked boxes" sweep taking out, say, a persistent CI runner; it does NOT
// block a deliberate `containarium delete` (that always succeeds).
//
// The current policy is read back via `containarium get` / `list` (the
// delete_policy field on the container view), so there is no separate "get"
// verb here — mirrors how `ttl get` reads ttl_expires_at off the container.
//
// A daemon too old to implement SetContainerDeletePolicy surfaces
// codes.Unimplemented (gRPC) / HTTP 404 mapped to Unimplemented (REST); the CLI
// degrades to a friendly no-op via isUnimplemented (shared with ttl.go) rather
// than failing.

var protectCmd = &cobra.Command{
	Use:   "protect <username>",
	Short: "Protect a container from automated/bulk deletion",
	Long: `Mark a container as protected (#284). A protected box is skipped by
the daemon's unattended deletion paths — the TTL sweeper's auto-reap and
'containarium prune' — so a "clean up leaked boxes" sweep can never take out
a box you want to keep (e.g. a persistent CI runner).

Protection does NOT block a deliberate single-box delete: 'containarium delete'
still removes a protected box. Use 'containarium unprotect' to clear it.

Examples:
  # Protect a long-lived runner from prune/auto-reap
  containarium protect ci-runner

  # Inspect the current policy (delete_policy field)
  containarium get ci-runner`,
	Args: cobra.ExactArgs(1),
	RunE: runProtect,
}

var unprotectCmd = &cobra.Command{
	Use:   "unprotect <username>",
	Short: "Clear a container's delete protection (back to the default)",
	Long: `Clear the protected delete policy on a container (#284), returning it
to the default — eligible for the TTL sweeper auto-reap and 'containarium prune'.

Examples:
  containarium unprotect ci-runner`,
	Args: cobra.ExactArgs(1),
	RunE: runUnprotect,
}

func init() {
	rootCmd.AddCommand(protectCmd)
	rootCmd.AddCommand(unprotectCmd)
}

func runProtect(cmd *cobra.Command, args []string) error {
	username := args[0]

	if serverAddr == "" {
		return fmt.Errorf("--server is required (delete policy is a server-side feature)")
	}

	err := setContainerDeletePolicyViaServer(username, pb.DeletePolicy_DELETE_POLICY_PROTECTED)
	if isUnimplemented(err) {
		fmt.Printf("⚠ Delete policy not yet supported by this server (daemon does not implement SetContainerDeletePolicy); %s is NOT protected.\n", username)
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to protect %s: %w", username, err)
	}

	fmt.Printf("✓ %s is now protected (skipped by auto-reap + prune; a deliberate delete still removes it)\n", username)
	return nil
}

func runUnprotect(cmd *cobra.Command, args []string) error {
	username := args[0]

	if serverAddr == "" {
		return fmt.Errorf("--server is required (delete policy is a server-side feature)")
	}

	err := setContainerDeletePolicyViaServer(username, pb.DeletePolicy_DELETE_POLICY_UNSPECIFIED)
	if isUnimplemented(err) {
		fmt.Printf("⚠ Delete policy not yet supported by this server (daemon does not implement SetContainerDeletePolicy); nothing to clear.\n")
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to unprotect %s: %w", username, err)
	}

	fmt.Printf("✓ %s is no longer protected (eligible for auto-reap + prune)\n", username)
	return nil
}

// setContainerDeletePolicyViaServer dispatches over grpc or http per the global
// httpMode flag, mirroring setContainerTTLViaServer in ttl.go.
func setContainerDeletePolicyViaServer(username string, policy pb.DeletePolicy) error {
	if httpMode {
		hc, err := client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return err
		}
		defer hc.Close()
		_, err = hc.SetContainerDeletePolicy(username, policy)
		return err
	}
	gc, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return err
	}
	defer gc.Close()
	_, err = gc.SetContainerDeletePolicy(username, policy)
	return err
}
