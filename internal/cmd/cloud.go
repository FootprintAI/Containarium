package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/footprintai/containarium/internal/cloud"
)

// cloudCmd is the parent for `containarium cloud <verb>` — host enrollment with
// a cloud control plane (#354, docs/CLOUD-ACTUATION-CLIENT-DESIGN.md). This is
// the OSS opt-in: a registered host receives desired-state container assignments
// + per-org egress network policies from the cloud and reconciles them locally.
//
// Distinct from `containarium login` (which stores a user-facing JWT in
// credentials.json): `cloud login` stores a host bearer in cloud.yaml, used by
// the daemon's actuation client. Slice 1: enrollment config only — the daemon
// heartbeat / WatchAssignments client lands in later slices.
var cloudCmd = &cobra.Command{
	Use:   "cloud",
	Short: "Enroll this host with a cloud control plane (actuation)",
	Long: `Manage this host's enrollment with a Containarium cloud control plane.

When enrolled, the daemon runs an actuation client that receives desired-state
container assignments and per-org network policies from the cloud and reconciles
them against local Incus state. Enrollment is opt-in — an unenrolled daemon is
single-tenant and makes no outbound calls.

The host bearer token comes from a cloud sysadmin (who runs the cloud-side
CreateHost); you receive the host ID + token out of band and register here.`,
}

var (
	cloudControlPlane string
	cloudHostID       string
	cloudTokenFile    string
)

var cloudLoginCmd = &cobra.Command{
	Use:   "login",
	Short: "Register this host (writes ~/.containarium/cloud.yaml)",
	Long: `Register this host with a cloud control plane.

The token is read from --token-file (not a flag) so it never lands in shell
history. Writes the enrollment to ~/.containarium/cloud.yaml at mode 0600.`,
	RunE: runCloudLogin,
}

var cloudStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show this host's cloud enrollment",
	RunE:  runCloudStatus,
}

var cloudLogoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Remove this host's enrollment (~/.containarium/cloud.yaml)",
	Long: `Delete the local enrollment config. The daemon stops actuating on next
restart. The cloud-side host row stays until a sysadmin tombstones it
(cloud DeleteHost).`,
	RunE: runCloudLogout,
}

func init() {
	rootCmd.AddCommand(cloudCmd)
	cloudCmd.AddCommand(cloudLoginCmd, cloudStatusCmd, cloudLogoutCmd)

	cloudLoginCmd.Flags().StringVar(&cloudControlPlane, "control-plane", "", "cloud control-plane gRPC address (host:port) (required)")
	cloudLoginCmd.Flags().StringVar(&cloudHostID, "host-id", "", "cloud-assigned host UUID from the sysadmin (required)")
	cloudLoginCmd.Flags().StringVar(&cloudTokenFile, "token-file", "", "file containing the host bearer token (required)")
	_ = cloudLoginCmd.MarkFlagRequired("control-plane")
	_ = cloudLoginCmd.MarkFlagRequired("host-id")
	_ = cloudLoginCmd.MarkFlagRequired("token-file")
}

func runCloudLogin(cmd *cobra.Command, _ []string) error {
	tokenBytes, err := os.ReadFile(cloudTokenFile) // #nosec G304 -- operator-provided token path
	if err != nil {
		return fmt.Errorf("read --token-file: %w", err)
	}
	token := strings.TrimSpace(string(tokenBytes))
	if token == "" {
		return fmt.Errorf("--token-file %q is empty", cloudTokenFile)
	}
	cfg := &cloud.Config{
		ControlPlane: strings.TrimSpace(cloudControlPlane),
		HostID:       strings.TrimSpace(cloudHostID),
		Token:        token,
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	path, err := cloud.DefaultPath()
	if err != nil {
		return err
	}
	if err := cloud.Save(path, cfg); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "✓ enrolled host %s with %s\n  config: %s (restart the daemon to start actuating)\n",
		cfg.HostID, cfg.ControlPlane, path)
	return nil
}

func runCloudStatus(cmd *cobra.Command, _ []string) error {
	path, err := cloud.DefaultPath()
	if err != nil {
		return err
	}
	cfg, err := cloud.Load(path)
	if err != nil {
		return err
	}
	w := cmd.OutOrStdout()
	if cfg == nil {
		fmt.Fprintf(w, "not enrolled (no %s) — daemon runs single-tenant\n", path)
		return nil
	}
	fmt.Fprintf(w, "enrolled\n  control-plane: %s\n  host-id:       %s\n  token:         %s\n  config:        %s\n",
		cfg.ControlPlane, cfg.HostID, redactToken(cfg.Token), path)
	return nil
}

func runCloudLogout(cmd *cobra.Command, _ []string) error {
	path, err := cloud.DefaultPath()
	if err != nil {
		return err
	}
	if err := cloud.Delete(path); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "✓ removed cloud enrollment (%s)\n", path)
	return nil
}

// redactToken shows only enough to recognize which token is stored, never the
// whole bearer.
func redactToken(t string) string {
	if len(t) <= 8 {
		return "********"
	}
	return t[:4] + "…" + t[len(t)-4:]
}
