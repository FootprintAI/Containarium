package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/cloud"
)

// defaultDaemonJWTSecretFile is where the daemon's JWT signing secret lives on
// a standard host install — the same secret `cloud enroll` mints the BYOC
// driver token against so the host's own daemon will accept it.
const defaultDaemonJWTSecretFile = "/etc/containarium/jwt.secret"

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

var (
	cloudEnrollControlPlane  string
	cloudEnrollTokenFile     string
	cloudEnrollInsecure      bool
	cloudEnrollJWTSecretFile string
	cloudEnrollBackendID     string
	cloudEnrollNoDriverToken bool
	cloudEnrollDriverTTL     time.Duration
)

var cloudEnrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Self-register this host with a single-use join token (BYO compute)",
	Long: `Redeem a single-use join token to register this host with a cloud control
plane, then write ~/.containarium/cloud.yaml.

Unlike 'cloud login' (which takes a sysadmin-issued host-id + token out of
band), 'cloud enroll' is the self-service BYO flow: the token from the cloud's
"Add compute" one-liner is redeemed against the control plane (EnrollHost),
which returns the host id and registers the host. The same token becomes this
host's durable bearer. The token is read from --token-file so it never lands
in shell history.`,
	RunE: runCloudEnroll,
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
	cloudCmd.AddCommand(cloudLoginCmd, cloudEnrollCmd, cloudStatusCmd, cloudLogoutCmd)

	cloudLoginCmd.Flags().StringVar(&cloudControlPlane, "control-plane", "", "cloud control-plane gRPC address (host:port) (required)")
	cloudLoginCmd.Flags().StringVar(&cloudHostID, "host-id", "", "cloud-assigned host UUID from the sysadmin (required)")
	cloudLoginCmd.Flags().StringVar(&cloudTokenFile, "token-file", "", "file containing the host bearer token (required)")
	_ = cloudLoginCmd.MarkFlagRequired("control-plane")
	_ = cloudLoginCmd.MarkFlagRequired("host-id")
	_ = cloudLoginCmd.MarkFlagRequired("token-file")

	cloudEnrollCmd.Flags().StringVar(&cloudEnrollControlPlane, "control-plane", "", "cloud control-plane gRPC address (host:port) (required)")
	cloudEnrollCmd.Flags().StringVar(&cloudEnrollTokenFile, "token-file", "", "file containing the single-use join token (required)")
	cloudEnrollCmd.Flags().BoolVar(&cloudEnrollInsecure, "insecure", false, "dial the control plane without TLS (local dev only)")
	cloudEnrollCmd.Flags().StringVar(&cloudEnrollJWTSecretFile, "jwt-secret-file", defaultDaemonJWTSecretFile, "path to this daemon's JWT secret; used to mint the BYOC driver token the cloud replays to drive this host")
	cloudEnrollCmd.Flags().StringVar(&cloudEnrollBackendID, "oss-backend-id", "", "this host's tunnel/`pool join` spot-id (what the sentinel peer-proxy keys on); enables the cloud to route container ops to this host")
	cloudEnrollCmd.Flags().BoolVar(&cloudEnrollNoDriverToken, "no-driver-token", false, "enroll without minting a driver token (host registers + heartbeats but the cloud cannot place workloads on it)")
	cloudEnrollCmd.Flags().DurationVar(&cloudEnrollDriverTTL, "driver-token-ttl", 30*24*time.Hour, "driver token lifetime (capped at the daemon max, 30d); re-run `cloud enroll` before it expires to rotate")
	_ = cloudEnrollCmd.MarkFlagRequired("control-plane")
	_ = cloudEnrollCmd.MarkFlagRequired("token-file")
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

func runCloudEnroll(cmd *cobra.Command, _ []string) error {
	tokenBytes, err := os.ReadFile(cloudEnrollTokenFile) // #nosec G304 -- operator-provided token path
	if err != nil {
		return fmt.Errorf("read --token-file: %w", err)
	}
	token := strings.TrimSpace(string(tokenBytes))
	if token == "" {
		return fmt.Errorf("--token-file %q is empty", cloudEnrollTokenFile)
	}
	controlPlane := strings.TrimSpace(cloudEnrollControlPlane)

	// Mint the BYOC driver token (cloud #554) — an admin JWT signed with THIS
	// host's own jwt.secret, which the cloud seals and replays to drive this
	// host's daemon through the sentinel peer-proxy. Best-effort: if the secret
	// isn't readable (e.g. not running as root, or a non-BYOC host), we warn and
	// enroll without it — the host still registers + heartbeats, it just isn't
	// cloud-drivable. --no-driver-token skips minting entirely.
	opts := cloud.EnrollOptions{OSSBackendID: strings.TrimSpace(cloudEnrollBackendID)}
	if !cloudEnrollNoDriverToken {
		driverTok, mintErr := mintDriverToken(cloudEnrollJWTSecretFile, cloudEnrollDriverTTL)
		switch {
		case mintErr != nil:
			fmt.Fprintf(cmd.ErrOrStderr(),
				"⚠ no driver token minted (%v)\n  host will enroll but the cloud can't place workloads on it; fix the jwt secret and re-run, or pass --no-driver-token to silence this\n",
				mintErr)
		case opts.OSSBackendID == "":
			fmt.Fprintf(cmd.ErrOrStderr(),
				"⚠ minted a driver token but --oss-backend-id is empty\n  the cloud can't route to this host until it knows the backend id; re-run with --oss-backend-id <spot-id>\n")
			opts.DriverToken = driverTok
		default:
			opts.DriverToken = driverTok
		}
	}

	// Redeem the join token against the control plane. On success the cloud
	// has created the host row and returns its id; the same token is now this
	// host's durable bearer (the cloud reuses the token secret).
	hostID, err := cloud.Enroll(cmd.Context(), controlPlane, token, cloudEnrollInsecure, opts)
	if err != nil {
		return err
	}
	cfg := &cloud.Config{
		ControlPlane: controlPlane,
		HostID:       hostID,
		Token:        token,
		Insecure:     cloudEnrollInsecure,
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
	fmt.Fprintf(cmd.OutOrStdout(), "✓ enrolled host %s with %s\n  config: %s (restart the daemon to start actuating + reporting)\n",
		hostID, controlPlane, path)
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

// mintDriverToken reads this daemon's JWT secret and mints a short-lived admin
// access token (cloud #554). The cloud seals + replays it to drive this host's
// daemon through the sentinel peer-proxy; because it's signed with the host's
// OWN secret, the host's daemon accepts it without the cloud ever learning the
// secret. ttl is capped at the daemon max (30d) by the token manager, so the
// cloud-stored token expires — re-run `cloud enroll` to rotate.
func mintDriverToken(secretFile string, ttl time.Duration) (string, error) {
	secretFile = strings.TrimSpace(secretFile)
	if secretFile == "" {
		return "", fmt.Errorf("no --jwt-secret-file")
	}
	secretBytes, err := os.ReadFile(secretFile) // #nosec G304 -- operator-provided daemon secret path
	if err != nil {
		return "", fmt.Errorf("read jwt secret %s: %w", secretFile, err)
	}
	secret := strings.TrimSpace(string(secretBytes))
	if secret == "" {
		return "", fmt.Errorf("jwt secret %s is empty", secretFile)
	}
	tm, err := auth.NewTokenManager(secret, "containarium")
	if err != nil {
		return "", fmt.Errorf("token manager: %w", err)
	}
	// admin role: the cloud drives container CRUD on this host through the
	// driver — same privilege the region-primary driver token carries.
	tok, err := tm.GenerateToken("cloud-byoc-driver", []string{"admin"}, ttl)
	if err != nil {
		return "", fmt.Errorf("mint driver token: %w", err)
	}
	return tok, nil
}

// redactToken shows only enough to recognize which token is stored, never the
// whole bearer.
func redactToken(t string) string {
	if len(t) <= 8 {
		return "********"
	}
	return t[:4] + "…" + t[len(t)-4:]
}
