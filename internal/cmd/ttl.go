package cmd

import (
	"fmt"
	"time"

	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The TTL verbs below are wired end-to-end:
//
//   - set/unset call the SetContainerTTL RPC (POST /v1/containers/{name}/ttl;
//     duration 0 clears), which stamps user.containarium.ttl_expires_at on the
//     Incus container — the exact key the daemon's ttlsweeper consumes to
//     force-delete the box when it elapses (see internal/ttlsweeper +
//     internal/server/container_server_ttl.go).
//   - get reads ttl_expires_at off the container via GetContainer (no separate
//     GetContainerTTL RPC; the field is part of the container view).
//
// This closes the #264 leak where the containarium-run "keep on failure" path
// called `containarium ttl set` but the call was a client-side stub (and over
// REST returned 404), so the kept debug box never got a TTL and never reaped.
// A daemon too old to implement SetContainerTTL still degrades gracefully:
// codes.Unimplemented (gRPC) / HTTP 404 mapped to Unimplemented (REST) → the
// CLI prints a friendly no-op rather than failing the Action.

// maxTTL caps the duration a caller can request. 168h (7 days) is the
// upper bound: long enough to cover a long weekend debug session on a
// failed CI run, short enough that a forgotten box won't bleed cloud
// budget for a month. Reject anything longer with InvalidArgument so
// callers see a clear error rather than a silently clamped value.
const maxTTL = 168 * time.Hour

var ttlCmd = &cobra.Command{
	Use:   "ttl",
	Short: "Manage container time-to-live (auto-delete) settings",
	Long: `Manage the TTL (time-to-live) on a container. When a TTL is set,
the container is scheduled for automatic deletion after the given
duration. Useful for ephemeral/CI boxes that should not leak when a
test run fails and the box is kept open for debugging.

Examples:
  # Keep this box alive for 1 hour, then auto-delete
  containarium ttl set alice 1h

  # Update an existing TTL to 30 minutes from now
  containarium ttl set alice 30m

  # Inspect the current TTL
  containarium ttl get alice

  # Clear the TTL (box will never auto-delete)
  containarium ttl unset alice

Maximum allowed TTL is 168h (7 days).`,
}

var ttlSetCmd = &cobra.Command{
	Use:   "set <username> <duration>",
	Short: "Set or update the TTL on a container",
	Long: `Set the TTL on a container. The container will be auto-deleted
after the given duration. Duration uses Go's time.ParseDuration
format ("30m", "1h", "24h", etc.). Maximum allowed: 168h (7 days).

If a TTL is already set, this overrides it (the timer restarts
from now). To clear an existing TTL, use 'containarium ttl unset'.

Examples:
  containarium ttl set alice 1h
  containarium ttl set ci-bob-pr123 30m
  containarium ttl set debug-box 24h`,
	Args: cobra.ExactArgs(2),
	RunE: runTTLSet,
}

var ttlGetCmd = &cobra.Command{
	Use:   "get <username>",
	Short: "Show the current TTL on a container",
	Long: `Print the TTL setting and the remaining time before
auto-delete. Prints "no TTL set" if the container has no TTL.

Examples:
  containarium ttl get alice`,
	Args: cobra.ExactArgs(1),
	RunE: runTTLGet,
}

var ttlUnsetCmd = &cobra.Command{
	Use:   "unset <username>",
	Short: "Clear the TTL on a container (it will never auto-delete)",
	Args:  cobra.ExactArgs(1),
	RunE:  runTTLUnset,
}

func init() {
	rootCmd.AddCommand(ttlCmd)
	ttlCmd.AddCommand(ttlSetCmd)
	ttlCmd.AddCommand(ttlGetCmd)
	ttlCmd.AddCommand(ttlUnsetCmd)
}

// parseTTL parses and validates a Go-format duration string against
// the maxTTL cap. Returns InvalidArgument-flavoured errors so callers
// can distinguish "your input was wrong" from "the server choked".
func parseTTL(s string) (time.Duration, error) {
	if s == "" {
		return 0, fmt.Errorf("ttl duration is required")
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q: %w (expected Go duration format like '30m', '1h', '24h')", s, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("ttl duration must be positive, got %s", s)
	}
	if d > maxTTL {
		return 0, fmt.Errorf("ttl duration %s exceeds maximum of %s (7 days); use a smaller value or delete the container manually", s, maxTTL)
	}
	return d, nil
}

func runTTLSet(cmd *cobra.Command, args []string) error {
	username := args[0]
	durStr := args[1]

	d, err := parseTTL(durStr)
	if err != nil {
		return err
	}

	if serverAddr == "" {
		return fmt.Errorf("--server is required (ttl scheduling is a server-side feature)")
	}

	expiresAt := time.Now().Add(d).UTC()
	if verbose {
		fmt.Printf("Setting TTL on %s: %s (expires at %s)\n", username, d, expiresAt.Format(time.RFC3339))
	}

	err = ttlClientSet(username, d)
	if isUnimplemented(err) {
		fmt.Printf("⚠ TTL not yet supported by this server (containarium daemon does not implement SetContainerTTL); the box will not auto-delete.\n")
		fmt.Printf("  Requested: ttl=%s, would have expired at %s.\n", d, expiresAt.Format(time.RFC3339))
		fmt.Printf("  See the TODO at the top of internal/cmd/ttl.go for the server-side gap.\n")
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to set TTL: %w", err)
	}

	fmt.Printf("✓ TTL set on %s: expires in %s (at %s)\n", username, d, expiresAt.Format(time.RFC3339))
	return nil
}

func runTTLGet(cmd *cobra.Command, args []string) error {
	username := args[0]

	if serverAddr == "" {
		return fmt.Errorf("--server is required (ttl scheduling is a server-side feature)")
	}

	expiresAt, ok, err := ttlClientGet(username)
	if isUnimplemented(err) {
		fmt.Printf("⚠ TTL not yet supported by this server (containarium daemon does not implement GetContainerTTL).\n")
		fmt.Printf("  See the TODO at the top of internal/cmd/ttl.go for the server-side gap.\n")
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to get TTL: %w", err)
	}

	if !ok {
		fmt.Printf("no TTL set on %s\n", username)
		return nil
	}

	remaining := time.Until(expiresAt).Round(time.Second)
	if remaining <= 0 {
		fmt.Printf("TTL on %s has expired (was due at %s); awaiting sweeper.\n", username, expiresAt.UTC().Format(time.RFC3339))
		return nil
	}
	fmt.Printf("expires in %s (at %s)\n", remaining, expiresAt.UTC().Format(time.RFC3339))
	return nil
}

func runTTLUnset(cmd *cobra.Command, args []string) error {
	username := args[0]

	if serverAddr == "" {
		return fmt.Errorf("--server is required (ttl scheduling is a server-side feature)")
	}

	err := ttlClientUnset(username)
	if isUnimplemented(err) {
		fmt.Printf("⚠ TTL not yet supported by this server (containarium daemon does not implement ClearContainerTTL); nothing to clear.\n")
		fmt.Printf("  See the TODO at the top of internal/cmd/ttl.go for the server-side gap.\n")
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to clear TTL: %w", err)
	}

	fmt.Printf("✓ TTL cleared on %s\n", username)
	return nil
}

// isUnimplemented returns true if err carries the gRPC Unimplemented
// status code. We treat that as a soft failure (print a warning,
// exit 0) rather than a hard error, so callers like the
// containarium-run Action can wire `containarium ttl set` into their
// failure path today without breaking when running against an older
// daemon.
func isUnimplemented(err error) bool {
	if err == nil {
		return false
	}
	if s, ok := status.FromError(err); ok && s.Code() == codes.Unimplemented {
		return true
	}
	return false
}

// ttlClientSet / ttlClientGet / ttlClientUnset are thin wrappers over the
// transport client (grpc or http per the global httpMode flag), mirroring
// how scale_down.go's toggleAutoSleepViaServer dispatches.
//
// set/unset call the SetContainerTTL RPC (unset = duration 0 = clear). get
// reads ttl_expires_at off the container via GetContainer — there is no
// separate GetContainerTTL RPC; the field is part of the container view. A
// daemon too old to implement SetContainerTTL surfaces codes.Unimplemented
// (gRPC) or HTTP 404 mapped to Unimplemented (REST), which runTTLSet/Unset
// degrade to a friendly no-op via isUnimplemented.

func ttlClientSet(username string, d time.Duration) error {
	return setContainerTTLViaServer(username, int64(d.Seconds()))
}

func ttlClientUnset(username string) error {
	return setContainerTTLViaServer(username, 0)
}

func setContainerTTLViaServer(username string, durationSeconds int64) error {
	if httpMode {
		hc, err := client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return err
		}
		defer hc.Close()
		_, err = hc.SetContainerTTL(username, durationSeconds)
		return err
	}
	gc, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return err
	}
	defer gc.Close()
	_, err = gc.SetContainerTTL(username, durationSeconds)
	return err
}

// ttlClientGet reads the container's current TTL via GetContainer. A zero
// expiry means "no TTL set" (ok == false). GetContainer is a long-standing
// RPC, so no Unimplemented degradation is needed here.
func ttlClientGet(username string) (time.Time, bool, error) {
	var info *incus.ContainerInfo
	var err error
	if httpMode {
		hc, e := client.NewHTTPClient(serverAddr, authToken)
		if e != nil {
			return time.Time{}, false, e
		}
		defer hc.Close()
		info, err = hc.GetContainer(username)
	} else {
		gc, e := client.NewGRPCClient(serverAddr, certsDir, insecure)
		if e != nil {
			return time.Time{}, false, e
		}
		defer gc.Close()
		info, err = gc.GetContainer(username)
	}
	if err != nil {
		return time.Time{}, false, err
	}
	if info == nil || info.TTLExpiresAt.IsZero() {
		return time.Time{}, false, nil
	}
	return info.TTLExpiresAt, true, nil
}
