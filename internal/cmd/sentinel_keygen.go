//go:build !windows

// The sentinel command tree (sentinelCmd, defined in sentinel.go) is
// !windows-only — the Windows build ships only the remote-client commands. This
// subcommand attaches to sentinelCmd, so it must carry the same constraint or
// the Windows cross-compile fails with "undefined: sentinelCmd".

package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/spf13/cobra"
)

var sentinelKeygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate an ed25519 keypair for sentinel→daemon authentication (#688)",
	Long: `Generate an ed25519 keypair for the asymmetric sentinel→daemon auth scheme.

The sentinel signs keysync/certsync requests (and the peer-discovery response)
with the PRIVATE key; every daemon verifies with only the PUBLIC key. Because a
daemon never holds the private key, the public key is safe to distribute to any
host — including untrusted BYO-compute (BYOC) hosts — without granting the
ability to forge a sentinel request.

This prints two values:

  CONTAINARIUM_SENTINEL_SIGNING_KEY   set on the SENTINEL only (keep secret)
  CONTAINARIUM_SENTINEL_PUBLIC_KEY    set on EVERY daemon (safe to distribute)

Rollout order matters: distribute the public key to ALL daemons first, THEN set
the signing key on the sentinel. Otherwise a daemon that hasn't received the
public key yet will reject the sentinel's ed25519 signatures and keysync breaks.
During migration both the new keys and the legacy CONTAINARIUM_SENTINEL_AUTH_SECRET
are accepted; once every daemon verifies ed25519, drop the shared secret.`,
	RunE: runSentinelKeygen,
}

func init() {
	sentinelCmd.AddCommand(sentinelKeygenCmd)
}

func runSentinelKeygen(cmd *cobra.Command, args []string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate ed25519 key: %w", err)
	}

	out := cmd.OutOrStdout()
	fmt.Fprintln(out, "# Sentinel→daemon ed25519 keypair (#688).")
	fmt.Fprintln(out, "# Distribute the PUBLIC key to every daemon FIRST, then set the")
	fmt.Fprintln(out, "# SIGNING key on the sentinel. Keep the signing key secret.")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "# On the SENTINEL only:")
	fmt.Fprintf(out, "CONTAINARIUM_SENTINEL_SIGNING_KEY=%s\n", base64.StdEncoding.EncodeToString(priv))
	fmt.Fprintln(out)
	fmt.Fprintln(out, "# On EVERY daemon (safe to distribute, incl. BYOC):")
	fmt.Fprintf(out, "CONTAINARIUM_SENTINEL_PUBLIC_KEY=%s\n", base64.StdEncoding.EncodeToString(pub))
	return nil
}
