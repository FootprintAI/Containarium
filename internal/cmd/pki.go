package cmd

import (
	"fmt"
	"os"

	"github.com/footprintai/containarium/pkg/core/pki"
	"github.com/spf13/cobra"
)

// pki is the Phase 0.5 peer-CA management command — distinct from
// the older `cert` command which manages the daemon's gRPC mTLS
// keypair. The two PKIs don't overlap; this one is owned by the
// sentinel and used for peer-to-peer HTTPS.
var pkiCmd = &cobra.Command{
	Use:   "pki",
	Short: "Manage the sentinel-owned peer-CA used for peer-to-peer HTTPS",
	Long: `Phase 0.5 peer-CA. A single operator-managed RSA private key on
the sentinel acts as the CA root. The CA certificate is generated
at runtime from that key; per-peer leaf certs are minted on demand
with a configurable short TTL (default 7 days).

This command is the one-time bootstrap step: it generates the CA
private key. Persist the output to a mode-0400 file on the sentinel,
back it up off-host, and point the sentinel at it with
CONTAINARIUM_CA_KEY_FILE.`,
}

var pkiGenerateCACmd = &cobra.Command{
	Use:   "generate-ca",
	Short: "Generate a fresh RSA-4096 CA private key (PEM, PKCS#1) to stdout",
	Long: `Outputs a PEM-encoded RSA-4096 private key to stdout. Capture it
to a file mode 0400 owned by root on the sentinel:

    containarium pki generate-ca > /etc/containarium/ca.key
    chmod 0400 /etc/containarium/ca.key

Then point the sentinel daemon at it via the systemd environment:

    CONTAINARIUM_CA_KEY_FILE=/etc/containarium/ca.key

On the next sentinel restart the binary generates a self-signed CA
certificate from this key (10-year validity) and starts issuing
peer leaf certs over /sentinel/peer-cert. Replacing this file and
restarting rotates the entire CA — every leaf cert in the fleet
expires within the leaf-TTL window (default 7 days) and re-issues
under the new CA on the next renewal tick.`,
	RunE: func(_ *cobra.Command, _ []string) error {
		keyPEM, err := pki.GenerateCAKey()
		if err != nil {
			return fmt.Errorf("generate CA key: %w", err)
		}
		if _, err := os.Stdout.Write(keyPEM); err != nil {
			return fmt.Errorf("write to stdout: %w", err)
		}
		return nil
	},
}

func init() {
	pkiCmd.AddCommand(pkiGenerateCACmd)
	rootCmd.AddCommand(pkiCmd)
}
