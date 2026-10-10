//go:build !windows && !containarium_client

// The sentinel command tree (sentinelCmd, defined in sentinel.go) is
// !windows-only; this subcommand attaches to it and carries the same
// constraint.

package cmd

import (
	"fmt"
	"io"
	"log"

	"github.com/footprintai/containarium/internal/sentinel"
	"github.com/spf13/cobra"
)

var sentinelTunnelIdentityPath string

var sentinelTunnelIdentityCmd = &cobra.Command{
	Use:   "tunnel-identity",
	Short: "Print the pin of the sentinel's tunnel identity",
	Long: `Print the public-key pin of the sentinel's tunnel identity, in the form
tunnel clients take with --sentinel-pin:

  sha256:<64 hex>

The identity is created by the sentinel on its first start (see
--tunnel-tls-identity on 'containarium sentinel'). This command only reads it:
when the file does not exist yet it fails instead of creating one. The pin is
public; distribute it to every tunnel client of this sentinel.`,
	Example: `  # On the sentinel host
  containarium sentinel tunnel-identity

  # Identity kept somewhere other than the default path
  containarium sentinel tunnel-identity --tunnel-tls-identity /path/to/identity.pem`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return printTunnelIdentityPin(cmd.OutOrStdout(), sentinelTunnelIdentityPath)
	},
}

func init() {
	sentinelCmd.AddCommand(sentinelTunnelIdentityCmd)
	sentinelTunnelIdentityCmd.Flags().StringVar(&sentinelTunnelIdentityPath, "tunnel-tls-identity", sentinel.DefaultTunnelIdentityPath, "Path of the sentinel's tunnel identity file")
}

// printTunnelIdentityPin loads the identity at path and writes its pin as a
// single line. It never creates the file.
func printTunnelIdentityPin(out io.Writer, path string) error {
	id, err := sentinel.LoadTunnelIdentity(path)
	if err != nil {
		return fmt.Errorf("load tunnel identity (the sentinel creates it on first start): %w", err)
	}
	_, err = fmt.Fprintln(out, id.Pin())
	return err
}

// configureTunnelTransport loads the tunnel identity at identityPath, or
// generates and saves it on first start, installs it on ts, and applies the
// cleartext policy. The pin is logged on every start so operators can read
// it from the service log as well as from 'sentinel tunnel-identity'.
func configureTunnelTransport(ts *sentinel.TunnelServer, identityPath string, allowCleartext bool) (sentinel.TunnelPin, error) {
	id, generated, err := sentinel.LoadOrGenerateTunnelIdentity(identityPath)
	if err != nil {
		return "", fmt.Errorf("tunnel identity: %w", err)
	}
	ts.SetTunnelIdentity(id)
	ts.AllowCleartext = allowCleartext

	pin := id.Pin()
	if generated {
		log.Printf("[sentinel] generated tunnel identity at %s; pin %s", identityPath, pin)
	} else {
		log.Printf("[sentinel] loaded tunnel identity from %s; pin %s", identityPath, pin)
	}
	if allowCleartext {
		log.Printf("[sentinel] tunnel transport: TLS, cleartext sessions accepted (--tunnel-allow-cleartext=true)")
	} else {
		log.Printf("[sentinel] tunnel transport: TLS only, cleartext sessions refused")
	}
	return pin, nil
}
