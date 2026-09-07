//go:build !containarium_client

package cmd

import (
	"github.com/spf13/cobra"
)

// hostingCmd represents the hosting command
var hostingCmd = &cobra.Command{
	Use:   "hosting",
	Short: "Manage app hosting infrastructure",
	Long: `Manage DNS, SSL certificates, and reverse proxy for app hosting.

This command provides tools to automate the setup of:
  - DNS records (via DNS provider API)
  - SSL/TLS certificates (via Let's Encrypt)
  - Caddy reverse proxy for HTTPS termination

Supported DNS providers:
  - GoDaddy (godaddy)
  - More providers coming soon...

Examples:
  # Full automated setup with GoDaddy
  containarium hosting setup --domain example.com --email admin@example.com --provider godaddy

  # Setup with credentials from environment variables
  export GODADDY_API_KEY=your-key
  export GODADDY_API_SECRET=your-secret
  containarium hosting setup --domain example.com --email admin@example.com

  # Check hosting status
  containarium hosting status

  # List supported providers
  containarium hosting providers`,
}

func init() {
	rootCmd.AddCommand(hostingCmd)
}
