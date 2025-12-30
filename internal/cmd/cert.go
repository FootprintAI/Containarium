package cmd

import (
	"fmt"
	"log"
	"time"

	"github.com/footprintai/containarium/internal/mtls"
	"github.com/spf13/cobra"
)

var (
	certOrganization string
	certDNSNames     []string
	certIPAddresses  []string
	certDuration     time.Duration
	certOutputDir    string
	certCAPath       string
	certCAKeyPath    string
)

var certCmd = &cobra.Command{
	Use:   "cert",
	Short: "Manage TLS certificates for mTLS authentication",
	Long: `Generate and manage TLS certificates for secure gRPC communication.

The cert command provides utilities for generating CA, server, and client
certificates required for mutual TLS (mTLS) authentication between the daemon
and CLI clients.

mTLS ensures that:
  - Only authenticated clients can connect to the daemon
  - Communication is encrypted end-to-end
  - Both server and client identities are verified`,
}

var certGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate new TLS certificates",
	Long: `Generate a new Certificate Authority (CA) and server/client certificates.

This command creates:
  - CA certificate and private key (ca.crt, ca.key)
  - Server certificate and private key (server.crt, server.key)
  - Client certificate and private key (client.crt, client.key)

By default, certificates are valid for 1 year and include localhost/127.0.0.1.
You can add additional DNS names and IP addresses for the server.

Examples:
  # Generate certificates with defaults
  sudo containarium cert generate

  # Generate with custom organization and DNS names
  sudo containarium cert generate --org "MyCompany" --dns api.example.com,service.internal

  # Generate with custom validity period
  sudo containarium cert generate --duration 8760h  # 1 year

  # Generate with custom output directory
  containarium cert generate --output ./mycerts

  # Generate with specific IP addresses
  sudo containarium cert generate --ips 10.0.0.5,192.168.1.100`,
	RunE: runCertGenerate,
}

var certGenerateWithCACmd = &cobra.Command{
	Use:   "generate-with-ca",
	Short: "Generate server/client certificates with existing CA",
	Long: `Generate new server and client certificates using an existing CA.

This is useful for:
  - Certificate rotation without changing the CA
  - Creating certificates for multiple servers with the same CA
  - Managing certificates in a multi-server deployment

Examples:
  # Generate certificates with existing CA
  sudo containarium cert generate-with-ca \
    --ca-cert /path/to/ca.crt \
    --ca-key /path/to/ca.key

  # Generate for a specific server
  sudo containarium cert generate-with-ca \
    --ca-cert /path/to/ca.crt \
    --ca-key /path/to/ca.key \
    --dns server2.internal \
    --output /etc/containarium/certs-server2`,
	RunE: runCertGenerateWithCA,
}

func init() {
	rootCmd.AddCommand(certCmd)
	certCmd.AddCommand(certGenerateCmd)
	certCmd.AddCommand(certGenerateWithCACmd)

	// Flags for 'cert generate'
	certGenerateCmd.Flags().StringVar(&certOrganization, "org", "Containarium", "Organization name for certificates")
	certGenerateCmd.Flags().StringSliceVar(&certDNSNames, "dns", []string{"containarium-daemon"}, "Additional DNS names (comma-separated)")
	certGenerateCmd.Flags().StringSliceVar(&certIPAddresses, "ips", []string{}, "Additional IP addresses (comma-separated)")
	certGenerateCmd.Flags().DurationVar(&certDuration, "duration", 365*24*time.Hour, "Certificate validity duration")
	certGenerateCmd.Flags().StringVar(&certOutputDir, "output", mtls.DefaultCertsDir, "Output directory for certificates")

	// Flags for 'cert generate-with-ca'
	certGenerateWithCACmd.Flags().StringVar(&certCAPath, "ca-cert", "", "Path to existing CA certificate (required)")
	certGenerateWithCACmd.Flags().StringVar(&certCAKeyPath, "ca-key", "", "Path to existing CA private key (required)")
	certGenerateWithCACmd.Flags().StringVar(&certOrganization, "org", "Containarium", "Organization name for certificates")
	certGenerateWithCACmd.Flags().StringSliceVar(&certDNSNames, "dns", []string{"containarium-daemon"}, "Additional DNS names (comma-separated)")
	certGenerateWithCACmd.Flags().StringSliceVar(&certIPAddresses, "ips", []string{}, "Additional IP addresses (comma-separated)")
	certGenerateWithCACmd.Flags().DurationVar(&certDuration, "duration", 365*24*time.Hour, "Certificate validity duration")
	certGenerateWithCACmd.Flags().StringVar(&certOutputDir, "output", mtls.DefaultCertsDir, "Output directory for certificates")

	certGenerateWithCACmd.MarkFlagRequired("ca-cert")
	certGenerateWithCACmd.MarkFlagRequired("ca-key")
}

func runCertGenerate(cmd *cobra.Command, args []string) error {
	log.Printf("Generating TLS certificates...")
	log.Printf("  Organization: %s", certOrganization)
	log.Printf("  DNS names: %v", certDNSNames)
	log.Printf("  IP addresses: %v", certIPAddresses)
	log.Printf("  Valid for: %v", certDuration)
	log.Printf("  Output directory: %s", certOutputDir)

	opts := mtls.GenerateOptions{
		Organization: certOrganization,
		DNSNames:     certDNSNames,
		IPAddresses:  certIPAddresses,
		Duration:     certDuration,
		OutputDir:    certOutputDir,
	}

	if err := mtls.Generate(opts); err != nil {
		return fmt.Errorf("failed to generate certificates: %w", err)
	}

	paths := mtls.CertPathsFromDir(certOutputDir)

	log.Printf("\n✓ Certificates generated successfully!")
	log.Printf("\nGenerated files:")
	log.Printf("  CA Certificate:     %s", paths.CACert)
	log.Printf("  CA Key:             %s", paths.CAKey)
	log.Printf("  Server Certificate: %s", paths.ServerCert)
	log.Printf("  Server Key:         %s", paths.ServerKey)
	log.Printf("  Client Certificate: %s", paths.ClientCert)
	log.Printf("  Client Key:         %s", paths.ClientKey)

	log.Printf("\nNext steps:")
	log.Printf("  1. Start the daemon with mTLS:")
	log.Printf("     sudo containarium daemon --mtls")
	log.Printf("\n  2. Connect from CLI (will use certificates automatically):")
	log.Printf("     containarium list")
	log.Printf("\n  3. For remote servers, copy client certificates:")
	log.Printf("     scp %s <user>@<remote>:~/.config/containarium/", paths.ClientCert)
	log.Printf("     scp %s <user>@<remote>:~/.config/containarium/", paths.ClientKey)
	log.Printf("     scp %s <user>@<remote>:~/.config/containarium/", paths.CACert)

	return nil
}

func runCertGenerateWithCA(cmd *cobra.Command, args []string) error {
	log.Printf("Generating TLS certificates with existing CA...")
	log.Printf("  CA Certificate: %s", certCAPath)
	log.Printf("  CA Key: %s", certCAKeyPath)
	log.Printf("  Organization: %s", certOrganization)
	log.Printf("  DNS names: %v", certDNSNames)
	log.Printf("  IP addresses: %v", certIPAddresses)
	log.Printf("  Valid for: %v", certDuration)
	log.Printf("  Output directory: %s", certOutputDir)

	opts := mtls.GenerateOptions{
		Organization: certOrganization,
		DNSNames:     certDNSNames,
		IPAddresses:  certIPAddresses,
		Duration:     certDuration,
		OutputDir:    certOutputDir,
	}

	if err := mtls.GenerateWithExistingCA(certCAPath, certCAKeyPath, opts); err != nil {
		return fmt.Errorf("failed to generate certificates: %w", err)
	}

	paths := mtls.CertPathsFromDir(certOutputDir)

	log.Printf("\n✓ Certificates generated successfully!")
	log.Printf("\nGenerated files:")
	log.Printf("  CA Certificate:     %s (copied from %s)", paths.CACert, certCAPath)
	log.Printf("  Server Certificate: %s", paths.ServerCert)
	log.Printf("  Server Key:         %s", paths.ServerKey)
	log.Printf("  Client Certificate: %s", paths.ClientCert)
	log.Printf("  Client Key:         %s", paths.ClientKey)

	log.Printf("\nNext steps:")
	log.Printf("  1. Start the daemon with mTLS:")
	log.Printf("     sudo containarium daemon --mtls --certs-dir %s", certOutputDir)

	return nil
}
