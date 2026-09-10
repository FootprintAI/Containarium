//go:build !containarium_client

package cmd

import (
	"fmt"
	"strings"

	"github.com/footprintai/containarium/internal/hosting"
	"github.com/spf13/cobra"
)

var showSecrets bool

var hostingConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "View or manage hosting configuration",
	Long: `View or manage the hosting configuration stored in /etc/containarium/hosting.json.

The configuration file contains:
  - DNS provider name
  - Domain name
  - Email for Let's Encrypt
  - API credentials (masked by default)

Examples:
  # View current configuration
  containarium hosting config

  # View configuration with credentials visible
  sudo containarium hosting config --show-secrets

  # Delete saved configuration
  containarium hosting config --delete`,
	RunE: runHostingConfig,
}

var deleteConfig bool

func init() {
	hostingCmd.AddCommand(hostingConfigCmd)
	hostingConfigCmd.Flags().BoolVar(&showSecrets, "show-secrets", false, "Show API credentials (requires root)")
	hostingConfigCmd.Flags().BoolVar(&deleteConfig, "delete", false, "Delete the saved configuration")
}

func runHostingConfig(cmd *cobra.Command, args []string) error {
	if deleteConfig {
		if err := hosting.DeleteConfig(); err != nil {
			return fmt.Errorf("failed to delete config: %w", err)
		}
		fmt.Printf("Configuration deleted: %s\n", hosting.ConfigPath())
		return nil
	}

	cfg, err := hosting.LoadConfig()
	if err != nil {
		return err
	}

	fmt.Println("Hosting Configuration")
	fmt.Println("=====================")
	fmt.Printf("Config file: %s\n", hosting.ConfigPath())
	fmt.Println()
	fmt.Printf("Provider:    %s\n", cfg.Provider)
	fmt.Printf("Domain:      %s\n", cfg.Domain)
	fmt.Printf("Email:       %s\n", cfg.Email)
	fmt.Println()
	fmt.Println("Credentials:")
	if showSecrets {
		fmt.Printf("  API Key:    %s\n", cfg.Credentials.APIKey)
		fmt.Printf("  API Secret: %s\n", cfg.Credentials.APISecret)
		if cfg.Credentials.APIToken != "" {
			fmt.Printf("  API Token:  %s\n", cfg.Credentials.APIToken)
		}
	} else {
		fmt.Printf("  API Key:    %s\n", maskString(cfg.Credentials.APIKey))
		fmt.Printf("  API Secret: %s\n", maskString(cfg.Credentials.APISecret))
		if cfg.Credentials.APIToken != "" {
			fmt.Printf("  API Token:  %s\n", maskString(cfg.Credentials.APIToken))
		}
		fmt.Println()
		fmt.Println("(Use --show-secrets to reveal credentials)")
	}

	return nil
}

// maskString masks a string showing only first 4 and last 4 characters
func maskString(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + strings.Repeat("*", len(s)-8) + s[len(s)-4:]
}
