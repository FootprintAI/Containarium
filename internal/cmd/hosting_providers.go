//go:build !containarium_client

package cmd

import (
	"fmt"

	"github.com/footprintai/containarium/internal/hosting"
	"github.com/spf13/cobra"
)

var hostingProvidersCmd = &cobra.Command{
	Use:   "providers",
	Short: "List supported DNS providers",
	Long: `List all supported DNS providers for hosting setup.

Each provider requires specific API credentials. Use the --help flag
with the setup command to see credential requirements for each provider.`,
	Run: runHostingProviders,
}

func init() {
	hostingCmd.AddCommand(hostingProvidersCmd)
}

func runHostingProviders(cmd *cobra.Command, args []string) {
	providers := hosting.SupportedProviders()

	fmt.Println("Supported DNS Providers:")
	fmt.Println()

	providerInfo := map[string]struct {
		name    string
		envVars []string
		docURL  string
	}{
		"godaddy": {
			name:    "GoDaddy",
			envVars: []string{"GODADDY_API_KEY", "GODADDY_API_SECRET"},
			docURL:  "https://developer.godaddy.com/keys",
		},
		// Future providers:
		// "cloudflare": {
		// 	name:    "Cloudflare",
		// 	envVars: []string{"CF_API_TOKEN"},
		// 	docURL:  "https://dash.cloudflare.com/profile/api-tokens",
		// },
	}

	for _, p := range providers {
		info, ok := providerInfo[p]
		if !ok {
			fmt.Printf("  - %s\n", p)
			continue
		}

		fmt.Printf("  %s (%s)\n", info.name, p)
		fmt.Printf("    Environment variables:\n")
		for _, env := range info.envVars {
			fmt.Printf("      - %s\n", env)
		}
		fmt.Printf("    Documentation: %s\n", info.docURL)
		fmt.Println()
	}

	fmt.Println("Usage:")
	fmt.Println("  containarium hosting setup --domain example.com --email admin@example.com --provider <provider>")
}
