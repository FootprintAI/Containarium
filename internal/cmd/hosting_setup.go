package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/footprintai/containarium/internal/hosting"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	// Setup flags
	setupDomain    string
	setupEmail     string
	setupProvider  string
	setupAPIKey    string
	setupAPISecret string
	setupServerIP  string
	skipDNS        bool
	skipCaddy      bool
	skipSaveConfig bool
	configFile     string
	noWildcard     bool
)

var hostingSetupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Set up DNS and SSL for app hosting",
	Long: `Automatically configure DNS records and SSL certificates for app hosting.

This command performs the following steps:
  1. Verifies DNS provider API credentials
  2. Verifies domain ownership in your DNS provider account
  3. Detects your server's public IP address (or uses --server-ip)
  4. Creates DNS records (A record for @ and * pointing to server IP)
  5. Installs Caddy with DNS provider plugin
  6. Configures Caddy for automatic Let's Encrypt SSL via DNS-01 challenge
  7. Starts Caddy service

Prerequisites:
  - Root/sudo access (for Caddy installation and systemd)
  - Go 1.21+ (for building Caddy with DNS plugin)
  - DNS provider API credentials

API Credentials:
  Credentials can be provided via (in priority order):
  1. Command line flags: --api-key and --api-secret
  2. Environment variables: GODADDY_API_KEY and GODADDY_API_SECRET
  3. Config file: /etc/containarium/hosting.json
  4. Interactive prompt (if not provided)

  After successful setup, credentials are saved to /etc/containarium/hosting.json
  with restricted permissions (0600). Use --no-save to skip saving.

Examples:
  # Interactive setup (prompts for credentials)
  sudo containarium hosting setup --domain example.com --email admin@example.com

  # Non-interactive with flags
  sudo containarium hosting setup \
    --domain example.com \
    --email admin@example.com \
    --provider godaddy \
    --api-key YOUR_KEY \
    --api-secret YOUR_SECRET

  # Using environment variables
  export GODADDY_API_KEY=your-key
  export GODADDY_API_SECRET=your-secret
  sudo containarium hosting setup --domain example.com --email admin@example.com

  # Skip DNS setup (if records already exist)
  sudo containarium hosting setup --domain example.com --email admin@example.com --skip-dns

  # Specify server IP manually
  sudo containarium hosting setup --domain example.com --email admin@example.com --server-ip 1.2.3.4`,
	RunE: runHostingSetup,
}

func init() {
	hostingCmd.AddCommand(hostingSetupCmd)

	// Required flags
	hostingSetupCmd.Flags().StringVar(&setupDomain, "domain", "", "Domain name (e.g., example.com)")
	hostingSetupCmd.Flags().StringVar(&setupEmail, "email", "", "Email for Let's Encrypt notifications")

	// Provider configuration
	hostingSetupCmd.Flags().StringVar(&setupProvider, "provider", "godaddy", "DNS provider (godaddy)")
	hostingSetupCmd.Flags().StringVar(&setupAPIKey, "api-key", "", "DNS provider API key (or use env var)")
	hostingSetupCmd.Flags().StringVar(&setupAPISecret, "api-secret", "", "DNS provider API secret (or use env var)")

	// Optional flags
	hostingSetupCmd.Flags().StringVar(&setupServerIP, "server-ip", "", "Server IP address (auto-detected if not provided)")
	hostingSetupCmd.Flags().BoolVar(&skipDNS, "skip-dns", false, "Skip DNS record creation")
	hostingSetupCmd.Flags().BoolVar(&skipCaddy, "skip-caddy", false, "Skip Caddy installation and configuration")
	hostingSetupCmd.Flags().BoolVar(&skipSaveConfig, "no-save", false, "Don't save credentials to config file")
	hostingSetupCmd.Flags().StringVar(&configFile, "config", "", "Config file path (default: /etc/containarium/hosting.json)")
	hostingSetupCmd.Flags().BoolVar(&noWildcard, "no-wildcard", false, "Only provision main domain (skip wildcard *.domain)")

	// Mark required
	hostingSetupCmd.MarkFlagRequired("domain")
	hostingSetupCmd.MarkFlagRequired("email")
}

func runHostingSetup(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Check if running as root (required for Caddy setup)
	if !skipCaddy && os.Geteuid() != 0 {
		return fmt.Errorf("this command requires root privileges for Caddy installation\nPlease run with sudo: sudo containarium hosting setup ...")
	}

	// Get API credentials
	apiKey, apiSecret, err := getAPICredentials(setupProvider)
	if err != nil {
		return err
	}

	// Create setup configuration
	cfg := hosting.SetupConfig{
		Domain:     setupDomain,
		Email:      setupEmail,
		Provider:   setupProvider,
		APIKey:     apiKey,
		APISecret:  apiSecret,
		ServerIP:   setupServerIP,
		SkipDNS:    skipDNS,
		SkipCaddy:  skipCaddy,
		NoWildcard: noWildcard,
		Verbose:    verbose,
	}

	// Create logger
	logger := func(format string, args ...interface{}) {
		fmt.Printf("[INFO] "+format+"\n", args...)
	}

	// Create and run setup
	setup, err := hosting.NewSetup(cfg, logger)
	if err != nil {
		return fmt.Errorf("failed to initialize setup: %w", err)
	}

	fmt.Println()
	fmt.Println("===========================================")
	fmt.Println("  Containarium Hosting Setup")
	fmt.Println("===========================================")
	fmt.Printf("  Domain:   %s\n", setupDomain)
	fmt.Printf("  Provider: %s\n", setupProvider)
	fmt.Printf("  Email:    %s\n", setupEmail)
	fmt.Println("===========================================")
	fmt.Println()

	result, err := setup.Run(ctx)
	if err != nil {
		return fmt.Errorf("setup failed: %w", err)
	}

	// Save configuration
	if !skipSaveConfig {
		hostingCfg := &hosting.Config{
			Provider: setupProvider,
			Domain:   setupDomain,
			Email:    setupEmail,
			Credentials: hosting.ProviderCredentials{
				APIKey:    apiKey,
				APISecret: apiSecret,
			},
		}

		var saveErr error
		if configFile != "" {
			saveErr = hosting.SaveConfigToFile(hostingCfg, configFile)
		} else {
			saveErr = hosting.SaveConfig(hostingCfg)
		}

		if saveErr != nil {
			fmt.Printf("[WARN] Failed to save config: %v\n", saveErr)
		} else {
			configPath := configFile
			if configPath == "" {
				configPath = hosting.ConfigPath()
			}
			fmt.Printf("[INFO] Credentials saved to %s\n", configPath)
		}
	}

	// Print summary
	printSetupSummary(result)

	return nil
}

func getAPICredentials(provider string) (string, string, error) {
	var apiKey, apiSecret string

	switch provider {
	case "godaddy":
		// Priority 1: Command-line flags
		apiKey = setupAPIKey
		apiSecret = setupAPISecret

		// Priority 2: Environment variables
		if apiKey == "" {
			apiKey = os.Getenv("GODADDY_API_KEY")
		}
		if apiSecret == "" {
			apiSecret = os.Getenv("GODADDY_API_SECRET")
		}

		// Priority 3: Config file
		if apiKey == "" || apiSecret == "" {
			var cfg *hosting.Config
			var err error
			if configFile != "" {
				cfg, err = hosting.LoadConfigFromFile(configFile)
			} else {
				cfg, err = hosting.LoadConfig()
			}
			if err == nil && cfg.Provider == provider {
				if apiKey == "" {
					apiKey = cfg.Credentials.APIKey
				}
				if apiSecret == "" {
					apiSecret = cfg.Credentials.APISecret
				}
				if apiKey != "" && apiSecret != "" {
					fmt.Println("[INFO] Loaded credentials from config file")
				}
			}
		}

		// Priority 4: Interactive prompt
		if apiKey == "" || apiSecret == "" {
			fmt.Println()
			fmt.Println("GoDaddy API credentials required.")
			fmt.Println("Get them from: https://developer.godaddy.com/keys")
			fmt.Println("(Select 'Production' environment when creating the key)")
			fmt.Println()

			if apiKey == "" {
				fmt.Print("Enter GoDaddy API Key: ")
				reader := bufio.NewReader(os.Stdin)
				key, err := reader.ReadString('\n')
				if err != nil {
					return "", "", fmt.Errorf("failed to read API key: %w", err)
				}
				apiKey = strings.TrimSpace(key)
			}

			if apiSecret == "" {
				fmt.Print("Enter GoDaddy API Secret: ")
				secretBytes, err := term.ReadPassword(int(syscall.Stdin))
				if err != nil {
					return "", "", fmt.Errorf("failed to read API secret: %w", err)
				}
				fmt.Println() // New line after password input
				apiSecret = strings.TrimSpace(string(secretBytes))
			}
		}

		if apiKey == "" || apiSecret == "" {
			return "", "", fmt.Errorf("API key and secret are required")
		}

	default:
		return "", "", fmt.Errorf("unsupported provider: %s", provider)
	}

	return apiKey, apiSecret, nil
}

func printSetupSummary(result *hosting.SetupResult) {
	fmt.Println()
	fmt.Println("===========================================")
	fmt.Println("  Setup Complete!")
	fmt.Println("===========================================")
	fmt.Println()
	fmt.Println("Configuration:")
	fmt.Printf("  Server IP:    %s\n", result.ServerIP)
	fmt.Printf("  DNS Created:  %v\n", result.DNSCreated)
	fmt.Printf("  Caddy Setup:  %v\n", result.CaddySetup)
	fmt.Printf("  Caddy Status: %s\n", result.CaddyStatus)
	if !skipSaveConfig {
		configPath := configFile
		if configPath == "" {
			configPath = hosting.ConfigPath()
		}
		fmt.Printf("  Config File:  %s\n", configPath)
	}
	fmt.Println()
	fmt.Println("DNS Records (may take a few minutes to propagate):")
	fmt.Printf("  %s      -> %s\n", setupDomain, result.ServerIP)
	fmt.Printf("  *.%s   -> %s\n", setupDomain, result.ServerIP)
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Wait for DNS propagation (1-5 minutes)")
	fmt.Println("  2. Start Containarium daemon with app hosting:")
	fmt.Println()
	fmt.Printf("     containarium daemon \\\n")
	fmt.Printf("       --app-hosting \\\n")
	fmt.Printf("       --base-domain '%s' \\\n", setupDomain)
	fmt.Printf("       --caddy-admin-url 'http://localhost:2019'\n")
	fmt.Println()
	fmt.Println("  3. Deploy an application:")
	fmt.Println()
	fmt.Println("     containarium app deploy myapp --source . --port 3000")
	fmt.Println()
	fmt.Println("  4. Access your app at:")
	fmt.Printf("     https://<username>-myapp.%s\n", setupDomain)
	fmt.Println()
	fmt.Println("Troubleshooting:")
	fmt.Println("  - Check Caddy logs:  journalctl -u caddy -f")
	fmt.Printf("  - Verify DNS:        dig +short %s\n", setupDomain)
	fmt.Printf("  - Test HTTPS:        curl -v https://%s\n", setupDomain)
	fmt.Println()
}
