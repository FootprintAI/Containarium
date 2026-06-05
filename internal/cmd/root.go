package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/footprintai/containarium/internal/releases"
	"github.com/footprintai/containarium/pkg/version"
	"github.com/spf13/cobra"
)

var (
	cfgFile        string
	verbose        bool
	versionCheck   bool
	serverAddr     string
	certsDir       string
	insecure       bool
	verboseVersion bool
	// HTTP mode flags
	httpMode  bool
	authToken string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "containarium",
	Short: "Containarium - SSH Jump Server + LXC Container Platform",
	Long: `Containarium is a production-ready platform for providing isolated
development environments using LXC containers on a single cloud VM.

It enables you to:
  - Create isolated Ubuntu containers with Docker support
  - Manage SSH access for multiple users
  - Deploy infrastructure with Terraform
  - Efficiently utilize cloud resources (10x savings vs VM-per-user)

Examples:
  # Create a new container for user alice
  containarium create alice --ssh-key ~/.ssh/alice.pub

  # List all containers
  containarium list

  # Delete a container
  containarium delete alice

  # Show system information
  containarium info`,
	// PersistentPreRunE fills in the auth token from the
	// credentials file when neither --token nor
	// CONTAINARIUM_TOKEN are set. Precedence:
	//   1. --token flag (explicit)
	//   2. CONTAINARIUM_TOKEN env var (becomes the flag default
	//      in init() below — so by the time this runs, both
	//      collapse into authToken)
	//   3. ~/.containarium/credentials.json (server matching
	//      --server, else default_server)
	// See `containarium login --help`.
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// login / logout / whoami / config get-token are the
		// commands that produce/consume the credentials file
		// directly. Skip the auto-fill for them — login is
		// unauthenticated by definition, and we don't want a
		// stale token to leak into a logout call.
		switch {
		case cmd == loginCmd, cmd == logoutCmd, cmd == whoamiCmd, cmd == configGetTokenCmd:
			return nil
		}
		if authToken == "" {
			authToken = resolveAuthToken(serverAddr)
		}
		return nil
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() error {
	return rootCmd.Execute()
}

// SetVersionInfo is deprecated - version info is now managed by pkg/version package
// This function is kept for backward compatibility but does nothing
func SetVersionInfo(ver, build string) {
	// Version info is now set via build-time ldflags in pkg/version
	// See Makefile for usage
}

// initConfig reads in config file and ENV variables if set
func initConfig() {
	// TODO: implement config file reading with viper
	if verbose {
		fmt.Println("Verbose mode enabled")
	}
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Long: `Display version information for Containarium.

Use --verbose flag for detailed build information including Git commit, build time, Go version, and platform.`,
	Run: func(cmd *cobra.Command, args []string) {
		if verboseVersion {
			fmt.Println(version.Verbose())
		} else {
			fmt.Println(version.String())
		}
		if versionCheck {
			runVersionCheck(cmd)
		}
	},
}

// runVersionCheck queries GitHub for the latest published release and
// reports whether this binary is behind it (#354). Server-less — it asks
// GitHub directly, so it works without a daemon configured.
func runVersionCheck(cmd *cobra.Command) {
	ctx, cancel := context.WithTimeout(cmd.Context(), 12*time.Second)
	defer cancel()
	rel, _, err := releases.NewClient().Latest(ctx)
	if err != nil {
		fmt.Printf("\nCould not check for updates: %v\n", err)
		return
	}
	cur := version.GetVersion()
	fmt.Printf("\ncurrent: %s\nlatest:  %s\n", cur, rel.TagName)
	if releases.IsBehind(cur, rel.TagName) {
		fmt.Printf("⚠ a newer release is available: %s\n", rel.HTMLURL)
	} else {
		fmt.Println("✓ up to date")
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.containarium.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")

	// Remote server flags (gRPC mode). Env vars provide defaults so the
	// CLI can be driven non-interactively (CI, scripts, GitHub Actions)
	// without repeating flags on every invocation.
	rootCmd.PersistentFlags().StringVar(&serverAddr, "server", os.Getenv("CONTAINARIUM_SERVER"), "remote server address (env: CONTAINARIUM_SERVER) — e.g., 35.229.246.67:50051 for gRPC, or http://host:8080 for HTTP")
	rootCmd.PersistentFlags().StringVar(&certsDir, "certs-dir", os.Getenv("CONTAINARIUM_CERTS_DIR"), "directory containing mTLS certificates (env: CONTAINARIUM_CERTS_DIR; default: ~/.config/containarium/certs)")
	rootCmd.PersistentFlags().BoolVar(&insecure, "insecure", os.Getenv("CONTAINARIUM_INSECURE") == "true", "connect without TLS (env: CONTAINARIUM_INSECURE=true; not recommended)")

	// Remote server flags (HTTP mode)
	rootCmd.PersistentFlags().BoolVar(&httpMode, "http", os.Getenv("CONTAINARIUM_HTTP") == "true", "use HTTP/REST API instead of gRPC (env: CONTAINARIUM_HTTP=true)")
	rootCmd.PersistentFlags().StringVar(&authToken, "token", os.Getenv("CONTAINARIUM_TOKEN"), "JWT authentication token for HTTP API. Precedence: 1) --token flag, 2) CONTAINARIUM_TOKEN env, 3) ~/.containarium/credentials.json (populated by `containarium login`).")

	// Version command with verbose flag
	versionCmd.Flags().BoolVar(&verboseVersion, "verbose", false, "show detailed version information")
	versionCmd.Flags().BoolVar(&versionCheck, "check", false, "check GitHub for a newer release and report drift")
	rootCmd.AddCommand(versionCmd)
}
