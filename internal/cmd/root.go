package cmd

import (
	"fmt"

	"github.com/footprintai/containarium/pkg/version"
	"github.com/spf13/cobra"
)

var (
	cfgFile    string
	verbose    bool
	serverAddr string
	certsDir   string
	insecure   bool
	verboseVersion bool
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
	},
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.containarium.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")

	// Remote gRPC server flags
	rootCmd.PersistentFlags().StringVar(&serverAddr, "server", "", "remote gRPC server address (e.g., 35.229.246.67:50051)")
	rootCmd.PersistentFlags().StringVar(&certsDir, "certs-dir", "", "directory containing mTLS certificates (default: ~/.config/containarium/certs)")
	rootCmd.PersistentFlags().BoolVar(&insecure, "insecure", false, "connect without TLS (not recommended)")

	// Version command with verbose flag
	versionCmd.Flags().BoolVar(&verboseVersion, "verbose", false, "show detailed version information")
	rootCmd.AddCommand(versionCmd)
}
