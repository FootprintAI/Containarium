package main

import (
	"fmt"
	"os"

	"github.com/footprintai/containarium/internal/cmd"
)

var (
	// Version is set by ldflags during build
	Version = "dev"
	// BuildTime is set by ldflags during build
	BuildTime = "unknown"
)

func main() {
	// Set version info for commands
	cmd.SetVersionInfo(Version, BuildTime)

	// Execute root command
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
