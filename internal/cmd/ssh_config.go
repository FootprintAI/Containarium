package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/internal/sshconfig"
	"github.com/spf13/cobra"
)

var (
	sshConfigSentinel       string
	sshConfigPort           int
	sshConfigIdentity       string
	sshConfigUser           string
	sshConfigIncludeStopped bool
	sshConfigOutPath        string
)

var sshConfigCmd = &cobra.Command{
	Use:   "ssh-config",
	Short: "Generate a self-contained ssh_config for your containers",
	Long: `Generate an OpenSSH config file containing one Host block per container.

The file is self-contained — it does NOT modify your ~/.ssh/config. Add a
single line to ~/.ssh/config to wire it in once:

    Include ~/.containarium/ssh_config

After that, ` + "`ssh <container-name>`" + ` and ` + "`scp`" + ` work transparently.

Two routing modes:

  - Direct (default):    HostName=<container IP>; for LAN-reachable boxes.
  - Via sentinel:        HostName=<sentinel>, User=<container-name>;
                         sshpiper on the sentinel routes by username.

Examples:

  # Print to stdout — review before writing
  containarium ssh-config show

  # Write the file (default: ~/.containarium/ssh_config)
  containarium ssh-config sync

  # Behind a sentinel
  containarium ssh-config sync --sentinel sentinel.example.com

  # With a dedicated identity file
  containarium ssh-config sync --identity ~/.ssh/containarium_ed25519`,
}

var sshConfigShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Print the generated ssh_config to stdout",
	RunE:  runSSHConfigShow,
}

var sshConfigSyncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Write the generated ssh_config to disk",
	RunE:  runSSHConfigSync,
}

func init() {
	rootCmd.AddCommand(sshConfigCmd)
	sshConfigCmd.AddCommand(sshConfigShowCmd, sshConfigSyncCmd)

	for _, c := range []*cobra.Command{sshConfigShowCmd, sshConfigSyncCmd} {
		c.Flags().StringVar(&sshConfigSentinel, "sentinel", "",
			"Sentinel SSH endpoint (e.g. sentinel.example.com or sentinel.example.com:2222). "+
				"When set, all entries route through it via sshpiper. Empty = direct mode.")
		c.Flags().IntVar(&sshConfigPort, "sentinel-port", 22,
			"SSH port on the sentinel (overridden by host:port form in --sentinel)")
		c.Flags().StringVar(&sshConfigIdentity, "identity", "",
			"IdentityFile to render in every Host block (omitted by default)")
		c.Flags().StringVar(&sshConfigUser, "user", "",
			"Override per-Host User (default: container name in sentinel mode, ubuntu in direct mode)")
		c.Flags().BoolVar(&sshConfigIncludeStopped, "include-stopped", false,
			"Include stopped containers (default: only running)")
	}

	sshConfigSyncCmd.Flags().StringVar(&sshConfigOutPath, "out", "",
		"Output path (default: ~/.containarium/ssh_config)")
}

func runSSHConfigShow(cmd *cobra.Command, args []string) error {
	containers, err := loadContainersForSSHConfig()
	if err != nil {
		return err
	}
	g := sshconfig.Generate(containers, sshConfigOptions())
	fmt.Print(g.Content)
	fmt.Fprintf(os.Stderr,
		"\n# %d host(s) generated, %d skipped (stopped), %d skipped (no address)\n",
		g.Count, g.SkippedStopped, g.SkippedNoAddr)
	return nil
}

func runSSHConfigSync(cmd *cobra.Command, args []string) error {
	containers, err := loadContainersForSSHConfig()
	if err != nil {
		return err
	}
	g := sshconfig.Generate(containers, sshConfigOptions())

	out := sshConfigOutPath
	if out == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("resolve home dir: %w", err)
		}
		out = filepath.Join(home, ".containarium", "ssh_config")
	}

	if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(out), err)
	}
	// 0600 — the file lists every host the user can SSH to. Treat it as
	// sensitive so it doesn't leak in a backup or shared shell.
	if err := os.WriteFile(out, []byte(g.Content), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", out, err)
	}

	fmt.Printf("wrote %s (%d host(s), %d skipped stopped, %d skipped no-address)\n",
		out, g.Count, g.SkippedStopped, g.SkippedNoAddr)
	fmt.Println()
	fmt.Println("If you haven't already, add this one line to ~/.ssh/config:")
	fmt.Println()
	fmt.Printf("    Include %s\n", out)
	fmt.Println()
	fmt.Println("Then `ssh <container-name>` will route correctly.")
	return nil
}

func sshConfigOptions() sshconfig.Options {
	return sshconfig.Options{
		Sentinel:       sshConfigSentinel,
		SentinelPort:   sshConfigPort,
		IdentityFile:   sshConfigIdentity,
		User:           sshConfigUser,
		IncludeStopped: sshConfigIncludeStopped,
	}
}

// loadContainersForSSHConfig pulls the container list using whichever
// transport the global flags select — same logic as `containarium list`.
// Reusing those helpers keeps the source-of-truth single.
func loadContainersForSSHConfig() ([]incus.ContainerInfo, error) {
	if httpMode && serverAddr != "" {
		return listRemoteHTTP()
	}
	if serverAddr != "" {
		return listRemote()
	}
	return listLocal()
}
