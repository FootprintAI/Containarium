package cmd

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/footprintai/containarium/internal/connectcore"
	"github.com/footprintai/containarium/internal/hostport"
	"github.com/footprintai/containarium/internal/sshconfig"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/spf13/cobra"
)

var (
	sshConfigSentinel       string
	sshConfigJumpHost       string
	sshConfigPort           int
	sshConfigIdentity       string
	sshConfigUser           string
	sshConfigIncludeStopped bool
	sshConfigOutPath        string
	sshConfigForce          bool
)

var sshConfigCmd = &cobra.Command{
	Use:   "ssh-config",
	Short: "Generate a self-contained ssh_config for your containers",
	Long: `Generate an OpenSSH config file containing one Host block per container.

The file is self-contained — it does NOT modify your ~/.ssh/config. Add a
single line to ~/.ssh/config to wire it in once:

    Include ~/.containarium/ssh_config

After that, ` + "`ssh <container-name>`" + ` and ` + "`scp`" + ` work transparently.

Routing modes:

  - Local:               HostName=<container IP>; for LAN-reachable boxes.
  - Remote single VM:    ProxyJump through the API host's SSH port (22)
                         when the daemon does not advertise ssh_host.
                         Use --jump-host for an API tunnel or custom SSH port.
  - Via sentinel:        HostName=<sentinel>, User=<container-name>;
                         sshpiper on the sentinel routes by username.

Examples:

  # Print to stdout — review before writing
  containarium ssh-config show

  # Write the file (default: ~/.containarium/ssh_config)
  containarium ssh-config sync

  # Behind a sentinel
  containarium ssh-config sync --sentinel sentinel.example.com

  # Single VM with the API forwarded to localhost
  containarium ssh-config sync --http --server http://localhost:8080 --jump-host vm.example.com

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
		c.Flags().StringVar(&sshConfigJumpHost, "jump-host", "",
			"VM SSH endpoint (host or host:port) for boxes without ssh_host (default: remote API host on port 22; required for API tunnels)")
		c.Flags().StringVar(&sshConfigIdentity, "identity", "",
			"IdentityFile to render in every Host block (omitted by default)")
		c.Flags().StringVar(&sshConfigUser, "user", "",
			"Override per-Host User (default: container name in sentinel mode, ubuntu in direct mode)")
		c.Flags().BoolVar(&sshConfigIncludeStopped, "include-stopped", false,
			"Include stopped containers (default: only running)")
	}

	sshConfigSyncCmd.Flags().BoolVar(&sshConfigForce, "force", false,
		"overwrite the config even when this run generated 0 hosts (a zero-host run is usually an expired credential, not an empty fleet)")
	sshConfigSyncCmd.Flags().StringVar(&sshConfigOutPath, "out", "",
		"Output path (default: ~/.containarium/ssh_config)")
}

func runSSHConfigShow(cmd *cobra.Command, args []string) error {
	containers, err := loadContainersForSSHConfig()
	if err != nil {
		return err
	}
	g, err := generateManagedSSHConfig(containers)
	if err != nil {
		return err
	}
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
	g, err := generateManagedSSHConfig(containers)
	if err != nil {
		return err
	}

	out := sshConfigOutPath
	if out == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("resolve home dir: %w", err)
		}
		out = filepath.Join(home, ".containarium", "ssh_config")
	}

	// Atomic, backed up, and refuses to replace a real config with a
	// zero-host generation — see sshconfig.WriteConfig. A run that
	// enumerates nothing is usually a credential or control-plane
	// problem, not an empty fleet.
	backedUp, err := sshconfig.WriteConfig(out, g, sshConfigForce)
	if err != nil {
		return err
	}

	fmt.Printf("wrote %s (%d host(s), %d skipped stopped, %d skipped no-address)\n",
		out, g.Count, g.SkippedStopped, g.SkippedNoAddr)
	if backedUp {
		fmt.Printf("previous config saved to %s.bak\n", out)
	}
	fmt.Println()
	fmt.Println("If you haven't already, add this one line to ~/.ssh/config:")
	fmt.Println()
	fmt.Printf("    Include %s\n", out)
	fmt.Println()
	fmt.Println("Then `ssh <container-name>` will route correctly.")
	return nil
}

func sshConfigOptions() sshconfig.Options {
	jumpHost := sshConfigJumpHost
	if jumpHost == "" && serverAddr != "" {
		server := serverAddr
		if !strings.Contains(server, "://") {
			server = "//" + server
		}
		if u, err := url.Parse(server); err == nil {
			// The API port is not the SSH port. Keep only the hostname;
			// bracket IPv6 so hostport.Split can recognize a bare literal.
			jumpHost = u.Hostname()
			if strings.Contains(jumpHost, ":") {
				jumpHost = "[" + jumpHost + "]"
			}
		}
	}
	return sshconfig.Options{
		Sentinel:       sshConfigSentinel,
		JumpHost:       jumpHost,
		SentinelPort:   sshConfigPort,
		IdentityFile:   sshConfigIdentity,
		User:           sshConfigUser,
		IncludeStopped: sshConfigIncludeStopped,
	}
}

func generateManagedSSHConfig(containers []incus.ContainerInfo) (sshconfig.Generated, error) {
	opts := sshConfigOptions()
	if opts.Sentinel == "" && (serverAddr != "" || sshConfigJumpHost != "") {
		for _, c := range containers {
			if (!opts.IncludeStopped && !connectcore.IsRunning(c.State)) || c.SSHHost != "" || c.IPAddress == "" {
				continue
			}
			if opts.JumpHost == "" {
				return sshconfig.Generated{}, fmt.Errorf("cannot determine the VM SSH host for %s: pass --jump-host <vm-host>, configure the daemon's --ssh-host, or use --sentinel", c.Name)
			}
			host, _ := hostport.Split(opts.JumpHost, 22)
			if sshConfigJumpHost == "" && (strings.EqualFold(host, "localhost") || net.ParseIP(host).IsLoopback()) {
				return sshconfig.Generated{}, fmt.Errorf("the API host is loopback and may be an SSH tunnel: pass --jump-host <vm-host>, configure the daemon's --ssh-host, or use --sentinel")
			}
			if c.Username == "" {
				return sshconfig.Generated{}, fmt.Errorf("cannot determine the jump account for %s: the daemon must report a username; configure the daemon's --ssh-host or use --sentinel", c.Name)
			}
		}
	}
	return sshconfig.Generate(containers, opts), nil
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
