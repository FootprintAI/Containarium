//go:build !windows

package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
)

// pool join — the turnkey, one-command path that turns a fresh Linux host
// into a member of YOUR pool (prd/oss/byo-compute-pool-join.md). It
// productizes the manual install-lab-*.sh ritual: it ensures the canonical
// hardened daemon unit (reusing the same template `service install` writes —
// no hand-authored, capability-trap-prone unit), drops in the --pool config,
// and writes + starts the tunnel unit that dials the sentinel.
//
// MVP scope: it assumes the binary is already at /usr/local/bin/containarium
// and that the operator passes a join token. Deferred to follow-ups (per the
// PRD): the `doctor` capability self-check, scoped short-lived token minting,
// binary fetch/--binary-src, and a --role=tunnel-only variant.

const (
	tunnelUnitPath  = "/etc/systemd/system/containarium-tunnel.service"
	daemonDropInDir = "/etc/systemd/system/containarium.service.d"
	daemonDropIn    = daemonDropInDir + "/pool.conf"
)

var (
	poolJoinSentinel       string
	poolJoinToken          string
	poolJoinPool           string
	poolJoinSpotID         string
	poolJoinPorts          string
	poolJoinPublicHostname string
	poolJoinPublicPort     int
	poolJoinBaseDomain     string
	poolJoinDryRun         bool
)

var poolJoinCmd = &cobra.Command{
	Use:   "join",
	Short: "Turn THIS host into a member of your pool (run on the host, as root)",
	Long: `Join this host to your compute pool in one command. Writes the canonical
hardened daemon unit (same template as 'service install'), a --pool
drop-in, and the tunnel unit that dials your sentinel — then enables and
starts both. Idempotent: re-running re-applies the config.

Run ON the host you're adding, as root. Use --dry-run to print the unit
files without writing anything.

Example:
  sudo containarium pool join \
    --sentinel sentinel.example.com:443 \
    --pool prod \
    --token <scoped-join-token> \
    --public-hostname node1.example.com --public-port 443`,
	RunE: runPoolJoin,
}

func init() {
	poolCmd.AddCommand(poolJoinCmd)
	poolJoinCmd.Flags().StringVar(&poolJoinSentinel, "sentinel", "", "Sentinel address host:port this host dials (required)")
	poolJoinCmd.Flags().StringVar(&poolJoinToken, "token", "", "Scoped join token for the tunnel handshake (required)")
	poolJoinCmd.Flags().StringVar(&poolJoinPool, "pool", "", "Pool to join (scopes daemon discovery + tunnel registration)")
	poolJoinCmd.Flags().StringVar(&poolJoinSpotID, "spot-id", "", "Unique id for this host in the pool (default: hostname)")
	poolJoinCmd.Flags().StringVar(&poolJoinPorts, "ports", "22,8080,443", "Comma-separated local ports to expose through the tunnel")
	poolJoinCmd.Flags().StringVar(&poolJoinPublicHostname, "public-hostname", "", "If set, register this host as the pool's public-routed primary for this hostname (needs --public-port)")
	poolJoinCmd.Flags().IntVar(&poolJoinPublicPort, "public-port", 0, "Public TLS port the sentinel forwards via this tunnel (typically 443; required with --public-hostname)")
	poolJoinCmd.Flags().StringVar(&poolJoinBaseDomain, "base-domain", "", "Base domain the daemon's Caddy auto-provisions HTTPS for (optional)")
	poolJoinCmd.Flags().BoolVar(&poolJoinDryRun, "dry-run", false, "Print the unit files that would be written, then exit (no changes)")
}

// tunnelUnitParams are the inputs to the tunnel systemd unit.
type tunnelUnitParams struct {
	SentinelAddr   string
	Token          string
	SpotID         string
	Ports          string
	Pool           string
	PublicHostname string
	PublicPort     int
}

// renderTunnelUnit renders the containarium-tunnel.service unit. Pure (no
// I/O) so the rendering is unit-tested without touching systemd.
func renderTunnelUnit(p tunnelUnitParams) string {
	var b strings.Builder
	desc := "Containarium Tunnel Client"
	if p.Pool != "" {
		desc = fmt.Sprintf("Containarium Tunnel Client (%s pool)", p.Pool)
	}
	fmt.Fprintf(&b, "[Unit]\nDescription=%s\n", desc)
	b.WriteString("Documentation=https://github.com/footprintai/Containarium\n")
	b.WriteString("After=network-online.target\nWants=network-online.target\n\n")
	b.WriteString("[Service]\nType=simple\n")
	b.WriteString("ExecStart=/usr/local/bin/containarium tunnel \\\n")
	fmt.Fprintf(&b, "  --sentinel-addr %s \\\n", p.SentinelAddr)
	fmt.Fprintf(&b, "  --token %s \\\n", p.Token)
	fmt.Fprintf(&b, "  --spot-id %s \\\n", p.SpotID)
	fmt.Fprintf(&b, "  --ports %s", p.Ports)
	if p.Pool != "" {
		fmt.Fprintf(&b, " \\\n  --pool %s", p.Pool)
	}
	if p.PublicHostname != "" {
		fmt.Fprintf(&b, " \\\n  --public-hostname %s", p.PublicHostname)
		if p.PublicPort > 0 {
			fmt.Fprintf(&b, " \\\n  --public-port %d", p.PublicPort)
		}
	}
	b.WriteString("\n")
	b.WriteString("Restart=always\nRestartSec=5s\nTimeoutStopSec=10s\n")
	b.WriteString("User=root\nGroup=root\n")
	b.WriteString("StandardOutput=journal\nStandardError=journal\nSyslogIdentifier=containarium-tunnel\n")
	b.WriteString("LimitNOFILE=65536\n\n")
	b.WriteString("[Install]\nWantedBy=multi-user.target\n")
	return b.String()
}

// renderPoolDropIn renders the daemon drop-in that adds --pool (and an
// optional --base-domain) on top of the canonical unit's ExecStart. Pure.
func renderPoolDropIn(pool, baseDomain string) string {
	var b strings.Builder
	b.WriteString("[Service]\n")
	// Clear then re-set ExecStart (systemd override semantics).
	b.WriteString("ExecStart=\n")
	b.WriteString("ExecStart=/usr/local/bin/containarium daemon \\\n")
	b.WriteString("  --rest \\\n")
	b.WriteString("  --jwt-secret-file /etc/containarium/jwt.secret")
	if pool != "" {
		fmt.Fprintf(&b, " \\\n  --pool %s", pool)
	}
	if baseDomain != "" {
		fmt.Fprintf(&b, " \\\n  --base-domain %s", baseDomain)
	}
	b.WriteString("\n")
	return b.String()
}

func runPoolJoin(cmd *cobra.Command, args []string) error {
	if poolJoinSentinel == "" {
		return fmt.Errorf("--sentinel is required (the sentinel host:port this host dials)")
	}
	if poolJoinToken == "" {
		return fmt.Errorf("--token is required (the scoped join token)")
	}
	if poolJoinPublicHostname != "" && poolJoinPublicPort == 0 {
		return fmt.Errorf("--public-port is required when --public-hostname is set")
	}
	spotID := poolJoinSpotID
	if spotID == "" {
		h, err := os.Hostname()
		if err != nil || h == "" {
			return fmt.Errorf("--spot-id is required (could not derive a default from the hostname)")
		}
		spotID = h
	}

	dropIn := renderPoolDropIn(poolJoinPool, poolJoinBaseDomain)
	tunnel := renderTunnelUnit(tunnelUnitParams{
		SentinelAddr:   poolJoinSentinel,
		Token:          poolJoinToken,
		SpotID:         spotID,
		Ports:          poolJoinPorts,
		Pool:           poolJoinPool,
		PublicHostname: poolJoinPublicHostname,
		PublicPort:     poolJoinPublicPort,
	})

	if poolJoinDryRun {
		fmt.Printf("# would ensure the canonical daemon unit (%s) + JWT secret\n\n", systemdServicePath)
		fmt.Printf("# %s\n%s\n", daemonDropIn, dropIn)
		fmt.Printf("# %s\n%s\n", tunnelUnitPath, tunnel)
		fmt.Println("# (dry-run: nothing written; re-run without --dry-run as root to apply)")
		return nil
	}

	if os.Geteuid() != 0 {
		return fmt.Errorf("this command requires root privileges (use sudo), or pass --dry-run to preview")
	}

	// 1. Canonical hardened daemon unit + JWT secret (shared with `service install`).
	if err := ensureDaemonUnitAndSecret(); err != nil {
		return err
	}
	// 2. --pool drop-in on the daemon unit.
	// #nosec G301 -- systemd drop-in dir, world-readable config by convention (no secrets)
	if err := os.MkdirAll(daemonDropInDir, 0755); err != nil {
		return fmt.Errorf("create drop-in dir: %w", err)
	}
	// #nosec G306 -- systemd unit/drop-in, world-readable config by convention (matches `service install`); no secrets
	if err := os.WriteFile(daemonDropIn, []byte(dropIn), 0644); err != nil {
		return fmt.Errorf("write pool drop-in: %w", err)
	}
	// 3. Tunnel unit (dials the sentinel; this is what joins the pool).
	// #nosec G306 -- systemd unit, world-readable config by convention; no secrets (the token lives in the unit but is operator-scoped, same as the manual install)
	if err := os.WriteFile(tunnelUnitPath, []byte(tunnel), 0644); err != nil {
		return fmt.Errorf("write tunnel unit: %w", err)
	}
	// 4. Reload + enable --now both, idempotently. Unit names are fixed
	// literals (not user input), kept as separate calls so the args are
	// constant.
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w", err)
	}
	if err := exec.Command("systemctl", "enable", "--now", "containarium").Run(); err != nil {
		return fmt.Errorf("systemctl enable --now containarium: %w", err)
	}
	if err := exec.Command("systemctl", "enable", "--now", "containarium-tunnel").Run(); err != nil {
		return fmt.Errorf("systemctl enable --now containarium-tunnel: %w", err)
	}

	// 5. Capability self-check (deploy-contract): refuse to report "joined" if
	// this host can't actually run the daemon's user management. NOTE: run
	// from this (root) process, so it catches missing paths / incus / useradd
	// / non-root — but NOT the daemon-unit capability trap (this shell has
	// full caps). The daemon's own startup self-check is the definitive
	// unit-constrained check.
	fmt.Println()
	fmt.Println("Host capability self-check (containarium doctor):")
	if failed := printDoctor(hostDoctorChecks()); failed > 0 {
		return fmt.Errorf("pool join: %d required capability check(s) FAILED — units were installed but this host is NOT a healthy pool member yet; fix the above and re-run", failed)
	}

	fmt.Println()
	fmt.Printf("Joined pool %q via sentinel %s (spot-id %s).\n", poolJoinPool, poolJoinSentinel, spotID)
	fmt.Println()
	fmt.Println("  Daemon:  sudo systemctl status containarium")
	fmt.Println("  Tunnel:  sudo systemctl status containarium-tunnel")
	fmt.Println("  Verify:  containarium pool list --server http://localhost:8080")
	fmt.Println()
	fmt.Println("NOTE (MVP): scoped-token minting and binary fetch are not yet wired.")
	return nil
}
