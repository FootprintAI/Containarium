//go:build !windows

package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/footprintai/containarium/internal/cloud"
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
	daemonBinPath   = "/usr/local/bin/containarium"

	// sentinelAuthSecretFile holds CONTAINARIUM_SENTINEL_AUTH_SECRET for the
	// EnvironmentFile= directive in the pool drop-in (see renderPoolDropIn).
	// Separate from daemonDropIn (which stays 0644/no-secrets by convention,
	// #341) so the fleet-wide HMAC secret this host needs to authenticate
	// the sentinel's keysync/certsync requests never lands in a
	// world-readable file.
	sentinelAuthSecretFile = "/etc/containarium/sentinel-auth.env" // #nosec G101 -- a file PATH, not a credential
)

// minimalDaemonArgv is the baseline daemon command used when no existing
// ExecStart can be read (a fresh host). On a host that already runs the daemon
// with extra flags, those flags are preserved instead (see resolvePoolDaemonArgv).
func minimalDaemonArgv() []string {
	return []string{daemonBinPath, "daemon", "--rest", "--jwt-secret-file", "/etc/containarium/jwt.secret"}
}

var (
	poolJoinSentinels          []string
	poolJoinRegion             string
	poolJoinToken              string
	poolJoinPool               string
	poolJoinSpotID             string
	poolJoinPorts              string
	poolJoinPublicHostname     string
	poolJoinPublicPort         int
	poolJoinBaseDomain         string
	poolJoinDryRun             bool
	poolJoinDaemonFlags        []string
	poolJoinCloudControlPlane  string
	poolJoinCloudInsecure      bool
	poolJoinSentinelAuthSecret string
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
    --public-hostname node1.example.com --public-port 443

Multi-region (probe + pick the closest sentinel from the host):
  sudo containarium pool join --region auto \
    --sentinel us=us.sentinel.example.com:443 \
    --sentinel eu=eu.sentinel.example.com:443 \
    --pool prod --token <scoped-join-token>

BYO-compute (also register with a cloud control plane, using the same
token — the webui's "Add compute" one-liner sets this automatically):
  sudo containarium pool join \
    --sentinel asia-east1.containarium.dev:443 \
    --token <scoped-join-token> \
    --cloud-control-plane https://cloud.containarium.dev`,
	RunE: runPoolJoin,
}

func init() {
	poolCmd.AddCommand(poolJoinCmd)
	poolJoinCmd.Flags().StringArrayVar(&poolJoinSentinels, "sentinel", nil, "Sentinel this host dials, as host:port or region=host:port (repeatable). Pass several with --region auto to probe-and-select the closest (required)")
	poolJoinCmd.Flags().StringVar(&poolJoinRegion, "region", "", "With multiple --sentinel candidates: 'auto' probes RTT and picks the closest, or a region name picks that one. Single --sentinel ignores this")
	poolJoinCmd.Flags().StringVar(&poolJoinToken, "token", "", "Scoped join token for the tunnel handshake (required)")
	poolJoinCmd.Flags().StringVar(&poolJoinPool, "pool", "", "Pool to join (scopes daemon discovery + tunnel registration)")
	poolJoinCmd.Flags().StringVar(&poolJoinSpotID, "spot-id", "", "Unique id for this host in the pool (default: hostname)")
	poolJoinCmd.Flags().StringVar(&poolJoinPorts, "ports", "22,8080,443", "Comma-separated local ports to expose through the tunnel")
	poolJoinCmd.Flags().StringVar(&poolJoinPublicHostname, "public-hostname", "", "If set, register this host as the pool's public-routed primary for this hostname (needs --public-port)")
	poolJoinCmd.Flags().IntVar(&poolJoinPublicPort, "public-port", 0, "Public TLS port the sentinel forwards via this tunnel (typically 443; required with --public-hostname)")
	poolJoinCmd.Flags().StringVar(&poolJoinBaseDomain, "base-domain", "", "Base domain the daemon's Caddy auto-provisions HTTPS for (optional)")
	poolJoinCmd.Flags().BoolVar(&poolJoinDryRun, "dry-run", false, "Print the unit files that would be written, then exit (no changes)")
	poolJoinCmd.Flags().StringArrayVar(&poolJoinDaemonFlags, "daemon-flag", nil, "Extra daemon flag to carry into the unit (repeatable), e.g. --daemon-flag=--app-hosting --daemon-flag=--network-subnet=10.0.0.0/24. Use to add/override flags on top of the preserved/baseline set")
	poolJoinCmd.Flags().StringVar(&poolJoinCloudControlPlane, "cloud-control-plane", "", "Also self-register this host with a cloud control plane (e.g. https://cloud.containarium.dev) using the same --token, right after the tunnel comes up. Optional — omit for a plain OSS pool join with no cloud involvement. A failure here is a warning, not a join failure: the tunnel is joined either way.")
	poolJoinCmd.Flags().BoolVar(&poolJoinCloudInsecure, "cloud-insecure", false, "Dial --cloud-control-plane without TLS (local dev only; ignored unless --cloud-control-plane is set)")
	poolJoinCmd.Flags().StringVar(&poolJoinSentinelAuthSecret, "sentinel-auth-secret", os.Getenv("CONTAINARIUM_SENTINEL_AUTH_SECRET"), "Fleet-wide HMAC secret (32+ bytes) matching the sentinel's CONTAINARIUM_SENTINEL_AUTH_SECRET. Without it, the sentinel's keysync/certsync requests to this host's /authorized-keys get rejected with 401 — this host stays joined to the tunnel but never gets an SSH pipe (#687). Defaults to $CONTAINARIUM_SENTINEL_AUTH_SECRET; written to a root-only env file, never into the world-readable drop-in")
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

// renderPoolDropIn renders the daemon drop-in that sets ExecStart to the
// resolved argv (which already carries the preserved/baseline flags + --pool /
// --base-domain). Pure. systemd override semantics: clear then re-set.
//
// authSecretFile, when non-empty, adds an EnvironmentFile= directive pointing
// at the root-only file holding CONTAINARIUM_SENTINEL_AUTH_SECRET (#687) —
// never inline as Environment=, since this drop-in itself stays 0644/no-secrets
// by convention (#341).
func renderPoolDropIn(argv []string, authSecretFile string) string {
	var b strings.Builder
	b.WriteString("[Service]\n")
	if authSecretFile != "" {
		fmt.Fprintf(&b, "EnvironmentFile=%s\n", authSecretFile)
	}
	b.WriteString("ExecStart=\n")
	b.WriteString("ExecStart=" + strings.Join(argv, " ") + "\n")
	return b.String()
}

// parseExecStartArgv extracts the daemon argv from `systemctl show -p ExecStart
// --value containarium` output, whose value looks like:
//
//	{ path=/usr/local/bin/containarium ; argv[]=/usr/local/bin/containarium daemon --rest … ; ignore_errors=no ; … }
//
// Returns (argv, true) only when the value clearly is the containarium daemon
// command; (nil, false) otherwise (no unit, empty, or unrecognized). Pure.
// Note: values containing spaces aren't recovered (systemd doesn't re-quote
// them here) — daemon flag values (CIDRs, file paths, domains) don't have spaces.
func parseExecStartArgv(showOutput string) ([]string, bool) {
	i := strings.Index(showOutput, "argv[]=")
	if i < 0 {
		return nil, false
	}
	rest := showOutput[i+len("argv[]="):]
	if j := strings.Index(rest, " ; "); j >= 0 {
		rest = rest[:j]
	}
	fields := strings.Fields(rest)
	if len(fields) < 2 || !strings.HasSuffix(fields[0], "containarium") || fields[1] != "daemon" {
		return nil, false
	}
	return fields, true
}

// stripValuedFlag removes occurrences of a value-taking flag from argv, in both
// `--flag value` and `--flag=value` forms, so a managed flag (--pool /
// --base-domain) can be re-set to the current invocation's value without
// duplicating it. Pure.
func stripValuedFlag(argv []string, flag string) []string {
	out := make([]string, 0, len(argv))
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if a == flag {
			// Skip the following value token too, if present and not itself a flag.
			if i+1 < len(argv) && !strings.HasPrefix(argv[i+1], "-") {
				i++
			}
			continue
		}
		if strings.HasPrefix(a, flag+"=") {
			continue
		}
		out = append(out, a)
	}
	return out
}

// resolvePoolDaemonArgv builds the daemon ExecStart argv for the pool drop-in.
// It PRESERVES the host's existing daemon flags (#702) — so onboarding a host
// that already runs e.g. `--app-hosting --network-subnet <cidr>` doesn't
// silently drop them — then re-sets the managed flags (--pool, --base-domain)
// to this invocation's values, and finally appends any operator --daemon-flag
// overrides. When no existing ExecStart is readable (fresh host), the minimal
// baseline is used. Pure.
func resolvePoolDaemonArgv(current []string, found bool, pool, baseDomain string, extra []string) []string {
	var argv []string
	if found && len(current) >= 2 {
		argv = append(argv, current...)
	} else {
		argv = append(argv, minimalDaemonArgv()...)
	}
	// Re-set the flags we own so re-running is idempotent and value-updates take.
	argv = stripValuedFlag(argv, "--pool")
	argv = stripValuedFlag(argv, "--base-domain")
	if pool != "" {
		argv = append(argv, "--pool", pool)
	}
	if baseDomain != "" {
		argv = append(argv, "--base-domain", baseDomain)
	}
	argv = append(argv, extra...)
	return argv
}

// currentDaemonArgv reads the effective daemon ExecStart via systemctl. Returns
// (nil, false) when the unit doesn't exist / isn't readable / isn't recognized
// — the caller then falls back to the minimal baseline (and warns).
func currentDaemonArgv() ([]string, bool) {
	out, err := exec.Command("systemctl", "show", "-p", "ExecStart", "--value", "containarium").Output()
	if err != nil {
		return nil, false
	}
	return parseExecStartArgv(string(out))
}

func runPoolJoin(cmd *cobra.Command, args []string) error {
	if len(poolJoinSentinels) == 0 {
		return fmt.Errorf("--sentinel is required (the sentinel host:port this host dials; repeatable with --region auto)")
	}
	if poolJoinToken == "" {
		return fmt.Errorf("--token is required (the scoped join token)")
	}
	if poolJoinPublicHostname != "" && poolJoinPublicPort == 0 {
		return fmt.Errorf("--public-port is required when --public-hostname is set")
	}
	if poolJoinSentinelAuthSecret != "" && len(poolJoinSentinelAuthSecret) < 32 {
		return fmt.Errorf("--sentinel-auth-secret must be at least 32 characters (got %d)", len(poolJoinSentinelAuthSecret))
	}
	spotID := poolJoinSpotID
	if spotID == "" {
		h, err := os.Hostname()
		if err != nil || h == "" {
			return fmt.Errorf("--spot-id is required (could not derive a default from the hostname)")
		}
		spotID = h
	}

	// Resolve which sentinel to dial (#699). With one candidate this is a no-op;
	// with several + --region auto the host probes RTT and self-selects the
	// closest (latency can only be measured from here, not the control plane).
	cands, err := parseSentinelCandidates(poolJoinSentinels)
	if err != nil {
		return err
	}
	chosen, rows, err := resolveSentinel(cands, poolJoinRegion, nil)
	if err != nil {
		return err
	}
	if len(rows) > 0 { // probed (--region auto with >1 candidate)
		fmt.Printf("# Sentinel RTT probe:\n%s", formatRTTTable(rows))
	}
	if len(cands) > 1 {
		fmt.Printf("# Selected sentinel %s (region %q)\n", chosen.Addr, chosen.Region)
	}
	sentinelAddr := chosen.Addr

	// Preserve the host's existing daemon flags (#702): read the effective
	// ExecStart and carry its flags forward, rather than resetting to a minimal
	// command and silently dropping e.g. --app-hosting / --network-subnet.
	current, found := currentDaemonArgv()
	daemonArgv := resolvePoolDaemonArgv(current, found, poolJoinPool, poolJoinBaseDomain, poolJoinDaemonFlags)
	authSecretFile := ""
	if poolJoinSentinelAuthSecret != "" {
		authSecretFile = sentinelAuthSecretFile
	}
	dropIn := renderPoolDropIn(daemonArgv, authSecretFile)
	if !found {
		fmt.Println("# WARNING: could not read an existing daemon ExecStart.")
		fmt.Println("#   Using the minimal baseline (--rest --jwt-secret-file). If this host")
		fmt.Println("#   already ran the daemon with extra flags (e.g. --app-hosting,")
		fmt.Println("#   --network-subnet), pass them via --daemon-flag to preserve them.")
	} else {
		fmt.Printf("# Preserving existing daemon ExecStart flags; resulting command:\n#   %s\n", strings.Join(daemonArgv, " "))
	}
	if authSecretFile == "" {
		fmt.Println("# WARNING: --sentinel-auth-secret not set (and $CONTAINARIUM_SENTINEL_AUTH_SECRET is")
		fmt.Println("#   empty). This host will join the tunnel but the sentinel's keysync/certsync")
		fmt.Println("#   requests to it will be rejected with 401 — SSH to containers on this host")
		fmt.Println("#   will silently never work (#687). Pass --sentinel-auth-secret matching the")
		fmt.Println("#   sentinel's value to fix this now, or re-run with it set later.")
	}
	tunnel := renderTunnelUnit(tunnelUnitParams{
		SentinelAddr:   sentinelAddr,
		Token:          poolJoinToken,
		SpotID:         spotID,
		Ports:          poolJoinPorts,
		Pool:           poolJoinPool,
		PublicHostname: poolJoinPublicHostname,
		PublicPort:     poolJoinPublicPort,
	})

	if poolJoinDryRun {
		fmt.Printf("# would ensure the canonical daemon unit (%s) + JWT secret\n\n", systemdServicePath)
		if authSecretFile != "" {
			fmt.Printf("# %s (mode 0600, contents redacted)\nCONTAINARIUM_SENTINEL_AUTH_SECRET=<redacted, %d bytes>\n\n", authSecretFile, len(poolJoinSentinelAuthSecret))
		}
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
	// 1b. Sentinel HMAC auth secret (#687) — root-only, referenced by the
	// drop-in's EnvironmentFile= rather than embedded in it.
	if authSecretFile != "" {
		if err := os.MkdirAll("/etc/containarium", 0700); err != nil {
			return fmt.Errorf("create config directory: %w", err)
		}
		content := fmt.Sprintf("CONTAINARIUM_SENTINEL_AUTH_SECRET=%s\n", poolJoinSentinelAuthSecret)
		if err := os.WriteFile(authSecretFile, []byte(content), 0600); err != nil {
			return fmt.Errorf("write sentinel auth secret file: %w", err)
		}
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
	fmt.Printf("Joined pool %q via sentinel %s (spot-id %s).\n", poolJoinPool, sentinelAddr, spotID)

	// 6. Cloud self-registration (opt-in, --cloud-control-plane). Chains the
	// same join token into `cloud enroll` so a BYOC host shows up in the
	// cloud's own host list right away, instead of tunnel-connected-but-
	// invisible until an operator separately discovers and runs `cloud
	// enroll` by hand (containarium-cloud#799). Best-effort: the tunnel is
	// already joined by this point regardless of how this goes.
	if cp := strings.TrimSpace(poolJoinCloudControlPlane); cp != "" {
		fmt.Println()
		if err := cloudEnrollAfterPoolJoin(cmd, cp, poolJoinToken, "tunnel-"+spotID, poolJoinCloudInsecure); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "⚠ cloud enrollment failed (%v)\n  the tunnel is joined regardless; re-run `containarium cloud enroll --control-plane %s --token-file <token-file> --oss-backend-id tunnel-%s` once fixed\n", err, cp, spotID)
		}
	}

	fmt.Println()
	fmt.Println("  Daemon:  sudo systemctl status containarium")
	fmt.Println("  Tunnel:  sudo systemctl status containarium-tunnel")
	fmt.Println("  Verify:  containarium pool list --server http://localhost:8080")
	fmt.Println()
	fmt.Println("NOTE (MVP): scoped-token minting and binary fetch are not yet wired.")
	return nil
}

// cloudEnrollAfterPoolJoin redeems the same join token used for the tunnel
// handshake against a cloud control plane's EnrollHost, mirroring `cloud
// enroll` (internal/cmd/cloud.go) — the join-token format (`<host_id>.
// <secret>`) is shared between the two steps, so no separate token is
// needed. Mints a driver token best-effort (same as `cloud enroll`); a
// mint failure is a warning inside cloud.Enroll's caller pattern, not
// treated as fatal here either.
func cloudEnrollAfterPoolJoin(cmd *cobra.Command, controlPlane, token, ossBackendID string, insecure bool) error {
	opts := cloud.EnrollOptions{OSSBackendID: ossBackendID}
	if driverTok, mintErr := mintDriverToken(defaultDaemonJWTSecretFile, 30*24*time.Hour); mintErr != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "⚠ no driver token minted (%v)\n  host will cloud-enroll but the cloud can't place workloads on it yet\n", mintErr)
	} else {
		opts.DriverToken = driverTok
	}

	hostID, err := cloud.Enroll(cmd.Context(), controlPlane, token, insecure, opts)
	if err != nil {
		return err
	}
	cfg := &cloud.Config{
		ControlPlane: controlPlane,
		HostID:       hostID,
		Token:        token,
		Insecure:     insecure,
		JWTSecretFile: func() string {
			if opts.DriverToken == "" {
				return ""
			}
			return defaultDaemonJWTSecretFile
		}(),
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	path, err := cloud.DefaultPath()
	if err != nil {
		return err
	}
	if err := cloud.Save(path, cfg); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "✓ also enrolled with cloud control plane %s\n  host-id: %s\n  config:  %s (restart the daemon to start actuating + reporting)\n",
		controlPlane, hostID, path)
	return nil
}
