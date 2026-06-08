package runner

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHEndpoint resolves a box name to the (user, host, port) tuple
// we'll SSH into. Real callers typically:
//
//   - return "<name>@<sentinel-host>:22" when boxes are reached
//     through sshpiper (typical Containarium-Cloud deployment), or
//   - return "ubuntu@<box-ip>:22" when the agent has L3 reach to
//     the box's LAN IP (typical self-hosted OSS daemon).
//
// Factored as an interface so the runner package doesn't pull in
// the containarium client / config plumbing. The CLI / MCP code
// build whatever resolver is appropriate for their environment
// and pass it through.
type SSHEndpoint interface {
	Resolve(ctx context.Context, boxName string) (user, hostport string, err error)
}

// SSHEndpointFunc is the function shape of SSHEndpoint.Resolve so
// callers can pass a closure directly without defining a type.
type SSHEndpointFunc func(ctx context.Context, boxName string) (user, hostport string, err error)

// Resolve makes SSHEndpointFunc satisfy SSHEndpoint.
func (f SSHEndpointFunc) Resolve(ctx context.Context, boxName string) (string, string, error) {
	return f(ctx, boxName)
}

// SSHInstallerConfig is the typed config for NewSSHInstaller.
type SSHInstallerConfig struct {
	// Endpoint resolves a box name to its SSH host:port + user.
	Endpoint SSHEndpoint

	// PrivateKeyPath points at the PEM-encoded private key used
	// to dial the box. Required — install needs root to drop a
	// systemd unit, so the key has to map to a user with sudo.
	PrivateKeyPath string

	// HostKeyCallback runs against the box's host key. Default
	// (nil) means InsecureIgnoreHostKey — fine for ephemeral
	// runner boxes on a private network where the daemon
	// already established the trust boundary, but pass your
	// own KnownHosts callback for hardened environments.
	HostKeyCallback ssh.HostKeyCallback

	// DialTimeout caps the per-SSH-dial TCP handshake + auth.
	// Default 15s.
	DialTimeout time.Duration
}

// NewSSHInstaller returns a RunnerInstaller that ships the
// embedded install script over SSH and runs it inside the box.
// The same instance is safe to share across goroutines.
func NewSSHInstaller(cfg SSHInstallerConfig) (RunnerInstaller, error) {
	if cfg.Endpoint == nil {
		return nil, fmt.Errorf("ssh endpoint resolver is required")
	}
	if cfg.PrivateKeyPath == "" {
		return nil, fmt.Errorf("private key path is required")
	}
	keyBytes, err := os.ReadFile(expandTilde(cfg.PrivateKeyPath))
	if err != nil {
		return nil, fmt.Errorf("read ssh key %s: %w", cfg.PrivateKeyPath, err)
	}
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse ssh key %s: %w", cfg.PrivateKeyPath, err)
	}
	if cfg.HostKeyCallback == nil {
		// InsecureIgnoreHostKey is the right default for the
		// runner-provision case: the boxes we're SSHing to were
		// just created by the same daemon, on a network the
		// agent already trusts. Pin host keys via the
		// HostKeyCallback option when running across an
		// untrusted path.
		cfg.HostKeyCallback = ssh.InsecureIgnoreHostKey() // #nosec G106 -- ephemeral runner box, intentional default
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 15 * time.Second
	}
	return &sshInstaller{
		endpoint:    cfg.Endpoint,
		signer:      signer,
		hostKeyCB:   cfg.HostKeyCallback,
		dialTimeout: cfg.DialTimeout,
	}, nil
}

type sshInstaller struct {
	endpoint    SSHEndpoint
	signer      ssh.Signer
	hostKeyCB   ssh.HostKeyCallback
	dialTimeout time.Duration
}

func (s *sshInstaller) IsInstalled(ctx context.Context, boxName string) (bool, error) {
	// `systemctl is-enabled` exits 0 when the unit exists and is
	// enabled, non-zero otherwise. The check itself is harmless
	// (read-only). We pipe to /dev/null so its noisy stderr
	// doesn't leak into our install logs.
	const cmd = `sudo test -f /etc/systemd/system/containarium-runner.service && sudo systemctl is-enabled containarium-runner.service >/dev/null 2>&1 && echo INSTALLED || echo NOT_INSTALLED`
	stdout, _, err := s.runCommand(ctx, boxName, cmd, nil)
	if err != nil {
		return false, fmt.Errorf("ssh probe: %w", err)
	}
	return strings.Contains(stdout, "INSTALLED") && !strings.Contains(stdout, "NOT_INSTALLED"), nil
}

func (s *sshInstaller) Install(ctx context.Context, boxName string, script []byte, env map[string]string) error {
	// We stream the embedded script via stdin into `sudo bash`
	// (with env vars set on the command line) so the script
	// content never lands on the box's filesystem outside of
	// what install.sh itself writes. Same effect as the manual
	// `curl … | sudo … bash` flow documented in hacks/runner.
	var envPrefix strings.Builder
	envPrefix.WriteString("sudo ")
	// Stable ordering for deterministic logs / tests.
	for _, k := range sortedKeys(env) {
		// Shell-quote the value defensively — PATs and labels
		// can contain characters that would otherwise break the
		// command line.
		fmt.Fprintf(&envPrefix, "%s=%s ", k, shellQuote(env[k]))
	}
	envPrefix.WriteString("bash -s")

	_, stderr, err := s.runCommand(ctx, boxName, envPrefix.String(), script)
	if err != nil {
		return fmt.Errorf("install script: %w (stderr: %s)", err, stderr)
	}
	return nil
}

// runCommand opens a fresh SSH connection to boxName, runs cmd
// with stdin from `input`, and returns (stdout, stderr, err).
// Connections are not pooled — each call dials fresh, which is
// simple and matches the relatively-low call volume of provision.
func (s *sshInstaller) runCommand(ctx context.Context, boxName, cmd string, input []byte) (string, string, error) {
	user, hostport, err := s.endpoint.Resolve(ctx, boxName)
	if err != nil {
		return "", "", fmt.Errorf("resolve ssh endpoint for %s: %w", boxName, err)
	}

	dialer := &net.Dialer{Timeout: s.dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", hostport)
	if err != nil {
		return "", "", fmt.Errorf("dial %s: %w", hostport, err)
	}

	sshConfig := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(s.signer)},
		HostKeyCallback: s.hostKeyCB,
		Timeout:         s.dialTimeout,
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, hostport, sshConfig)
	if err != nil {
		_ = conn.Close()
		return "", "", fmt.Errorf("ssh handshake %s: %w", hostport, err)
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	defer func() { _ = client.Close() }()

	session, err := client.NewSession()
	if err != nil {
		return "", "", fmt.Errorf("ssh session: %w", err)
	}
	defer func() { _ = session.Close() }()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr
	if input != nil {
		session.Stdin = bytes.NewReader(input)
	}

	if err := session.Run(cmd); err != nil {
		return stdout.String(), stderr.String(), fmt.Errorf("ssh run: %w", err)
	}
	return stdout.String(), stderr.String(), nil
}

// expandTilde turns "~/foo" into "$HOME/foo". Mirrors the helper
// in internal/cmd/create.go but kept local so this package has
// no dependency on the cmd package.
func expandTilde(p string) string {
	if !strings.HasPrefix(p, "~/") {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	return filepath.Join(home, p[2:])
}

// shellQuote wraps a value in single quotes with embedded single
// quotes escaped as '\”. Enough for PATs and label strings; we
// deliberately don't try to support arbitrary shell metachars in
// runner names (validated upstream).
func shellQuote(v string) string {
	return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'"
}

// sortedKeys is a tiny helper so install logs (and tests) see env
// vars in a stable order regardless of map iteration randomness.
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// Manual sort to keep imports minimal — n is always 4.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}
