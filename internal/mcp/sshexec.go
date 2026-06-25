package mcp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/connectcore"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// The in-box MCP `connect` tool runs INSIDE a box (e.g. the Alpine/musl
// managed-workspace LXC), where there is no system `ssh` binary to shell
// out to. So the exec/session paths use a pure-Go SSH client
// (golang.org/x/crypto/ssh) — the same approach internal/runner uses to
// provision boxes — making the mcp-server self-contained in any minimal
// image. Config mode still hands the human a ready `ssh …` line to run in
// their own terminal; only the non-interactive exec paths dial in-process.

const (
	mcpSSHDialTimeout = 15 * time.Second
	mcpSSHExecTimeout = 90 * time.Second
)

// dialSSH opens a pure-Go SSH client to the target using the managed
// private key at privPath. No system `ssh` binary required.
func dialSSH(ctx context.Context, t connectcore.Target, privPath string) (*ssh.Client, error) {
	keyBytes, err := os.ReadFile(privPath) // #nosec G304 -- privPath is the managed key sshkey.LocateOrGenerate resolved
	if err != nil {
		return nil, fmt.Errorf("read managed key %s: %w", privPath, err)
	}
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse managed key: %w", err)
	}
	hostKeyCB, err := tofuHostKeyCallback()
	if err != nil {
		return nil, err
	}
	cfg := &ssh.ClientConfig{
		User:            t.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hostKeyCB,
		Timeout:         mcpSSHDialTimeout,
	}
	hostport := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	d := &net.Dialer{Timeout: mcpSSHDialTimeout}
	conn, err := d.DialContext(ctx, "tcp", hostport)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", hostport, err)
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, hostport, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ssh handshake %s: %w", hostport, err)
	}
	return ssh.NewClient(sshConn, chans, reqs), nil
}

// tofuHostKeyCallback returns an accept-new (trust-on-first-use) host-key
// callback backed by ~/.ssh/known_hosts — the pure-Go equivalent of ssh's
// StrictHostKeyChecking=accept-new the CLI uses: an unknown host is
// recorded and trusted, but a CHANGED key for a known host is rejected
// (MITM detection). This preserves the CLI's posture without shelling out.
func tofuHostKeyCallback() (ssh.HostKeyCallback, error) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = os.TempDir() // minimal container with no HOME — still get in-file TOFU
	}
	khPath := filepath.Join(home, ".ssh", "known_hosts")
	if err := os.MkdirAll(filepath.Dir(khPath), 0o700); err != nil {
		return nil, fmt.Errorf("create known_hosts dir: %w", err)
	}
	// knownhosts.New needs the file to exist; create it empty if absent.
	f, err := os.OpenFile(khPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 -- fixed ~/.ssh/known_hosts path
	if err != nil {
		return nil, fmt.Errorf("open known_hosts: %w", err)
	}
	_ = f.Close()
	known, err := knownhosts.New(khPath)
	if err != nil {
		return nil, fmt.Errorf("load known_hosts: %w", err)
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		verr := known(hostname, remote, key)
		if verr == nil {
			return nil
		}
		var keyErr *knownhosts.KeyError
		if errors.As(verr, &keyErr) && len(keyErr.Want) == 0 {
			// Unknown host → record it (accept-new), then trust.
			return appendKnownHost(khPath, hostname, key)
		}
		// Known host whose key changed → reject (potential MITM).
		return verr
	}, nil
}

func appendKnownHost(path, hostname string, key ssh.PublicKey) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 -- fixed ~/.ssh/known_hosts path
	if err != nil {
		return fmt.Errorf("open known_hosts for append: %w", err)
	}
	defer func() { _ = f.Close() }()
	line := knownhosts.Line([]string{knownhosts.Normalize(hostname)}, key)
	if _, err := f.WriteString(line + "\n"); err != nil {
		return fmt.Errorf("record host key: %w", err)
	}
	return nil
}

// runMCPSSHExec runs one command over a pure-Go SSH session and returns its
// stdout/stderr + exit code. A non-zero remote exit is NOT a tool error —
// the command ran; the agent needs the output and the code. Only a failure
// to connect or open the session is an error.
func runMCPSSHExec(t connectcore.Target, privPath, execCmd string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), mcpSSHExecTimeout)
	defer cancel()

	client, err := dialSSH(ctx, t, privPath)
	if err != nil {
		return "", err
	}
	defer func() { _ = client.Close() }()

	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("ssh session: %w", err)
	}
	defer func() { _ = session.Close() }()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	exitCode := 0
	if runErr := session.Run(execCmd); runErr != nil {
		var ee *ssh.ExitError
		if errors.As(runErr, &ee) {
			exitCode = ee.ExitStatus()
		} else {
			return "", fmt.Errorf("ssh run: %w", runErr)
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "exit_code: %d\n", exitCode)
	if stdout.Len() > 0 {
		fmt.Fprintf(&b, "\n--- stdout ---\n%s", stdout.String())
	}
	if stderr.Len() > 0 {
		fmt.Fprintf(&b, "\n--- stderr ---\n%s", stderr.String())
	}
	return b.String(), nil
}

// runMCPSessionExec runs one command inside a named tmux session on the box
// (Tier 2) over a pure-Go SSH session, piping the orchestration script on
// stdin, and returns the framed output + exit code. Like runMCPSSHExec, a
// non-zero remote exit is data, not a tool error.
func runMCPSessionExec(target connectcore.Target, privPath, session, command string) (string, error) {
	marker, err := connectcore.NewMarker()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), mcpSSHExecTimeout)
	defer cancel()

	client, err := dialSSH(ctx, target, privPath)
	if err != nil {
		return "", err
	}
	defer func() { _ = client.Close() }()

	sess, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("ssh session: %w", err)
	}
	defer func() { _ = sess.Close() }()

	// The orchestration script reads positional args: $1 session $2 marker
	// $3 base64-command $4 timeout. session is validated [A-Za-z0-9_-],
	// marker is hex, the command is base64, timeout is an int — all safe as
	// bare words, so no shell quoting is needed.
	remote := "bash -s -- " + strings.Join([]string{
		session, marker, connectcore.EncodeCommand(command), "60",
	}, " ")

	sess.Stdin = strings.NewReader(connectcore.SessionExecScript())
	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr
	if runErr := sess.Run(remote); runErr != nil {
		var ee *ssh.ExitError
		if !errors.As(runErr, &ee) {
			return "", fmt.Errorf("session exec: %w", runErr)
		}
		// Non-zero ssh exit still carries framed output we parse below.
	}

	out, code, perr := connectcore.ParseSessionResult(stdout.String(), marker)
	if perr != nil {
		if stderr.Len() > 0 {
			return "", fmt.Errorf("%w (ssh: %s)", perr, strings.TrimSpace(stderr.String()))
		}
		return "", perr
	}
	var b strings.Builder
	fmt.Fprintf(&b, "session: %s\nexit_code: %d\n", session, code)
	if out != "" {
		fmt.Fprintf(&b, "\n--- output ---\n%s", out)
	}
	return b.String(), nil
}
