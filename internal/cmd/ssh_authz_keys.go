//go:build !windows && !containarium_client

package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/internal/sshkey"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// `containarium ssh-authz-keys` is the jump host's sshd AuthorizedKeysCommand
// (#2527, part of the SSH live authorization design in #2515). It covers
// boxes reachable without the sentinel: a direct SSH login to the LXC jump
// host asks the local daemon's SSHAuthzService.Authorize, the same decision
// the sentinel plugin gets.
//
// sshd runs it as
//
//	containarium ssh-authz-keys %u %f %t %k
//
// and accepts the key only if it is printed back as an authorized_keys line.

const (
	// DefaultSSHAuthzKeysTokenFile holds the dedicated ssh:authorize JWT the
	// startup script mints at install time, readable only by
	// AuthorizedKeysCommandUser.
	DefaultSSHAuthzKeysTokenFile = "/etc/containarium-authz/ssh-authz-keys.token"
	// DefaultSSHAuthzKeysDaemonURL is the local daemon's REST gateway.
	DefaultSSHAuthzKeysDaemonURL = "http://127.0.0.1:8080"
	// defaultSSHAuthzKeysTimeout bounds the daemon call: sshd waits for the
	// command inside LoginGraceTime.
	defaultSSHAuthzKeysTimeout = 5 * time.Second
)

var (
	sshAuthzKeysTokenFile string
	sshAuthzKeysDaemonURL string
	sshAuthzKeysTimeout   time.Duration
	sshAuthzKeysEnforce   bool
)

var sshAuthzKeysCmd = &cobra.Command{
	Use:   "ssh-authz-keys <login> <fingerprint> <key-type> <key>",
	Short: "sshd AuthorizedKeysCommand: print the key only if the daemon authorizes it",
	Long: `Asks the local daemon whether <key> may open a session as <login>
(SSHAuthzService.Authorize) and prints it as an authorized_keys line on ALLOW.
On DENY it prints nothing, so sshd does not accept the key from this command.

Meant to be run by sshd, not by hand. The jump host's sshd drop-in runs it as:

  AuthorizedKeysCommand /usr/local/bin/containariumd ssh-authz-keys --token-file <file> %u %f %t %k

<fingerprint> must match <key> (sshd's SHA256 form); a mismatch is refused.

When the daemon cannot be asked (unreachable, token refused, timeout) no
decision is made: the command exits 0 in audit-only mode and 1 with --enforce.
Either way it prints nothing.

The token file holds a JWT carrying the ssh:authorize scope; the daemon must
run with --ssh-authz-keys-command to accept it.`,
	Args: cobra.ExactArgs(4),
	// sshd runs this as an unprivileged account with no home or credentials
	// file; skip the root command's server/token resolution.
	PersistentPreRunE: func(*cobra.Command, []string) error { return nil },
	SilenceUsage:      true,
	SilenceErrors:     true,
	RunE: func(cmd *cobra.Command, args []string) error {
		code := runSSHAuthzKeys(cmd.Context(), sshAuthzKeysOptions{
			Login:       args[0],
			Fingerprint: args[1],
			KeyType:     args[2],
			Key:         args[3],
			Enforce:     sshAuthzKeysEnforce,
			Timeout:     sshAuthzKeysTimeout,
			Authorize:   httpSSHAuthorizer(sshAuthzKeysDaemonURL, sshAuthzKeysTokenFile),
		}, os.Stdout, os.Stderr)
		if code != 0 {
			os.Exit(code)
		}
		return nil
	},
}

func init() {
	sshAuthzKeysCmd.Flags().StringVar(&sshAuthzKeysTokenFile, "token-file", DefaultSSHAuthzKeysTokenFile, "file holding the ssh:authorize JWT")
	sshAuthzKeysCmd.Flags().StringVar(&sshAuthzKeysDaemonURL, "daemon-url", DefaultSSHAuthzKeysDaemonURL, "local daemon REST URL")
	sshAuthzKeysCmd.Flags().DurationVar(&sshAuthzKeysTimeout, "timeout", defaultSSHAuthzKeysTimeout, "how long to wait for the daemon's decision")
	sshAuthzKeysCmd.Flags().BoolVar(&sshAuthzKeysEnforce, "enforce", false, "exit 1 (not 0) when the daemon cannot be asked")
	rootCmd.AddCommand(sshAuthzKeysCmd)
}

// sshAuthorizer is the daemon call; the CLI's is httpSSHAuthorizer, tests
// pass a fake.
type sshAuthorizer func(ctx context.Context, req *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error)

type sshAuthzKeysOptions struct {
	Login       string
	Fingerprint string
	KeyType     string
	Key         string
	Enforce     bool
	Timeout     time.Duration
	Authorize   sshAuthorizer
}

// runSSHAuthzKeys decides one AuthorizedKeysCommand call. It writes the
// authorized_keys line to stdout only on ALLOW, diagnostics to stderr (sshd
// logs them), and returns the exit code.
func runSSHAuthzKeys(ctx context.Context, o sshAuthzKeysOptions, stdout, stderr io.Writer) int {
	line := o.KeyType + " " + o.Key
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		fmt.Fprintf(stderr, "ssh-authz-keys: unparseable key for %q: %v\n", o.Login, err)
		return 1
	}
	if fp := ssh.FingerprintSHA256(pk); fp != o.Fingerprint {
		fmt.Fprintf(stderr, "ssh-authz-keys: fingerprint %q does not match the key (%s)\n", o.Fingerprint, fp)
		return 1
	}

	if ctx == nil {
		ctx = context.Background()
	}
	if o.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, o.Timeout)
		defer cancel()
	}
	resp, err := o.Authorize(ctx, &pb.AuthorizeSSHRequest{
		Login: o.Login,
		Credential: &pb.SSHCredential{Kind: &pb.SSHCredential_PublicKey{PublicKey: &pb.SSHPublicKeyCredential{
			FingerprintSha256: o.Fingerprint,
			KeyType:           sshkey.ParseType(line),
		}}},
	})
	if err != nil {
		mode, code := "audit-only", 0
		if o.Enforce {
			mode, code = "enforce", 1
		}
		fmt.Fprintf(stderr, "ssh-authz-keys: no decision for %q (%s): %v\n", o.Login, mode, err)
		return code
	}
	if resp.GetDecision() != pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW {
		fmt.Fprintf(stderr, "ssh-authz-keys: %q %s denied: %s\n", o.Login, o.Fingerprint, resp.GetDenyReason())
		return 0
	}
	fmt.Fprintln(stdout, line)
	return 0
}

// httpSSHAuthorizer calls the daemon's REST gateway with the token in
// tokenFile, read per call so a re-minted token takes effect without
// touching sshd.
func httpSSHAuthorizer(daemonURL, tokenFile string) sshAuthorizer {
	return func(ctx context.Context, req *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error) {
		// #nosec G304 -- operator-configured path from the sshd drop-in.
		raw, err := os.ReadFile(tokenFile)
		if err != nil {
			return nil, fmt.Errorf("read token: %w", err)
		}
		token := strings.TrimSpace(string(raw))
		if token == "" {
			return nil, fmt.Errorf("token file %s is empty", tokenFile)
		}
		c, err := client.NewHTTPClient(daemonURL, token)
		if err != nil {
			return nil, err
		}
		defer func() { _ = c.Close() }()
		return c.AuthorizeSSH(ctx, req)
	}
}
