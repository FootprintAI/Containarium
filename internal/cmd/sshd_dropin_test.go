//go:build !windows

package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Guards over the sshd settings setup-ssh-container-proxy.sh installs (#1137).
//
// The incident shape: the script wrote PrintMotd/PrintLastLog inside a
// `Match` block. Those directives are not permitted inside Match, so the
// whole sshd config became unparseable and sshd refused to start on its next
// restart — taking SSH to the backend host down, and with it every box on
// that backend, since sshpiper's upstream is that host's sshd.
//
// Everything else kept running and the backend still reported healthy, so
// nothing surfaced the outage until someone tried to connect; recovery
// needed the machine's console. The trigger was whatever restarted sshd
// next, in practice an unattended-upgrades openssh update at an arbitrary
// later time — which is why this must be caught at build time and not left
// to "it worked when we ran it".

const sshProxyScript = "../../scripts/setup-ssh-container-proxy.sh"

func readSSHProxyScript(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(sshProxyScript)
	if err != nil {
		t.Fatalf("read %s: %v", sshProxyScript, err)
	}
	return string(b)
}

// sshdConfigBlocks returns the SSHDEOF heredoc bodies the script writes into
// sshd configuration — the exact text that lands on a host.
func sshdConfigBlocks(t *testing.T) []string {
	t.Helper()
	// Non-greedy so each heredoc is captured separately.
	re := regexp.MustCompile(`(?s)<< 'SSHDEOF'\n(.*?)\nSSHDEOF`)
	matches := re.FindAllStringSubmatch(readSSHProxyScript(t), -1)

	var blocks []string
	for _, m := range matches {
		// Only the sshd_config ones; the script has other heredocs.
		if strings.Contains(m[1], "PrintMotd") || strings.Contains(m[1], "PrintLastLog") {
			blocks = append(blocks, m[1])
		}
	}
	if len(blocks) == 0 {
		t.Fatal("found no sshd config blocks in the script — this guard would pass vacuously")
	}
	return blocks
}

// The cheap guard, and the one that runs everywhere: no Match block.
//
// PrintMotd/PrintLastLog inside Match is rejected wherever the file lives —
// the restriction is on Match, not on the drop-in directory. So "move it to
// the main sshd_config" is not a fix, and this check deliberately does not
// care which branch of the script wrote the block.
func TestSSHDDropInHasNoMatchBlock(t *testing.T) {
	for i, block := range sshdConfigBlocks(t) {
		for _, line := range strings.Split(block, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "Match ") {
				t.Errorf("sshd config block %d contains a Match block:\n\t%s\n"+
					"PrintMotd/PrintLastLog are not permitted inside Match — this makes the "+
					"entire sshd config unparseable, so sshd refuses to start on its next "+
					"restart and SSH to the host (and every box on it) is lost (#1137).",
					i, strings.TrimSpace(line))
			}
		}
	}
}

// The real check: hand the block to the actual sshd parser.
//
// A hand-rolled "does it look right" assertion would have missed the
// original bug too — the block looked entirely reasonable. Only the parser
// knows which directives Match accepts.
func TestSSHDDropInParsesUnderRealSSHD(t *testing.T) {
	sshd := findSSHD()
	if sshd == "" {
		t.Skip("sshd not installed; the Match guard above still applies")
	}
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not installed, cannot mint a host key for sshd -t")
	}

	dir := t.TempDir()
	hostKey := filepath.Join(dir, "hostkey")
	if out, err := exec.Command(keygen, "-q", "-t", "ed25519", "-f", hostKey, "-N", "").CombinedOutput(); err != nil {
		t.Skipf("ssh-keygen failed (%v): %s", err, out)
	}

	for i, block := range sshdConfigBlocks(t) {
		t.Run(fmt.Sprintf("block%d", i), func(t *testing.T) {
			dropInDir := filepath.Join(dir, fmt.Sprintf("sshd_config.d.%d", i))
			if err := os.MkdirAll(dropInDir, 0o755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			if err := os.WriteFile(filepath.Join(dropInDir, "containarium-motd.conf"), []byte(block+"\n"), 0o644); err != nil {
				t.Fatalf("write drop-in: %v", err)
			}

			// Stock-Ubuntu shape: the Include comes FIRST, global directives
			// after it. Some of those globals (Subsystem, UsePAM) are
			// themselves illegal inside Match, so this layout is what turns a
			// bad drop-in into a whole-config parse failure.
			main := filepath.Join(dir, fmt.Sprintf("sshd_config.%d", i))
			cfg := fmt.Sprintf("Include %s/*.conf\nHostKey %s\nSubsystem sftp /usr/lib/openssh/sftp-server\nUsePAM yes\n",
				dropInDir, hostKey)
			if err := os.WriteFile(main, []byte(cfg), 0o600); err != nil {
				t.Fatalf("write sshd_config: %v", err)
			}

			out, err := exec.Command(sshd, "-t", "-f", main).CombinedOutput()
			if err != nil {
				t.Errorf("sshd rejected the config this script installs (#1137):\n%s\n"+
					"A host that applies this loses sshd on its next restart.", out)
			}
		})
	}
}

// The other half of the incident: the failure was invisible because the
// reload discarded its own output and exit status, so the host looked
// healthy while carrying a config that would not survive a restart.
func TestSSHDReloadIsValidatedNotSuppressed(t *testing.T) {
	script := readSSHProxyScript(t)

	// Comments are stripped first: the fix's own comment quotes the old
	// `systemctl reload sshd 2>/dev/null || true` line to explain what went
	// wrong, and a naive scan matches that and fails on the explanation.
	suppressed := regexp.MustCompile(`systemctl reload sshd[^\n]*\|\|\s*true`)
	for i, line := range strings.Split(script, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if suppressed.MatchString(line) {
			t.Errorf("line %d: `systemctl reload sshd ... || true` discards the exit status, so an "+
				"invalid config installs silently: the running sshd keeps serving its "+
				"already-loaded config and the host looks fine until something restarts "+
				"ssh (#1137)\n\t%s", i+1, strings.TrimSpace(line))
		}
	}
	if !strings.Contains(script, `-t`) || !strings.Contains(script, "SSHD_BIN") {
		t.Error("the script must validate with `sshd -t` before reloading, so a bad config " +
			"fails the install instead of waiting to take the host down later (#1137)")
	}
}

func findSSHD() string {
	if p, err := exec.LookPath("sshd"); err == nil {
		return p
	}
	for _, p := range []string{"/usr/sbin/sshd", "/sbin/sshd"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
