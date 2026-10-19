//go:build !windows && !containarium_client

package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
)

// Guards over the sshd AuthorizedKeysCommand drop-in the module's startup
// scripts install (#2527), on the regular VM and on the spot backend. Each
// script writes the drop-in from a heredoc whose
// only variable is $SSH_AUTHZ_KEYS_ARGS (the subcommand plus --token-file and,
// in enforce mode, --enforce); these tests render it both ways.

var sshAuthzStartupScripts = []string{
	"../../terraform/modules/containarium/scripts/startup.sh",
	"../../terraform/modules/containarium/scripts/startup-spot.sh",
}

func readStartupScript(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// renderSSHAuthzDropIn returns the drop-in exactly as the script writes it,
// for audit-only (enforce=false) or enforce mode.
func renderSSHAuthzDropIn(t *testing.T, script string, enforce bool) string {
	t.Helper()
	m := regexp.MustCompile(`(?s)<<SSHAUTHZEOF\n(.*?)\nSSHAUTHZEOF`).FindStringSubmatch(readStartupScript(t, script))
	if m == nil {
		t.Fatalf("found no SSHAUTHZEOF drop-in in %s — these guards would pass vacuously", script)
	}
	args := "ssh-authz-keys --token-file /etc/containarium-authz/ssh-authz-keys.token"
	if enforce {
		args += " --enforce"
	}
	body := strings.ReplaceAll(m[1], "$SSH_AUTHZ_KEYS_ARGS", args)
	if strings.Contains(body, "$") {
		t.Fatalf("drop-in still has an unrendered shell variable:\n%s", body)
	}
	return body
}

func sshdDirectives(body string) map[string]string {
	d := map[string]string{}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, _ := strings.Cut(line, " ")
		d[k] = strings.TrimSpace(v)
	}
	return d
}

func TestSSHAuthzDropIn_RendersTheKeysCommand(t *testing.T) {
	for _, script := range sshAuthzStartupScripts {
		t.Run(filepath.Base(script), func(t *testing.T) { checkSSHAuthzKeysCommand(t, script) })
	}
}

func checkSSHAuthzKeysCommand(t *testing.T, script string) {
	for _, enforce := range []bool{false, true} {
		body := renderSSHAuthzDropIn(t, script, enforce)
		if strings.Contains(body, "\nMatch ") || strings.HasPrefix(body, "Match ") {
			t.Errorf("enforce=%v: drop-in has a Match block (#1137):\n%s", enforce, body)
		}
		d := sshdDirectives(body)

		user := d["AuthorizedKeysCommandUser"]
		if user == "" || user == "root" {
			t.Errorf("enforce=%v: AuthorizedKeysCommandUser = %q, want the dedicated unprivileged account", enforce, user)
		}

		fields := strings.Fields(d["AuthorizedKeysCommand"])
		if len(fields) < 6 || !filepath.IsAbs(fields[0]) || fields[1] != sshAuthzKeysCmd.Name() {
			t.Fatalf("enforce=%v: AuthorizedKeysCommand = %q, want <absolute binary> %s ... %%u %%f %%t %%k",
				enforce, d["AuthorizedKeysCommand"], sshAuthzKeysCmd.Name())
		}
		if got := strings.Join(fields[len(fields)-4:], " "); got != "%u %f %t %k" {
			t.Errorf("enforce=%v: positional args = %q, want %q (login, fingerprint, key type, key)", enforce, got, "%u %f %t %k")
		}

		// The flags the script passes must be ones the subcommand accepts,
		// with the mode the operator chose.
		flags := sshAuthzKeysCmd.Flags()
		if err := flags.Parse(fields[2:]); err != nil {
			t.Fatalf("enforce=%v: subcommand rejects the drop-in's flags: %v", enforce, err)
		}
		if got, _ := flags.GetBool("enforce"); got != enforce {
			t.Errorf("enforce=%v: --enforce parsed as %v", enforce, got)
		}
		if got, _ := flags.GetString("token-file"); got != DefaultSSHAuthzKeysTokenFile {
			t.Errorf("enforce=%v: --token-file = %q, want %q", enforce, got, DefaultSSHAuthzKeysTokenFile)
		}
		if got := flags.Args(); len(got) != 4 {
			t.Errorf("enforce=%v: positional args = %v, want 4", enforce, got)
		}
		_ = flags.Set("enforce", "false")
	}
}

// Opt-in, validated, and never touching the static authorized_keys path.
func TestSSHAuthzDropIn_InstallIsOptInAndValidated(t *testing.T) {
	for _, path := range sshAuthzStartupScripts {
		t.Run(filepath.Base(path), func(t *testing.T) { checkSSHAuthzInstall(t, readStartupScript(t, path)) })
	}
}

func checkSSHAuthzInstall(t *testing.T, script string) {
	start := strings.Index(script, `if [ "$SSH_AUTHZ_KEYS_COMMAND" = "true" ]; then`)
	if start < 0 {
		t.Fatal("the AuthorizedKeysCommand install is not gated on ssh_authz_keys_command")
	}
	section := script[start:]
	if !strings.Contains(section, `"$SSHD_BIN" -t`) {
		t.Error("the drop-in must be validated with `sshd -t` before sshd restarts (#1137)")
	}
	if strings.Contains(section[:strings.Index(section, "SSHAUTHZEOF\n")], "AuthorizedKeysFile") {
		t.Error("the install must leave AuthorizedKeysFile alone: the static files are the sentinel's upstream path")
	}
	for _, want := range []string{"--scopes ssh:authorize", "chmod 0400", "CONTAINARIUM_SSH_AUTHZ_KEYS_COMMAND=true"} {
		if !strings.Contains(section, want) {
			t.Errorf("install section is missing %q", want)
		}
	}
}

// The real parser, where installed.
func TestSSHAuthzDropIn_ParsesUnderRealSSHD(t *testing.T) {
	sshd := findSSHD()
	if sshd == "" {
		t.Skip("sshd not installed; the structural checks above still apply")
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
	for _, script := range sshAuthzStartupScripts {
		for _, enforce := range []bool{false, true} {
			dropIn := filepath.Join(dir, "containarium-ssh-authz.conf")
			if err := os.WriteFile(dropIn, []byte(renderSSHAuthzDropIn(t, script, enforce)+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			main := filepath.Join(dir, "sshd_config")
			cfg := "Include " + dropIn + "\nHostKey " + hostKey + "\nUsePAM yes\n"
			if err := os.WriteFile(main, []byte(cfg), 0o600); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.Command(sshd, "-t", "-f", main).CombinedOutput(); err != nil {
				t.Errorf("%s enforce=%v: sshd rejected the drop-in:\n%s", filepath.Base(script), enforce, out)
			}
		}
	}
}

// The daemon never accepts a non-expiring token (--expiry 0 on an access
// token is the 15-minute default), so the install must keep re-minting it:
// a timer that fires at boot and well inside the token's lifetime.
func TestSSHAuthzDropIn_TokenIsRenewedBeforeItExpires(t *testing.T) {
	for _, path := range sshAuthzStartupScripts {
		t.Run(filepath.Base(path), func(t *testing.T) { checkSSHAuthzTokenRenewal(t, readStartupScript(t, path)) })
	}
}

func checkSSHAuthzTokenRenewal(t *testing.T, script string) {
	renew := regexp.MustCompile(`(?s)<<'SSHAUTHZRENEWEOF'\n(.*?)\nSSHAUTHZRENEWEOF`).FindStringSubmatch(script)
	if renew == nil {
		t.Fatal("found no SSHAUTHZRENEWEOF token-renewal script")
	}
	if regexp.MustCompile(`(?m)^[^#]*--expiry 0\b`).MatchString(script) {
		t.Error("--expiry 0 mints a 15-minute access token, not a non-expiring one")
	}
	m := regexp.MustCompile(`--expiry (\S+)`).FindStringSubmatch(renew[1])
	if m == nil {
		t.Fatal("the renewal script does not set --expiry")
	}
	lifetime, err := time.ParseDuration(m[1])
	if err != nil || lifetime <= 0 || lifetime > auth.DefaultMaxTokenExpiry {
		t.Fatalf("--expiry %q: want a positive duration within the daemon's %s cap (err %v)", m[1], auth.DefaultMaxTokenExpiry, err)
	}

	timer := regexp.MustCompile(`(?s)containarium-ssh-authz-token\.timer <<'EOF'\n(.*?)\nEOF`).FindStringSubmatch(script)
	if timer == nil {
		t.Fatal("found no containarium-ssh-authz-token.timer unit")
	}
	d := sshdDirectives(strings.ReplaceAll(timer[1], "=", " "))
	if d["OnBootSec"] == "" {
		t.Error("the timer must renew at boot: a stopped VM comes back with an expired token")
	}
	every, err := time.ParseDuration(d["OnUnitActiveSec"])
	if err != nil || every <= 0 || every > lifetime/2 {
		t.Errorf("OnUnitActiveSec %q: want a renewal at most half of the %s lifetime, so one missed run is survivable", d["OnUnitActiveSec"], lifetime)
	}
	if !strings.Contains(script, "systemctl enable containarium-ssh-authz-token.timer") {
		t.Error("the renewal timer is never enabled")
	}

	if sh, err := exec.LookPath("sh"); err == nil {
		cmd := exec.Command(sh, "-n")
		cmd.Stdin = strings.NewReader(renew[1])
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("the renewal script does not parse: %v\n%s", err, out)
		}
	}
}
