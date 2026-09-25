package cmd

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/coderun"
	"github.com/footprintai/containarium/internal/connectcore"
	"github.com/spf13/cobra"
)

func TestShellQuoteSingle_RoundTripsThroughARealShell(t *testing.T) {
	cases := []string{
		"plain text",
		"it's got an apostrophe",
		"multiple ''' quotes '' in a row",
		"",
		"$(rm -rf /) and `also this`",
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			quoted := coderun.ShellQuoteSingle(in)
			// #nosec G204 -- fixed "sh -c" with a single literal-quoted
			// argument built by the function under test; this is the
			// injection check itself, not a caller-reachable path.
			out, err := exec.Command("/bin/sh", "-c", "printf '%s' "+quoted).Output()
			if err != nil {
				t.Fatalf("shell rejected %q (quoted as %q): %v", in, quoted, err)
			}
			if string(out) != in {
				t.Errorf("round-trip = %q, want %q (quoted form was %q)", out, in, quoted)
			}
		})
	}
}

func TestShellQuoteSingle_NeverEscapesOutOfTheQuotedString(t *testing.T) {
	// The classic injection shape: a naive quoter that doesn't handle
	// embedded quotes lets this argument terminate early and run a second
	// command.
	malicious := "'; touch /tmp/pwned; echo '"
	quoted := coderun.ShellQuoteSingle(malicious)
	// #nosec G204 -- see above.
	out, err := exec.Command("/bin/sh", "-c", "echo "+quoted).Output()
	if err != nil {
		t.Fatalf("shell rejected quoted input: %v", err)
	}
	got := strings.TrimSuffix(string(out), "\n")
	if got != malicious {
		t.Errorf("got %q, want the argument echoed back verbatim (%q) — the shell ran something other than plain echo", got, malicious)
	}
}

func TestBuildClaudeRunCommand(t *testing.T) {
	cmd := coderun.BuildClaudeRunCommand("fix the bug", false)
	for _, want := range []string{"secrets.env", "~/.local/bin/claude", "-p", coderun.ShellQuoteSingle("fix the bug")} {
		if !strings.Contains(cmd, want) {
			t.Errorf("command missing %q:\n%s", want, cmd)
		}
	}
	if strings.Contains(cmd, "stream-json") {
		t.Errorf("combined-mode command should not request stream-json:\n%s", cmd)
	}
}

func TestBuildClaudeRunCommand_StreamJSON(t *testing.T) {
	cmd := coderun.BuildClaudeRunCommand("fix the bug", true)
	if !strings.Contains(cmd, "--output-format stream-json") {
		t.Errorf("expected --output-format stream-json in:\n%s", cmd)
	}
}

func TestRunOutcomeLine(t *testing.T) {
	listing := "Found 2 process(es):\n\n" +
		"🟢 code  (pid 111, running)\n" +
		"   Command:    sleep 5\n" +
		"   Started at: 2026-09-02T12:00:00Z\n" +
		"   Log path:   /tmp/agent-box/code.log\n\n" +
		"⚪ old-task  (pid 222, exited)\n" +
		"   Command:    true\n" +
		"   Exit code:  0\n" +
		"   Log path:   /tmp/agent-box/old-task.log\n\n"

	line, running := coderun.RunOutcomeLine(listing, "code")
	if !running {
		t.Errorf("code should be reported running, line=%q", line)
	}
	if !strings.Contains(line, "code") || !strings.Contains(line, "running") {
		t.Errorf("line = %q", line)
	}

	line, running = coderun.RunOutcomeLine(listing, "old-task")
	if running {
		t.Errorf("old-task should not be reported running, line=%q", line)
	}
	if !strings.Contains(line, "old-task") {
		t.Errorf("line = %q", line)
	}

	line, running = coderun.RunOutcomeLine(listing, "does-not-exist")
	if running || line != "" {
		t.Errorf("unknown name should report not-running/empty line, got running=%v line=%q", running, line)
	}
}

func TestLogPathFromListing(t *testing.T) {
	listing := "Found 1 process(es):\n\n" +
		"🟢 code  (pid 111, running)\n" +
		"   Command:    claude -p hi\n" +
		"   Started at: 2026-09-02T12:00:00Z\n" +
		"   Log path:   /tmp/agent-box/code.log\n\n"

	got, err := coderun.LogPathFromListing(listing, "code")
	if err != nil {
		t.Fatalf("logPathFromListing: %v", err)
	}
	if got != "/tmp/agent-box/code.log" {
		t.Errorf("got %q, want /tmp/agent-box/code.log", got)
	}

	if _, err := coderun.LogPathFromListing(listing, "nope"); err == nil {
		t.Error("expected an error for a name not in the listing")
	}
}

// --- `code install` (#2030) ------------------------------------------------
//
// #2030 removed the CLAUDE_CODE_OAUTH_TOKEN tenant-secret precheck: a platform
// may not collect, store, or intermediate a Claude.ai credential
// (https://code.claude.com/docs/en/legal-and-compliance). The install lands a
// toolchain and nothing else; the user signs in inside the box, or places
// their own API key. These tests drive runCodeInstall through the sshExec /
// resolveCodeTargetFn seams, so no box, daemon, or ssh binary is involved.

// installRun is one captured remote exec: the script runCodeInstall asked the
// box to run.
type installRun struct {
	script string
}

// runInstall drives runCodeInstall against fakes and returns every remote
// script it ran, plus the command's own stdout.
func runInstall(t *testing.T, box string, flags map[string]string) ([]installRun, string, error) {
	t.Helper()

	origSSH, origResolve := sshExec, resolveCodeTargetFn
	origBootstrap, origRelease, origVersion := codeBootstrapURL, codeRelease, codeClaudeCodeVersion
	t.Cleanup(func() {
		sshExec, resolveCodeTargetFn = origSSH, origResolve
		codeBootstrapURL, codeRelease, codeClaudeCodeVersion = origBootstrap, origRelease, origVersion
	})

	codeBootstrapURL, codeRelease, codeClaudeCodeVersion = flags["bootstrap-url"], flags["release"], flags["claude-code-version"]

	var runs []installRun
	resolveCodeTargetFn = func(context.Context, string, io.Writer) (connectcore.Target, string, error) {
		return connectcore.Target{User: "alice", Host: "box.example.test", Port: 22}, "/dev/null", nil
	}
	sshExec = func(_ io.Writer, args []string) (string, error) {
		script := ""
		if len(args) > 0 {
			script = args[len(args)-1]
		}
		runs = append(runs, installRun{script: script})
		return "1.2.3 (Claude Code)\ncredential sources present:\n  (none)", nil
	}

	cmd := &cobra.Command{}
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetContext(context.Background())
	err := runCodeInstall(cmd, []string{box})
	return runs, out.String(), err
}

func allScripts(runs []installRun) string {
	var sb strings.Builder
	for _, r := range runs {
		sb.WriteString(r.script)
		sb.WriteString("\n")
	}
	return sb.String()
}

// TestCodeInstall_NoCredentialPrecheck is the headline #2030 AC: "Remove the
// CLAUDE_CODE_OAUTH_TOKEN tenant-secret precheck. `code install` neither
// reads, lists, nor names a Claude.ai token." It also pins that --server is no
// longer required, since the only reason it was is gone.
func TestCodeInstall_NoCredentialPrecheck(t *testing.T) {
	origServer := serverAddr
	serverAddr = "" // used to be a hard error: "--server is required"
	t.Cleanup(func() { serverAddr = origServer })

	runs, _, err := runInstall(t, "alice", nil)
	if err != nil {
		t.Fatalf("install failed with no --server and no credential set: %v", err)
	}
	if len(runs) == 0 {
		t.Fatal("no remote command ran")
	}

	scripts := allScripts(runs)
	banned := []string{
		"CLAUDE_CODE_OAUTH_TOKEN",
		"setup-token",
		"secrets set",
		"/run/secrets/",
	}
	for _, b := range banned {
		if strings.Contains(scripts, b) {
			t.Errorf("install scripts still reference %q:\n%s", b, scripts)
		}
	}
	// The same promise on the surface the user reads.
	help := codeInstallCmd.Long + "\n" + codeInstallCmd.Short
	for _, b := range banned {
		if strings.Contains(help, b) {
			t.Errorf("`code install` help still tells users about %q", b)
		}
	}
	// Anthropic's own installer line must be unchanged.
	if !strings.Contains(scripts, "curl -fsSL https://claude.ai/install.sh | bash") {
		t.Errorf("Anthropic's installer line is not run verbatim:\n%s", scripts)
	}
}

// TestCodeInstall_VerifyScript covers the replaced verification: `claude
// --version`, an assertion that the install created no ~/.claude/.credentials.json,
// and a report of which credential SOURCE is present — names only, never a
// value.
func TestCodeInstall_VerifyScript(t *testing.T) {
	script := claudeVerifyScript()

	tests := []struct {
		name   string
		want   string
		absent bool
	}{
		{name: "runs the installed binary's version", want: "/.local/bin/claude"},
		{name: "version, not a prompt", want: "--version"},
		{name: "no non-interactive prompt any more", want: "claude -p ", absent: true},
		{name: "asserts no credentials file was created", want: ".credentials.json"},
		{name: "names the API-key source", want: "ANTHROPIC_API_KEY"},
		{name: "names the auth-token source", want: "ANTHROPIC_AUTH_TOKEN"},
		{name: "names the settings.json env block", want: "settings.json"},
		{name: "names 3P inference providers", want: "CLAUDE_CODE_USE_"},
		// Presence only. Expanding any of these would put a live credential
		// into the CLI's own output and the user's scrollback.
		{name: "never expands the API key", want: `$ANTHROPIC_API_KEY`, absent: true},
		{name: "never expands the auth token", want: `$ANTHROPIC_AUTH_TOKEN`, absent: true},
		{name: "never cats the credentials file", want: "cat \"$HOME/.claude/.credentials.json\"", absent: true},
		{name: "never cats settings.json", want: "cat \"$settings\"", absent: true},
		// #1673's own rule, still true: bare mode is never used here.
		{name: "no bare mode", want: "--bare", absent: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := strings.Contains(script, tc.want)
			if tc.absent && got {
				t.Errorf("verify script must NOT contain %q:\n%s", tc.want, script)
			}
			if !tc.absent && !got {
				t.Errorf("verify script is missing %q:\n%s", tc.want, script)
			}
		})
	}

	if strings.Contains(claudeInstallScript, "--bare") {
		t.Error("install script must never pass --bare")
	}
}

// TestCodeInstall_BootstrapURLApplied covers the new --bootstrap-url: fetch a
// tarball, unpack it into a temp dir, run its apply.sh as the box user.
func TestCodeInstall_BootstrapURLApplied(t *testing.T) {
	const url = "https://example.test/bundles/team.tar.gz"
	runs, _, err := runInstall(t, "alice", map[string]string{"bootstrap-url": url})
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	scripts := allScripts(runs)
	for _, want := range []string{url, "tar -xz", "apply.sh", "mktemp -d"} {
		if !strings.Contains(scripts, want) {
			t.Errorf("bootstrap step is missing %q:\n%s", want, scripts)
		}
	}
	// The URL is caller-supplied and reaches a shell — it must be quoted.
	if !strings.Contains(scripts, coderun.ShellQuoteSingle(url)) {
		t.Errorf("bootstrap URL is not shell-quoted:\n%s", scripts)
	}
	// And it must not run as root: no sudo anywhere on this path.
	if strings.Contains(scripts, "sudo") {
		t.Errorf("bootstrap must run as the box user, not root:\n%s", scripts)
	}
}

func TestCodeInstall_BootstrapURLSkippedWhenEmpty(t *testing.T) {
	runs, _, err := runInstall(t, "alice", nil)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if scripts := allScripts(runs); strings.Contains(scripts, "apply.sh") {
		t.Errorf("no --bootstrap-url was given but a bootstrap step ran:\n%s", scripts)
	}
}

// TestCodeInstall_LandsAgentBox covers the #2030 AC that `code install` also
// lands the agent-box helper (and mcp-server) on PATH, so code
// run/attach/status/stop work on the same box rather than only on an
// agent-runtime recipe box.
func TestCodeInstall_LandsAgentBox(t *testing.T) {
	runs, _, err := runInstall(t, "alice", map[string]string{"release": "v9.9.9"})
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	scripts := allScripts(runs)
	for _, want := range []string{
		"releases/download/v9.9.9/agent-box-linux-amd64",
		"releases/download/v9.9.9/mcp-server-linux-amd64",
		"$HOME/.local/bin",
	} {
		if !strings.Contains(scripts, want) {
			t.Errorf("agent-box step is missing %q:\n%s", want, scripts)
		}
	}
}

// TestCodeInstall_DefaultReleaseIsVPrefixed pins the default for --release:
// the CLI's own version, v-prefixed, because release TAGS carry the v and
// pkg/version does not (see docs/RELEASE-PROCESS.md).
func TestCodeInstall_DefaultReleaseIsVPrefixed(t *testing.T) {
	got := defaultAgentBoxRelease()
	if !strings.HasPrefix(got, "v") {
		t.Errorf("default release %q must be v-prefixed to match the release tag", got)
	}
	if strings.HasPrefix(got, "vv") {
		t.Errorf("default release %q double-prefixed", got)
	}
}

// TestCodeInstall_ClaudeCodeVersionPinned covers --claude-code-version: the
// installer line itself is unchanged, the version is passed to it as an
// argument.
func TestCodeInstall_ClaudeCodeVersionPinned(t *testing.T) {
	runs, _, err := runInstall(t, "alice", map[string]string{"claude-code-version": "1.0.58"})
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	scripts := allScripts(runs)
	// Quoted: the version is a flag value reaching a shell.
	if !strings.Contains(scripts, claudeInstallScript+" -s "+coderun.ShellQuoteSingle("1.0.58")) {
		t.Errorf("--claude-code-version not passed to the installer:\n%s", scripts)
	}

	unpinned, _, err := runInstall(t, "alice", nil)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if strings.Contains(allScripts(unpinned), " -s ") {
		t.Error("an unpinned install must run the installer line verbatim")
	}
}

// TestCodeInstall_PrintsBothSignInPaths is the user-facing half of the terms
// change: after installing, the command has to say how to get a credential,
// because it no longer provides one.
func TestCodeInstall_PrintsBothSignInPaths(t *testing.T) {
	_, out, err := runInstall(t, "alice", nil)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	for _, want := range []string{
		"containarium connect alice",
		"claude",
		"ANTHROPIC_API_KEY",
		"settings.json",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("post-install output never mentions %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "CLAUDE_CODE_OAUTH_TOKEN") {
		t.Errorf("post-install output still names a Claude.ai OAuth token:\n%s", out)
	}
}

// TestCodeInstallScripts_AreValidPOSIXShell runs every script `code install`
// sends to a box through `sh -n`. They are built by string concatenation and
// executed on a remote host, where a syntax error surfaces as an opaque exit
// status hours after the typo.
func TestCodeInstallScripts_AreValidPOSIXShell(t *testing.T) {
	scripts := map[string]string{
		"claude-install":      claudeInstallScriptFor("1.2.3"),
		"claude-install-bare": claudeInstallScriptFor(""),
		"agent-box":           agentBoxInstallScript("v0.89.0"),
		"bootstrap":           bootstrapScript("https://example.test/b.tar.gz"),
		"verify":              claudeVerifyScript(),
	}
	for name, script := range scripts {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), name+".sh")
			if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command("/bin/sh", "-n", path).CombinedOutput()
			if err != nil {
				t.Errorf("sh -n rejected %s: %v\n%s\n--- script ---\n%s", name, err, out, script)
			}
		})
	}
}

// runVerifyScript executes claudeVerifyScript() against a throwaway HOME with
// a stub `claude` in place, so the script's actual behavior is tested — not
// just the strings it contains.
func runVerifyScript(t *testing.T, setup func(home string)) (string, string, error) {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".local", "bin"), 0o750); err != nil {
		t.Fatal(err)
	}
	stub := "#!/bin/sh\necho '1.2.3 (Claude Code)'\n"
	if err := os.WriteFile(filepath.Join(home, ".local", "bin", "claude"), []byte(stub), 0o700); err != nil { // #nosec G306 -- a stub the test then executes
		t.Fatal(err)
	}
	if setup != nil {
		setup(home)
	}
	path := filepath.Join(t.TempDir(), "verify.sh")
	if err := os.WriteFile(path, []byte(claudeVerifyScript()), 0o600); err != nil {
		t.Fatal(err)
	}
	c := exec.Command("/bin/sh", path) // #nosec G204 -- fixed interpreter, package-built script
	c.Env = append(os.Environ(), "HOME="+home, "ANTHROPIC_API_KEY=sk-should-never-be-echoed", "CLAUDE_CODE_USE_BEDROCK=1")
	var out, errBuf bytes.Buffer
	c.Stdout = &out
	c.Stderr = &errBuf
	err := c.Run()
	return out.String(), errBuf.String(), err
}

func writeClaudeFile(t *testing.T, home, name, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude", name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestCodeInstall_VerifyScriptReportsSourcesByName runs the script for real:
// a user-placed API key is a SUPPORTED path (it used to be a hard failure),
// and what gets reported is the key's NAME, never its value.
func TestCodeInstall_VerifyScriptReportsSourcesByName(t *testing.T) {
	stdout, stderr, err := runVerifyScript(t, func(home string) {
		writeClaudeFile(t, home, "settings.json", `{"env": {"ANTHROPIC_API_KEY": "sk-user-placed-secret"}}`)
	})
	if err != nil {
		t.Fatalf("verify failed although a user-placed API key is supported: %v\nstdout:%s\nstderr:%s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "1.2.3") {
		t.Errorf("version not reported:\n%s", stdout)
	}
	if !strings.Contains(stdout, "ANTHROPIC_API_KEY in the env block") {
		t.Errorf("settings.json API key not reported as a source:\n%s", stdout)
	}
	if !strings.Contains(stdout, "CLAUDE_CODE_USE_BEDROCK") {
		t.Errorf("3P inference provider not reported as a source:\n%s", stdout)
	}
	all := stdout + stderr
	for _, secret := range []string{"sk-user-placed-secret", "sk-should-never-be-echoed"} {
		if strings.Contains(all, secret) {
			t.Errorf("a credential VALUE reached the output: %q\n%s", secret, all)
		}
	}
}

// TestCodeInstall_VerifyScriptFailsWhenInstallMintedCredentials is the terms
// assertion: if a credentials file appears where the install step recorded
// none, the platform has minted or stored a Claude.ai credential and that is a
// hard failure.
func TestCodeInstall_VerifyScriptFailsWhenInstallMintedCredentials(t *testing.T) {
	stdout, stderr, err := runVerifyScript(t, func(home string) {
		// The install step recorded "absent"...
		state := filepath.Join(home, ".cache", "containarium")
		if mkErr := os.MkdirAll(state, 0o750); mkErr != nil {
			t.Fatal(mkErr)
		}
		if wErr := os.WriteFile(filepath.Join(state, "code-install-state"), []byte("absent\n"), 0o600); wErr != nil {
			t.Fatal(wErr)
		}
		// ...and yet one exists now.
		writeClaudeFile(t, home, ".credentials.json", `{"claudeAiOauth": {}}`)
	})
	if err == nil {
		t.Fatalf("expected a failure when the install created a credentials file\nstdout:%s\nstderr:%s", stdout, stderr)
	}
	if !strings.Contains(stderr, "never mints or stores") {
		t.Errorf("failure does not explain itself:\n%s", stderr)
	}
}

// TestCodeInstall_VerifyScriptAcceptsAPreExistingSignIn is the other side: a
// user who signed in through Anthropic's own flow before re-running install
// must not be treated as a violation — that sign-in is the documented path.
func TestCodeInstall_VerifyScriptAcceptsAPreExistingSignIn(t *testing.T) {
	stdout, stderr, err := runVerifyScript(t, func(home string) {
		state := filepath.Join(home, ".cache", "containarium")
		if mkErr := os.MkdirAll(state, 0o750); mkErr != nil {
			t.Fatal(mkErr)
		}
		if wErr := os.WriteFile(filepath.Join(state, "code-install-state"), []byte("present\n"), 0o600); wErr != nil {
			t.Fatal(wErr)
		}
		writeClaudeFile(t, home, ".credentials.json", `{"claudeAiOauth": {}}`)
	})
	if err != nil {
		t.Fatalf("a pre-existing sign-in was rejected: %v\nstdout:%s\nstderr:%s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "signed in through Anthropic's own flow") {
		t.Errorf("pre-existing sign-in not reported as the credential source:\n%s", stdout)
	}
}
