package server

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/footprintai/containarium/internal/coderun/engine"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// runSh executes script with `sh -c`, with chown stubbed out so the script can
// run as an ordinary user in a test sandbox (the real one runs as root in a box).
func runSh(t *testing.T, script string) string {
	t.Helper()
	out, err := exec.Command("sh", "-c", "chown() { :; }\n"+script).CombinedOutput()
	if err != nil {
		t.Fatalf("script failed: %v\n%s\n--- script ---\n%s", err, out, script)
	}
	return string(out)
}

func TestBoxRunScripts_ParseAsShell(t *testing.T) {
	stage, err := boxRunStageScript("/home/alice", "/home/ctn-run")
	if err != nil {
		t.Fatal(err)
	}
	for name, script := range map[string]string{
		"provision": boxRunProvisionScript(),
		"dir":       boxRunDirScript("/tmp/agent-box"),
		"stage":     stage,
	} {
		if out, err := exec.Command("sh", "-n", "-c", script).CombinedOutput(); err != nil {
			t.Errorf("%s script does not parse: %v\n%s", name, err, out)
		}
	}
}

func TestBoxRunProvisionScript_NeverPrivileged(t *testing.T) {
	s := boxRunProvisionScript()
	for _, want := range []string{
		"id -u", // idempotent: only creates when absent
		"useradd --create-home",
		"passwd -l",  // no password login
		"chmod 0700", // private home
		"gpasswd -d", // out of root-equivalent groups
		"sudo wheel", // the groups that matter
		"docker podman",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("provision script lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "sudoers") || strings.Contains(s, "NOPASSWD") {
		t.Errorf("provisioning must never grant sudo:\n%s", s)
	}
}

func TestBoxRunStageScript_RefusesUnsafeOrEqualHomes(t *testing.T) {
	for _, tc := range []struct{ owner, run string }{
		{"/home/alice", "/home/alice"},            // same home: would stage onto itself
		{"/home/al ice", "/home/ctn-run"},         // space
		{"/home/alice;rm -rf /", "/home/ctn-run"}, // metacharacters
		{"home/alice", "/home/ctn-run"},           // relative
		{"/home/../etc", "/home/ctn-run"},         // traversal
		{"/home/alice", "/home/ctn|run"},          // sed delimiter
		{"/home/alice/", "/home/ctn-run"},         // trailing slash
		{"", "/home/ctn-run"},
	} {
		if _, err := boxRunStageScript(tc.owner, tc.run); err == nil {
			t.Errorf("stage(%q, %q) must be refused", tc.owner, tc.run)
		}
	}
}

// The stage script, run for real on two temp homes: the platform's own box
// credential arrives 0600, config has the owner's home rewritten to the run
// user's, binaries are dereferenced copies, and nothing outside the allowlist is
// copied. Above all, the owner's Claude login is NEVER copied, even when it is
// right there: the platform does not handle a Claude credential at all.
func TestBoxRunStageScript_RunsAndNeverCopiesAClaudeLogin(t *testing.T) {
	root := t.TempDir()
	owner, run := filepath.Join(root, "alice"), filepath.Join(root, "ctn-run")
	for _, d := range []string{".claude/skills/s1", ".config/containarium", ".local/bin", ".local/share/claude", ".ssh"} {
		if err := os.MkdirAll(filepath.Join(owner, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(run, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(rel, content string, mode os.FileMode) {
		if err := os.WriteFile(filepath.Join(owner, rel), []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(".claude/.credentials.json", `{"token":"SECRET-SIGNIN"}`, 0o600)
	write(".claude.json", `{"oauthAccount":{}}`, 0o600)
	write(".config/containarium/box-token", "BOX-SECRET", 0o600)
	write(".config/containarium/manifest.json", `{"home":"`+owner+`/x"}`, 0o644)
	write(".claude/containarium-mcp.json", `{"cmd":"`+owner+`/.local/bin/skill-mcp-server","tokenFile":"`+owner+`/.config/containarium/box-token"}`, 0o644)
	write(".claude/settings.json", `{"permissions":{"allow":["Read"]}}`, 0o644)
	write(".gitconfig", "[credential]\n\thelper = "+owner+"/.local/bin/box-credential-helper\n", 0o644)
	write(".claude/skills/s1/SKILL.md", "skill", 0o644)
	write(".local/share/claude/claude-real", "#!/bin/sh\necho real-claude\n", 0o755)
	if err := os.Symlink(filepath.Join(owner, ".local/share/claude/claude-real"), filepath.Join(owner, ".local/bin/claude")); err != nil {
		t.Fatal(err)
	}
	write(".ssh/id_ed25519", "PRIVATE-KEY-MUST-NOT-MOVE", 0o600)
	write(".bash_history", "history-must-not-move", 0o600)

	stage, err := boxRunStageScript(owner, run)
	if err != nil {
		t.Fatal(err)
	}
	runSh(t, stage)
	runSh(t, stage) // idempotent

	mode := func(rel string) os.FileMode {
		fi, err := os.Stat(filepath.Join(run, rel))
		if err != nil {
			t.Fatalf("%s not staged: %v", rel, err)
		}
		return fi.Mode().Perm()
	}
	read := func(rel string) string {
		b, err := os.ReadFile(filepath.Join(run, rel))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	for _, rel := range boxRunStagedPlatformCredentials {
		if m := mode(rel); m != 0o600 {
			t.Errorf("%s mode = %o, want 600", rel, m)
		}
		if _, err := os.Stat(filepath.Join(run, rel+".new")); err == nil {
			t.Errorf("%s: the temp file of the atomic write was left behind", rel)
		}
	}
	// The owner's Claude login and account state must not move, in any form.
	for _, rel := range []string{".claude/.credentials.json", ".claude.json"} {
		if _, err := os.Stat(filepath.Join(run, rel)); err == nil {
			t.Errorf("%s was copied: the platform must never handle a Claude login", rel)
		}
	}
	if got := read(".claude/containarium-mcp.json"); strings.Contains(got, owner) || !strings.Contains(got, run+"/.local/bin/skill-mcp-server") {
		t.Errorf("mcp config not rewritten to the run home: %s", got)
	}
	if got := read(".gitconfig"); strings.Contains(got, owner) || !strings.Contains(got, run) {
		t.Errorf(".gitconfig not rewritten: %s", got)
	}
	if fi, err := os.Lstat(filepath.Join(run, ".local/bin/claude")); err != nil || fi.Mode()&os.ModeSymlink != 0 {
		t.Errorf("claude must be a dereferenced regular copy, got %v %v", fi, err)
	}
	if got := read(".local/bin/claude"); !strings.Contains(got, "real-claude") {
		t.Errorf("claude content wrong: %s", got)
	}
	if m := mode(".config/containarium"); m != 0o700 {
		t.Errorf(".config/containarium mode = %o, want 700", m)
	}
	if _, err := os.Stat(filepath.Join(run, ".claude/skills/s1/SKILL.md")); err != nil {
		t.Errorf("skills not staged: %v", err)
	}
	for _, rel := range []string{".ssh/id_ed25519", ".bash_history", ".ssh"} {
		if _, err := os.Stat(filepath.Join(run, rel)); err == nil {
			t.Errorf("%s must NOT be staged", rel)
		}
	}

	// Nothing is deleted when a run ends, so a finishing run cannot pull the
	// platform credential from under one that is still going: staging again
	// (the next run) leaves everything in place.
	runSh(t, stage)
	for _, rel := range append([]string{".local/bin/claude", ".claude/settings.json", ".claude/containarium-mcp.json"}, boxRunStagedPlatformCredentials...) {
		if _, err := os.Stat(filepath.Join(run, rel)); err != nil {
			t.Errorf("%s must still be there after another staging: %v", rel, err)
		}
	}
}

// StartBoxRun picks the run's identity from the recorded level, with recording
// fakes (no Linux shell needed): no level -> the owner for every script, no root
// staging; a level -> root provisions and stages, the config read stays the
// owner's, and the spawn and the record are written as the run user. The run
// user is signed in here (the probe says so); the next tests cover it not being.
func TestStartBoxRun_IdentityFollowsTheRecordedLevel(t *testing.T) {
	for _, tc := range []struct {
		name, level string
		unpriv      bool
	}{
		{"none recorded keeps the owner", "", false},
		{"none level runs unprivileged", "none", true},
		{"build_tools runs unprivileged", "build_tools", true},
		{"full_sudo runs unprivileged until sudo is wired", "full_sudo", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			type call struct{ user, script string }
			var rootCalls []string
			var userCalls []call
			s := &ContainerServer{
				boxRunLogDir:       t.TempDir(),
				boxRunCollaborator: func(owner, subject string) (bool, error) { return false, nil },
				boxRunToolAccess:   func(ctx context.Context, username string) (string, error) { return tc.level, nil },
				boxRunExec: func(box, script string) (string, error) {
					mu.Lock()
					defer mu.Unlock()
					rootCalls = append(rootCalls, script)
					if strings.Contains(script, "useradd") {
						return "/home/ctn-run\n", nil
					}
					return "", nil
				},
				boxRunStartExec: func(box, username, script string) (string, error) {
					mu.Lock()
					defer mu.Unlock()
					userCalls = append(userCalls, call{username, script})
					switch {
					case script == boxRunHomeAndConfigScript():
						return "/home/alice\n" + `{"version":1,"engine":"claude","credential":"secret","provider":"anthropic"}`, nil
					case script == signInProbeScript(t):
						return "interactive\n", nil
					case strings.Contains(script, "setsid"):
						return "4242 boot-1\n", nil
					}
					return "", nil
				},
			}
			if _, err := s.StartBoxRun(adminCtx(), &pb.StartBoxRunRequest{Username: "alice", Prompt: "do it"}); err != nil {
				t.Fatalf("StartBoxRun: %v", err)
			}
			var stagedAsRoot bool
			for _, sc := range rootCalls {
				if strings.Contains(sc, "useradd") {
					stagedAsRoot = true
				}
			}
			if stagedAsRoot != tc.unpriv {
				t.Errorf("root provisioning = %v, want %v", stagedAsRoot, tc.unpriv)
			}
			var spawnUser, recordUser, configUser, spawnScript string
			for _, c := range userCalls {
				switch {
				case c.script == boxRunHomeAndConfigScript():
					configUser = c.user
				case strings.Contains(c.script, "setsid"):
					spawnUser, spawnScript = c.user, c.script
				case strings.HasPrefix(c.script, "printf '%s' "):
					recordUser = c.user
				}
			}
			if configUser != "alice" {
				t.Errorf("the config read must stay the owner's, got %q", configUser)
			}
			want := "alice"
			if tc.unpriv {
				want = boxRunUnprivilegedUser
			}
			if spawnUser != want || recordUser != want {
				t.Errorf("spawn as %q, record as %q; want %q", spawnUser, recordUser, want)
			}
			if strings.Contains(spawnScript, "rm -f") && strings.Contains(spawnScript, "box-token") {
				t.Errorf("a run must not delete the shared box credential when it ends:\n%s", spawnScript)
			}
			if tc.unpriv && !strings.Contains(spawnScript, "cd '/home/ctn-run'") {
				t.Errorf("the run must start in the run user's home:\n%s", spawnScript)
			}
		})
	}
}

// signInProbeScript is the credential-status probe the daemon runs as the run user.
func signInProbeScript(t *testing.T) string {
	t.Helper()
	s, ok := engine.CredentialAlertStatusScript(engine.NameClaude)
	if !ok {
		t.Fatal("no credential-status probe for the claude engine")
	}
	return s
}

// signInRun starts a run on a box with a recorded level whose run user reports
// the given sign-in state (or probe error), and returns what happened.
func signInRun(t *testing.T, probeOut string, probeErr error) (spawned bool, user string, err error) {
	t.Helper()
	s := &ContainerServer{
		boxRunLogDir:       t.TempDir(),
		boxRunCollaborator: func(owner, subject string) (bool, error) { return false, nil },
		boxRunToolAccess:   func(ctx context.Context, username string) (string, error) { return "build_tools", nil },
		boxRunExec: func(box, script string) (string, error) {
			if strings.Contains(script, "useradd") {
				return "/home/ctn-run\n", nil
			}
			return "", nil
		},
		boxRunStartExec: func(box, username, script string) (string, error) {
			switch {
			case script == boxRunHomeAndConfigScript():
				return "/home/alice\n" + `{"version":1,"engine":"claude","credential":"secret","provider":"anthropic"}`, nil
			case script == signInProbeScript(t):
				user = username
				return probeOut, probeErr
			case strings.Contains(script, "setsid"):
				spawned = true
				return "4242 boot-1\n", nil
			}
			return "", nil
		},
	}
	_, err = s.StartBoxRun(adminCtx(), &pb.StartBoxRunRequest{Username: "alice", Prompt: "do it"})
	return spawned, user, err
}

// The platform never signs the run user in and never copies a Claude login: a
// run user with no usable sign-in refuses the run with the exact command the
// owner runs, and nothing is spawned.
func TestStartBoxRun_RunUserNotSignedInRefusesWithAnActionableMessage(t *testing.T) {
	for _, state := range []string{"none", "expired"} {
		t.Run(state, func(t *testing.T) {
			spawned, probedAs, err := signInRun(t, state+"\n", nil)
			if status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("err = %v, want FailedPrecondition", err)
			}
			if spawned {
				t.Error("nothing may be spawned for a run user that is not signed in")
			}
			if probedAs != boxRunUnprivilegedUser {
				t.Errorf("the sign-in must be probed AS the run user, got %q", probedAs)
			}
			msg := err.Error()
			for _, want := range []string{"claude auth login", "sudo -iu " + boxRunUnprivilegedUser, "/home/ctn-run/.local/bin/claude", "never reads, copies or refreshes"} {
				if !strings.Contains(msg, want) {
					t.Errorf("the message lacks %q: %s", want, msg)
				}
			}
			if state == "expired" && !strings.Contains(msg, "expired") {
				t.Errorf("an expired sign-in must say so: %s", msg)
			}
			// Through StartBoxRun itself, the refusal carries the typed reason a
			// caller switches on.
			wantType := BoxRunViolationRunUserNotSignedIn
			if state == "expired" {
				wantType = BoxRunViolationRunUserSignInExpired
			}
			if got := violationTypeOf(err); got != wantType {
				t.Errorf("typed reason = %q, want %q", got, wantType)
			}
		})
	}
}

// A signed-in run user (an interactive sign-in or a user-placed key) proceeds.
func TestStartBoxRun_RunUserSignedInProceeds(t *testing.T) {
	for _, state := range []string{"interactive", "api-key"} {
		spawned, _, err := signInRun(t, state+"\n", nil)
		if err != nil || !spawned {
			t.Errorf("state %q: err=%v spawned=%v, want a started run", state, err, spawned)
		}
	}
}

// A probe that fails or prints something unexpected is an infrastructure problem
// (Unavailable), not a claim about the sign-in, and it also stops the run.
func TestStartBoxRun_UnreadableSignInStateStopsTheRun(t *testing.T) {
	for name, tc := range map[string]struct {
		out string
		err error
	}{
		"probe fails":       {"", os.ErrDeadlineExceeded},
		"unexpected output": {"all good\n", nil},
	} {
		t.Run(name, func(t *testing.T) {
			spawned, _, err := signInRun(t, tc.out, tc.err)
			if status.Code(err) != codes.Unavailable {
				t.Fatalf("err = %v, want Unavailable", err)
			}
			if spawned {
				t.Error("nothing may be spawned when the sign-in state cannot be read")
			}
		})
	}
}

// A failure to read the level refuses the run: it must not silently run as the owner.
func TestStartBoxRun_LevelReadErrorRefusesTheRun(t *testing.T) {
	var spawned bool
	s := &ContainerServer{
		boxRunLogDir:       t.TempDir(),
		boxRunCollaborator: func(owner, subject string) (bool, error) { return false, nil },
		boxRunToolAccess:   func(ctx context.Context, username string) (string, error) { return "", os.ErrDeadlineExceeded },
		boxRunExec:         func(box, script string) (string, error) { return "", nil },
		boxRunStartExec: func(box, username, script string) (string, error) {
			if strings.Contains(script, "setsid") {
				spawned = true
			}
			if script == boxRunHomeAndConfigScript() {
				return "/home/alice\n" + `{"version":1,"engine":"claude","credential":"secret","provider":"anthropic"}`, nil
			}
			return "", nil
		},
	}
	if _, err := s.StartBoxRun(adminCtx(), &pb.StartBoxRunRequest{Username: "alice", Prompt: "do it"}); err == nil {
		t.Fatal("a level read error must refuse the run")
	}
	if spawned {
		t.Error("nothing may be spawned when the level could not be read")
	}
}
