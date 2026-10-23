package server

import (
	"context"
	"os/exec"
	"strings"
	"sync"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func hasRule(rules []string, r string) bool {
	for _, x := range rules {
		if x == r {
			return true
		}
	}
	return false
}

// Each level grants exactly its own tier, and nothing ever grants publishing
// (git push / remote), a bare Bash, or a wildcard.
func TestBoxRunPolicyFor_LevelsAreCumulativeAndBounded(t *testing.T) {
	none, err := boxRunPolicyFor("none")
	if err != nil {
		t.Fatal(err)
	}
	build, err := boxRunPolicyFor("build_tools")
	if err != nil {
		t.Fatal(err)
	}
	full, err := boxRunPolicyFor("full_sudo")
	if err != nil {
		t.Fatal(err)
	}

	for _, r := range []string{"Read", "Edit", "Write", "Bash(git status)", "Bash(git commit *)", boxRunSkillFetchTool} {
		if !hasRule(none.Allowed, r) {
			t.Errorf("NONE lacks the base rule %q", r)
		}
	}
	if hasRule(none.Allowed, "Bash(go test *)") || hasRule(none.Allowed, "Bash(sudo *)") {
		t.Error("NONE must not allow build tools or sudo")
	}
	if !hasRule(build.Allowed, "Bash(go test *)") || !hasRule(build.Allowed, "Bash(make)") || !hasRule(build.Allowed, "Bash(pnpm install *)") {
		t.Error("BUILD_TOOLS must allow the toolchains")
	}
	if hasRule(build.Allowed, "Bash(sudo *)") {
		t.Error("BUILD_TOOLS must not allow sudo")
	}
	if !hasRule(full.Allowed, "Bash(sudo *)") || !hasRule(full.Allowed, "Bash(go test *)") {
		t.Error("FULL_SUDO must allow sudo and the toolchains")
	}
	if len(none.Allowed) >= len(build.Allowed) || len(build.Allowed) >= len(full.Allowed) {
		t.Errorf("levels must be cumulative: %d < %d < %d", len(none.Allowed), len(build.Allowed), len(full.Allowed))
	}
	for name, p := range map[string]boxRunPolicy{"none": none, "build": build, "full": full} {
		for _, r := range p.Allowed {
			switch {
			case r == "Bash", r == "*", strings.Contains(r, "git push"), strings.Contains(r, "git remote"),
				strings.Contains(r, "curl"), strings.Contains(r, "wget"), strings.Contains(r, "go run"), strings.Contains(r, "go install"):
				t.Errorf("%s allows %q, which no level may grant", name, r)
			}
		}
	}
}

// An unknown, empty or hand-edited level is an error, never a default policy.
func TestBoxRunPolicyFor_UnknownLevelFailsClosed(t *testing.T) {
	for _, level := range []string{"", "root", "FULL_SUDO", "install_packages", "full-sudo"} {
		if _, err := boxRunPolicyFor(level); err == nil {
			t.Errorf("level %q must have no policy", level)
		}
	}
}

// The flags survive a real shell as exactly the intended tokens: the rules
// contain spaces, '*' and parentheses, and an unquoted one would glob or break.
func TestBoxRunPolicy_CommandFlagsRoundTripThroughAShell(t *testing.T) {
	p, err := boxRunPolicyFor("build_tools")
	if err != nil {
		t.Fatal(err)
	}
	flags := p.commandFlags()
	out, err := exec.Command("sh", "-c", "for a in"+flags+"; do printf '%s\\n' \"$a\"; done").CombinedOutput()
	if err != nil {
		t.Fatalf("flags do not parse as shell: %v\n%s", err, out)
	}
	got := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	want := append([]string{"--restricted", "--tools", strings.Join(p.Tools, ","), "--allowedTools"}, p.Allowed...)
	if len(got) != len(want) {
		t.Fatalf("token count = %d, want %d\n%v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("token %d = %q, want %q", i, got[i], want[i])
		}
	}
	if got[0] != "--restricted" || got[len(got)-1] != p.Allowed[len(p.Allowed)-1] {
		t.Error("--restricted must come first and the variadic --allowedTools last")
	}
}

func TestBoxRunSudoersScript(t *testing.T) {
	for _, level := range []string{"none", "build_tools", "", "garbage"} {
		s := boxRunSudoersScript(level)
		if s != "rm -f '/etc/sudoers.d/90-ctn-run'\n" {
			t.Errorf("level %q must only REMOVE the grant, got:\n%s", level, s)
		}
	}
	s := boxRunSudoersScript("full_sudo")
	for _, want := range []string{"visudo -cf", "NOPASSWD:ALL", "chmod 0440", "mv -f", "command -v visudo", "90-ctn-run", "'ctn-run'"} {
		if !strings.Contains(s, want) {
			t.Errorf("full_sudo script lacks %q:\n%s", want, s)
		}
	}
	for _, sc := range []string{boxRunSudoersScript("full_sudo"), boxRunSudoersScript("none")} {
		if out, err := exec.Command("sh", "-n", "-c", sc).CombinedOutput(); err != nil {
			t.Errorf("sudoers script does not parse: %v\n%s", err, out)
		}
	}
}

type policyRun struct {
	rootCalls []string
	userCalls []string
	err       error
}

// runWithLevel runs StartBoxRun against recording fakes with the given recorded
// level and the owner's code.json engine config.
func runWithLevel(t *testing.T, level, engineJSON string) policyRun {
	t.Helper()
	var mu sync.Mutex
	var r policyRun
	runHome := "/srv/" + boxRunUnprivilegedUser
	s := &ContainerServer{
		boxRunLogDir:       t.TempDir(),
		boxRunCollaborator: func(owner, subject string) (bool, error) { return false, nil },
		boxRunToolAccess:   func(ctx context.Context, username string) (string, error) { return level, nil },
		boxRunExec: func(box, script string) (string, error) {
			mu.Lock()
			defer mu.Unlock()
			r.rootCalls = append(r.rootCalls, script)
			if strings.Contains(script, "useradd") {
				return runHome + "\n", nil
			}
			return "", nil
		},
		boxRunStartExec: func(box, username, script string) (string, error) {
			mu.Lock()
			defer mu.Unlock()
			r.userCalls = append(r.userCalls, script)
			switch {
			case script == boxRunHomeAndConfigScript():
				return "/srv/alice\n" + engineJSON, nil
			case script == signInProbeScript(t):
				return "interactive\n", nil
			case strings.Contains(script, "setsid"):
				return "4242 boot-1\n", nil
			}
			return "", nil
		},
	}
	_, r.err = s.StartBoxRun(adminCtx(), &pb.StartBoxRunRequest{Username: "alice", Prompt: "do it"})
	return r
}

const claudeCfg = `{"version":1,"engine":"claude","credential":"secret","provider":"anthropic"}`

func spawnScriptOf(r policyRun) string {
	for _, c := range r.userCalls {
		if strings.Contains(c, "setsid") {
			return c
		}
	}
	return ""
}

func TestStartBoxRun_PolicyFlagsAndSudoGrantFollowTheLevel(t *testing.T) {
	// No level: today's command, no flags, nothing to do with sudo.
	legacy := runWithLevel(t, "", claudeCfg)
	if legacy.err != nil {
		t.Fatal(legacy.err)
	}
	if sp := spawnScriptOf(legacy); strings.Contains(sp, "--restricted") || strings.Contains(sp, "--allowedTools") {
		t.Errorf("a box with no level must keep its command unchanged:\n%s", sp)
	}
	for _, c := range legacy.rootCalls {
		if strings.Contains(c, "sudoers") {
			t.Errorf("a box with no level must not touch sudoers:\n%s", c)
		}
	}

	for _, tc := range []struct {
		level     string
		wantSudo  bool
		wantBuild bool
	}{{"none", false, false}, {"build_tools", false, true}, {"full_sudo", true, true}} {
		t.Run(tc.level, func(t *testing.T) {
			r := runWithLevel(t, tc.level, claudeCfg)
			if r.err != nil {
				t.Fatal(r.err)
			}
			sp := spawnScriptOf(r)
			for _, want := range []string{"--restricted", "--tools", "--allowedTools"} {
				if !strings.Contains(sp, want) {
					t.Errorf("spawn lacks %s:\n%s", want, sp)
				}
			}
			if got := strings.Contains(sp, "go test"); got != tc.wantBuild {
				t.Errorf("go test allowed = %v, want %v", got, tc.wantBuild)
			}
			if got := strings.Contains(sp, "Bash(sudo *)"); got != tc.wantSudo {
				t.Errorf("sudo rule allowed = %v, want %v", got, tc.wantSudo)
			}
			var grant, revoke bool
			for _, c := range r.rootCalls {
				grant = grant || strings.Contains(c, "NOPASSWD:ALL")
				revoke = revoke || c == "rm -f '/etc/sudoers.d/90-ctn-run'\n"
			}
			if grant != tc.wantSudo || revoke == tc.wantSudo {
				t.Errorf("sudoers grant=%v revoke=%v, want grant=%v", grant, revoke, tc.wantSudo)
			}
		})
	}
}

// A level that cannot be enforced refuses the run BEFORE anything is mutated.
func TestStartBoxRun_UnenforceableLevelRefusesBeforeMutating(t *testing.T) {
	for name, tc := range map[string]struct{ level, cfg string }{
		"unknown level":  {"root", claudeCfg},
		"another engine": {"build_tools", `{"version":1,"engine":"codex","credential":"secret","provider":"openai"}`},
	} {
		t.Run(name, func(t *testing.T) {
			r := runWithLevel(t, tc.level, tc.cfg)
			if status.Code(r.err) != codes.FailedPrecondition {
				t.Fatalf("err = %v, want FailedPrecondition", r.err)
			}
			// The read-only run listing (collision check) is allowed; any
			// provisioning, sudo grant, staging or directory change is not.
			for _, c := range r.rootCalls {
				for _, mutation := range []string{"useradd", "sudoers", "chown", "chmod", "mkdir", "cp ", "rm -f"} {
					if strings.Contains(c, mutation) {
						t.Errorf("a refused run must not mutate the box (%q):\n%s", mutation, c)
					}
				}
			}
			if sp := spawnScriptOf(r); sp != "" {
				t.Errorf("nothing may be spawned for a refused run:\n%s", sp)
			}
		})
	}
}
