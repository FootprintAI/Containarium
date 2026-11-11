package server

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/config"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// A synthetic value, odd enough that finding it in a script is never a
// coincidence.
const testBoxRunToken = "synthetic-run-token-91bd.not-a-credential"

// runTokenFor gives a run on a box with a recorded tool-access level what such
// a run must carry since #3581: a per-run token, and a daemon that can install
// one. Tests of leveled runs written before the token was required pass their
// request through it, so they keep exercising what they were written for. A
// run on a box with no level is returned as is.
func runTokenFor(s *ContainerServer, req *pb.StartBoxRunRequest) *pb.StartBoxRunRequest {
	if s.boxRunToolAccess == nil {
		return req
	}
	if level, err := s.boxRunToolAccess(context.Background(), req.GetUsername()); err != nil || level == "" {
		return req
	}
	if s.boxRunTokenInstall == nil {
		s.boxRunTokenInstall = func(string, string, string, string) error { return nil }
	}
	if req.RunToken == "" {
		req.RunToken = testBoxRunToken
	}
	return req
}

// tokenRun is one StartBoxRun against recording fakes.
type tokenRun struct {
	mu          sync.Mutex
	rootScripts []string
	userScripts []string
	spawnUsers  []string
	installs    []string
	toolchain   int
}

func (r *tokenRun) spawnScript() string {
	for _, c := range r.userScripts {
		if strings.Contains(c, "setsid") {
			return c
		}
	}
	return ""
}

// newTokenRunServer is a daemon whose box has the given recorded tool-access
// level ("" for none, so runs keep the owner's identity).
func newTokenRunServer(t *testing.T, level string) (*ContainerServer, *tokenRun) {
	t.Helper()
	r := &tokenRun{}
	runHome := "/srv/" + boxRunUnprivilegedUser
	s := &ContainerServer{
		boxRunLogDir:       t.TempDir(),
		boxRunCollaborator: func(owner, subject string) (bool, error) { return false, nil },
		boxRunToolAccess:   func(context.Context, string) (string, error) { return level, nil },
		boxRunEnsureToolchain: func(string) error {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.toolchain++
			return nil
		},
		boxRunTokenInstall: func(box, runAs, name, token string) error {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.installs = append(r.installs, box+"|"+runAs+"|"+name+"|"+token)
			return nil
		},
		boxRunExec: func(box, script string) (string, error) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.rootScripts = append(r.rootScripts, script)
			if strings.Contains(script, "useradd") {
				return runHome + "\n", nil
			}
			return "", nil
		},
		boxRunStartExec: func(box, username, script string) (string, error) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.userScripts = append(r.userScripts, script)
			switch {
			case script == boxRunHomeAndConfigScript():
				return "/srv/alice\n" + claudeCfg, nil
			case script == signInProbeScript(t):
				return "interactive\n", nil
			case strings.Contains(script, "setsid"):
				r.spawnUsers = append(r.spawnUsers, username)
				return "4242 boot-1\n", nil
			}
			return "", nil
		},
	}
	return s, r
}

// tokenRunModes are the two kinds of run: an engine prompt and a shell command.
func tokenRunModes() map[string]*pb.StartBoxRunRequest {
	return map[string]*pb.StartBoxRunRequest{
		"engine run":  {Username: "alice", Prompt: "do it", RunName: "r1"},
		"command run": {Username: "alice", Command: "make test", RunName: "r1"},
	}
}

// #3581 (Q3, Q7): a run as the unprivileged run user that carries no token is
// refused with FAILED_PRECONDITION naming the field and the capability, before
// the run user is provisioned, anything is staged, rotated or spawned.
func TestStartBoxRun_RunUserWithoutATokenIsRefusedBeforeAnySideEffect(t *testing.T) {
	for _, level := range []string{"none", "build_tools", "full_sudo"} {
		for mode, req := range tokenRunModes() {
			t.Run(level+"/"+mode, func(t *testing.T) {
				s, r := newTokenRunServer(t, level)
				_, err := s.StartBoxRun(adminCtx(), req)
				if status.Code(err) != codes.FailedPrecondition {
					t.Fatalf("err = %v, want FailedPrecondition", err)
				}
				for _, want := range []string{"run_token", DaemonCapBoxRunToken, `"alice"`} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("the refusal does not name %s: %v", want, err)
					}
				}
				if len(r.installs) != 0 {
					t.Errorf("a token was installed for a refused run: %v", r.installs)
				}
				if r.toolchain != 0 {
					t.Errorf("the managed toolchain was attached %d time(s) for a refused run", r.toolchain)
				}
				if sp := r.spawnScript(); sp != "" {
					t.Errorf("a refused run was spawned:\n%s", sp)
				}
				// The read-only listing (the collision check) is allowed; no
				// provisioning, staging, sudo grant, rotation or removal is.
				for _, c := range r.rootScripts {
					for _, mutation := range []string{"useradd", "sudoers", "chown", "chmod", "mkdir", "cp ", "rm -f", "mv "} {
						if strings.Contains(c, mutation) {
							t.Errorf("a refused run mutated the box as root (%q):\n%s", mutation, c)
						}
					}
				}
				for _, c := range r.userScripts {
					if c != boxRunHomeAndConfigScript() {
						t.Errorf("a refused run ran a script as the box user:\n%s", c)
					}
				}
			})
		}
	}
}

// Q7: a run as the box owner (no recorded level) is unchanged. It needs no
// token, gets no token file, and is spawned as the owner.
func TestStartBoxRun_OwnerRunNeedsNoToken(t *testing.T) {
	for mode, req := range tokenRunModes() {
		t.Run(mode, func(t *testing.T) {
			s, r := newTokenRunServer(t, "")
			if _, err := s.StartBoxRun(adminCtx(), req); err != nil {
				t.Fatalf("StartBoxRun without a token on a box with no level: %v", err)
			}
			if len(r.spawnUsers) != 1 || r.spawnUsers[0] != "alice" {
				t.Fatalf("spawned as %v, want the owner", r.spawnUsers)
			}
			if len(r.installs) != 0 {
				t.Errorf("a token was installed for a run without one: %v", r.installs)
			}
			if sp := r.spawnScript(); strings.Contains(sp, config.EnvJWTTokenFile) {
				t.Errorf("a run without a token exports %s:\n%s", config.EnvJWTTokenFile, sp)
			}
		})
	}
}

// The daemon half end to end, against fakes: a run as the run user with a
// token starts; the token is installed for that user under the run's name,
// the run's shell points CONTAINARIUM_JWT_TOKEN_FILE at it, the token appears
// in no script, and the box principal is not copied into the run user's home.
func TestStartBoxRun_RunUserWithATokenGetsItsOwnCredentialAndNoPrincipal(t *testing.T) {
	for mode, base := range tokenRunModes() {
		t.Run(mode, func(t *testing.T) {
			s, r := newTokenRunServer(t, "none")
			req := base
			req.RunToken = testBoxRunToken
			resp, err := s.StartBoxRun(adminCtx(), req)
			if err != nil {
				t.Fatalf("StartBoxRun: %v", err)
			}
			if resp.GetRun().GetRunName() != "r1" {
				t.Errorf("run = %v", resp.GetRun())
			}
			box := "alice-container"
			if want := box + "|" + boxRunUnprivilegedUser + "|r1|" + testBoxRunToken; len(r.installs) != 1 || r.installs[0] != want {
				t.Fatalf("token installs = %v, want exactly %q", r.installs, want)
			}
			if len(r.spawnUsers) != 1 || r.spawnUsers[0] != boxRunUnprivilegedUser {
				t.Fatalf("spawned as %v, want the run user", r.spawnUsers)
			}
			sp := r.spawnScript()
			if want := "export " + config.EnvJWTTokenFile + "="; !strings.Contains(sp, want) || !strings.Contains(sp, boxRunTokenPath("r1")) {
				t.Errorf("the run's shell does not point %s at %s:\n%s", config.EnvJWTTokenFile, boxRunTokenPath("r1"), sp)
			}
			var staged bool
			for _, c := range append(append([]string{}, r.rootScripts...), r.userScripts...) {
				if strings.Contains(c, testBoxRunToken) {
					t.Errorf("the token is in a script the daemon ran:\n%s", c)
				}
				if strings.Contains(c, `cat "$o/.config/containarium/box-token"`) {
					t.Errorf("the box principal is copied into the run user's home:\n%s", c)
				}
				staged = staged || strings.Contains(c, `rm -f "$r/.config/containarium/box-token"`)
			}
			if !staged {
				t.Error("no script removed an earlier daemon's copy of the box principal from the run user's home")
			}
		})
	}
}

// A start that fails at the spawn, after the token was installed, removes the
// token: no run exists whose exit path or stop would. The removal runs as root
// (#3622: the file need not belong to the user the next run starts as), after
// the failed spawn, and names the run's own token file.
func TestStartBoxRun_FailedSpawnRemovesTheInstalledToken(t *testing.T) {
	for mode, base := range tokenRunModes() {
		t.Run(mode, func(t *testing.T) {
			s, r := newTokenRunServer(t, "none")
			const asRoot = "(root)"
			type call struct{ user, script string }
			var (
				mu    sync.Mutex
				calls []call
			)
			inner := s.boxRunStartExec
			s.boxRunStartExec = func(box, username, script string) (string, error) {
				mu.Lock()
				calls = append(calls, call{username, script})
				mu.Unlock()
				if strings.Contains(script, "setsid") {
					return "", errors.New("exec failed")
				}
				return inner(box, username, script)
			}
			innerRoot := s.boxRunExec
			s.boxRunExec = func(box, script string) (string, error) {
				mu.Lock()
				calls = append(calls, call{asRoot, script})
				mu.Unlock()
				if strings.Contains(script, "setsid") {
					return "", errors.New("exec failed")
				}
				return innerRoot(box, script)
			}
			req := base
			req.RunToken = testBoxRunToken
			_, err := s.StartBoxRun(adminCtx(), req)
			if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "start run") {
				t.Fatalf("err = %v, want Unavailable from the failed spawn", err)
			}
			if len(r.installs) != 1 {
				t.Fatalf("token installs = %v, want one before the spawn", r.installs)
			}
			removal := "rm -f " + shellSingleQuote(boxRunTokenPath("r1")) + "\n"
			spawnAt, removeAt := -1, -1
			for i, c := range calls {
				switch {
				case strings.Contains(c.script, "setsid"):
					spawnAt = i
				case c.script == removal:
					removeAt = i
					if c.user != asRoot {
						t.Errorf("the token was removed as %q, want root", c.user)
					}
				}
			}
			if spawnAt < 0 {
				t.Fatal("the spawn was never attempted")
			}
			if removeAt < spawnAt {
				t.Errorf("no script removed the installed token after the failed spawn (spawn at %d, removal at %d)", spawnAt, removeAt)
			}
		})
	}
}

// The variable the run's shell exports is the one the platform MCP server and
// every other consumer in this repo reads (internal/config). Renaming either
// side fails here.
func TestBoxRunSpawn_ExportsTheVariableConsumersRead(t *testing.T) {
	if config.EnvJWTTokenFile != "CONTAINARIUM_JWT_TOKEN_FILE" {
		t.Fatalf("config.EnvJWTTokenFile = %q; the upgrade note and external consumers name CONTAINARIUM_JWT_TOKEN_FILE", config.EnvJWTTokenFile)
	}
	inner := boxRunSpawnInner(boxRunSpawn{dir: "/d", name: "r1", command: "echo hi", home: "/h", runToken: "t"})
	want := "export " + config.EnvJWTTokenFile + "=" + shellSingleQuote(boxRunTokenPath("r1")) + "; "
	if !strings.HasPrefix(inner, want) {
		t.Errorf("the run's shell does not start with %q:\n%s", want, inner)
	}
}
