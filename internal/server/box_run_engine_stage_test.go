//go:build !containarium_client

package server

import (
	"context"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/footprintai/containarium/internal/runhook"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/status"
)

// stageFixture is a throwaway owner home, audit directory and run user for
// running the engine staging script for real. Root ownership is the test
// user's own uid, as the script takes the owner of the files it writes as a
// parameter.
type stageFixture struct {
	t         *testing.T
	ownerHome string
	audit     string
	runUser   string
	src       string
}

func newStageFixture(t *testing.T) *stageFixture {
	t.Helper()
	f := &stageFixture{t: t, ownerHome: t.TempDir(), audit: filepath.Join(t.TempDir(), "audit"), runUser: "no-such-run-user-3582"}
	if err := os.MkdirAll(filepath.Join(f.ownerHome, ".local/bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Installed the way the engine installs itself: a symlink into a versions dir.
	f.src = filepath.Join(f.ownerHome, ".local/share/claude/versions/1.0")
	f.writeSrc("engine-v1", 0o755)
	if err := os.Symlink(f.src, filepath.Join(f.ownerHome, ".local/bin/claude")); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *stageFixture) writeSrc(content string, mode os.FileMode) {
	f.t.Helper()
	if err := os.MkdirAll(filepath.Dir(f.src), 0o755); err != nil {
		f.t.Fatal(err)
	}
	_ = os.Remove(f.src)
	if err := os.WriteFile(f.src, []byte(content), mode); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Chmod(f.src, mode); err != nil {
		f.t.Fatal(err)
	}
}

func (f *stageFixture) run() (string, error) {
	f.t.Helper()
	cur, err := user.Current()
	if err != nil {
		f.t.Fatal(err)
	}
	script, err := boxRunEngineStageScriptFor(f.ownerHome, f.audit, f.runUser, cur.Uid, cur.Uid+":"+cur.Gid)
	if err != nil {
		f.t.Fatal(err)
	}
	out, err := exec.Command("sh", "-c", script).CombinedOutput()
	return string(out), err
}

func (f *stageFixture) staged() string { return filepath.Join(f.audit, "bin", "claude") }

func TestBoxRunEngineStage_StagesARootOwnedCopy(t *testing.T) {
	f := newStageFixture(t)
	if out, err := f.run(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	st, err := os.Stat(f.staged())
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o755 {
		t.Errorf("staged engine mode = %v, want 0755", st.Mode().Perm())
	}
	if b, _ := os.ReadFile(f.staged()); string(b) != "engine-v1" {
		t.Errorf("staged engine content = %q (the symlink must be dereferenced)", b)
	}
	if dst, _ := os.Stat(filepath.Dir(f.staged())); dst.Mode().Perm()&0o022 != 0 {
		t.Errorf("staging directory is group/world-writable: %v", dst.Mode())
	}
}

// An engine the run user owns, or can write, is not used.
func TestBoxRunEngineStage_RefusesARunUserOwnedOrWritableEngine(t *testing.T) {
	cases := map[string]func(f *stageFixture){
		"group-writable": func(f *stageFixture) { f.writeSrc("engine", 0o775) },
		"world-writable": func(f *stageFixture) { f.writeSrc("engine", 0o757) },
		"owned by the run user": func(f *stageFixture) {
			cur, _ := user.Current()
			f.runUser = cur.Username // the owner's uid is then the run user's
		},
		"missing": func(f *stageFixture) { _ = os.Remove(filepath.Join(f.ownerHome, ".local/bin/claude")) },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			f := newStageFixture(t)
			setup(f)
			out, err := f.run()
			if err == nil {
				t.Fatalf("the script staged an untrusted engine:\n%s", out)
			}
			if _, statErr := os.Stat(f.staged()); statErr == nil {
				t.Errorf("an engine was staged although it was refused")
			}
		})
	}
}

// A copy that is already staged is kept while the owner's is unchanged, and
// replaced when the owner's changes; a staged copy the run user could write
// is never trusted again.
func TestBoxRunEngineStage_RestagesWhenTheOwnersCopyChanges(t *testing.T) {
	f := newStageFixture(t)
	if out, err := f.run(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	before, _ := os.Stat(f.staged())
	if out, err := f.run(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if after, _ := os.Stat(f.staged()); !os.SameFile(before, after) {
		t.Errorf("an unchanged engine was copied again")
	}

	f.writeSrc("engine-v2-longer", 0o755)
	if out, err := f.run(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if b, _ := os.ReadFile(f.staged()); string(b) != "engine-v2-longer" {
		t.Errorf("a new owner version was not staged: %q", b)
	}

	if err := os.Chmod(f.staged(), 0o777); err != nil {
		t.Fatal(err)
	}
	if out, err := f.run(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if st, _ := os.Stat(f.staged()); st.Mode().Perm() != 0o755 {
		t.Errorf("a writable staged copy was kept: %v", st.Mode().Perm())
	}
}

func TestBoxRunEngineStageScript_RejectsAnUnsafeHome(t *testing.T) {
	if _, err := boxRunEngineStageScript("/home/a b"); err == nil {
		t.Fatal("an unsafe owner home must be refused")
	}
}

func engineStageCall(script string) bool { return strings.Contains(script, "claude.src") }

type engineRunCalls struct {
	mu    sync.Mutex
	calls []policyCall
	err   error
}

func runEngineStageReq(t *testing.T, failStage bool, req *pb.StartBoxRunRequest) *engineRunCalls {
	t.Helper()
	r := &engineRunCalls{}
	s := &ContainerServer{
		boxRunLogDir:          t.TempDir(),
		boxRunCollaborator:    func(owner, subject string) (bool, error) { return false, nil },
		boxRunToolAccess:      func(ctx context.Context, username string) (string, error) { return "none", nil },
		boxRunEnsureToolchain: func(string) error { return nil },
		boxRunExec: func(box, script string) (string, error) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.calls = append(r.calls, policyCall{root: true, script: script})
			switch {
			case strings.Contains(script, "useradd"):
				return "/srv/" + boxRunUnprivilegedUser + "\n", nil
			case engineStageCall(script) && failStage:
				return "", os.ErrPermission
			case strings.Contains(script, "run-supervise --config '"):
				return "4242 boot-1\n", nil
			}
			return "", nil
		},
		boxRunStartExec: func(box, username, script string) (string, error) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.calls = append(r.calls, policyCall{script: script})
			switch {
			case script == boxRunHomeAndConfigScript():
				return "/srv/alice\n" + claudeCfg, nil
			case script == signInProbeScript(t):
				return "interactive\n", nil
			case strings.Contains(script, "setsid"):
				return "4242 boot-1\n", nil
			}
			return "", nil
		},
	}
	req.Username = "alice"
	_, r.err = s.StartBoxRun(adminCtx(), runTokenFor(s, req))
	return r
}

func (r *engineRunCalls) spawn() string {
	for _, c := range r.calls {
		if (c.root && strings.Contains(c.script, "run-supervise --config '")) || (!c.root && strings.Contains(c.script, "setsid sh -c")) {
			return c.script
		}
	}
	return ""
}

func (r *engineRunCalls) staged() bool {
	for _, c := range r.calls {
		if c.root && engineStageCall(c.script) {
			return true
		}
	}
	return false
}

// Under a command policy the engine that runs is the root-staged copy, not
// the run user's own, and the run user's copy is not referenced at all.
func TestStartBoxRun_CommandPolicy_RunsTheRootStagedEngine(t *testing.T) {
	r := runEngineStageReq(t, false, &pb.StartBoxRunRequest{Prompt: "do it", CommandPolicy: withPolicy("make lint")})
	if r.err != nil {
		t.Fatal(r.err)
	}
	if !r.staged() {
		t.Fatal("the engine was not staged root-owned before the run")
	}
	spawn := r.spawn()
	if !strings.Contains(spawn, runhook.EnginePath) {
		t.Errorf("the run does not execute %s:\n%s", runhook.EnginePath, spawn)
	}
	if strings.Contains(spawn, ".local/bin/claude") {
		t.Errorf("the run still references the run user's engine copy:\n%s", spawn)
	}
}

// When the engine cannot be staged root-owned the run is refused with a typed
// reason, and never falls back to the run user's copy.
func TestStartBoxRun_CommandPolicy_RefusesWhenTheEngineCannotBeStaged(t *testing.T) {
	r := runEngineStageReq(t, true, &pb.StartBoxRunRequest{Prompt: "do it", CommandPolicy: withPolicy("make lint")})
	if r.err == nil {
		t.Fatal("the run started without a root-owned engine")
	}
	var typed bool
	for _, d := range status.Convert(r.err).Details() {
		if pf, ok := d.(*errdetails.PreconditionFailure); ok {
			for _, v := range pf.GetViolations() {
				typed = typed || v.GetType() == BoxRunViolationEngineNotRootStaged
			}
		}
	}
	if !typed {
		t.Errorf("the refusal carries no %s violation: %v", BoxRunViolationEngineNotRootStaged, r.err)
	}
	if r.spawn() != "" {
		t.Errorf("a run was spawned after the refusal")
	}
}

// Runs without a policy, and command-mode runs (no engine), are unchanged.
func TestStartBoxRun_EngineStaging_OnlyForEngineRunsWithAPolicy(t *testing.T) {
	r := runEngineStageReq(t, true, &pb.StartBoxRunRequest{Prompt: "do it"})
	if r.err != nil || r.staged() || !strings.Contains(r.spawn(), ".local/bin/claude") {
		t.Errorf("a run without a policy changed: err=%v staged=%v", r.err, r.staged())
	}
	r = runEngineStageReq(t, true, &pb.StartBoxRunRequest{Command: "make lint", CommandPolicy: withPolicy("make lint")})
	if r.err != nil || r.staged() {
		t.Errorf("a command-mode run needs no engine: err=%v staged=%v", r.err, r.staged())
	}
}
