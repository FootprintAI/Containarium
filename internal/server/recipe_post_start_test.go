package server

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/limitio"
	"github.com/footprintai/containarium/pkg/core/recipes"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/footprintai/containarium/pkg/version"
)

// #3542: the daemon exports its own release tag into every post_start, next
// to the caller's CONTAINARIUM_PARAM_* values, so a recipe can pin what must
// match the daemon (the slides-agent image) without trusting the caller's
// `release` parameter.

// runPostStartEcho builds the post_start script for a recipe whose only step
// prints the daemon release and the caller's release, runs it, and returns
// both values.
func runPostStartEcho(t *testing.T, params map[string]string) (daemon, caller string) {
	t.Helper()
	recipe := &pb.Recipe{Id: "r", PostStart: []string{
		`printf 'daemon=%s\ncaller=%s\n' "$` + recipes.ReleaseEnvName + `" "${` + recipes.ParamEnvName("release") + `:-}"`,
	}}
	out, err := exec.Command("bash", "-c", buildPostStartScript(recipe, params, "")).CombinedOutput() //nolint:gosec // test-built script
	if err != nil {
		t.Fatalf("post_start: %v\n%s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if v, ok := strings.CutPrefix(line, "daemon="); ok {
			daemon = v
		}
		if v, ok := strings.CutPrefix(line, "caller="); ok {
			caller = v
		}
	}
	return daemon, caller
}

func TestBuildPostStartScript_ExportsDaemonRelease(t *testing.T) {
	orig := version.Version
	t.Cleanup(func() { version.Version = orig })

	version.Version = "0.131.2"
	daemon, caller := runPostStartEcho(t, map[string]string{"release": "v0.1.0"})
	if daemon != "v0.131.2" {
		t.Errorf("%s = %q, want the daemon's own release v0.131.2", recipes.ReleaseEnvName, daemon)
	}
	if caller != "v0.1.0" {
		t.Errorf("the caller's release parameter must still reach post_start unchanged; got %q", caller)
	}

	// Parameters export under the CONTAINARIUM_PARAM_ prefix, so one named
	// like the release variable cannot reach it. (The ordering against the
	// recipe's own env is pinned by
	// TestBuildPostStartScript_RecipeEnvCannotOverrideRelease.)
	daemon, _ = runPostStartEcho(t, map[string]string{"release": "v0.1.0", "containarium_release": "v6.6.6"})
	if daemon != "v0.131.2" {
		t.Errorf("a parameter overrode %s: got %q", recipes.ReleaseEnvName, daemon)
	}

	// A build that is not a release exports an empty value (set, so `set -u`
	// steps can test it), never an invented tag.
	version.Version = "dev"
	if daemon, _ = runPostStartEcho(t, nil); daemon != "" {
		t.Errorf("non-release build: %s = %q, want empty", recipes.ReleaseEnvName, daemon)
	}
}

// TestBuildPostStartScript_RecipeEnvCannotOverrideRelease: the daemon's
// release is exported after the recipe's static env, so an env entry of the
// same name cannot stand in for it. Moving the export before the env loop
// makes this fail.
func TestBuildPostStartScript_RecipeEnvCannotOverrideRelease(t *testing.T) {
	orig := version.Version
	t.Cleanup(func() { version.Version = orig })
	version.Version = "0.131.2"
	recipe := &pb.Recipe{
		Id:        "r",
		Env:       map[string]string{recipes.ReleaseEnvName: "v6.6.6"},
		PostStart: []string{`printf '%s' "$` + recipes.ReleaseEnvName + `"`},
	}
	out, err := exec.Command("bash", "-c", buildPostStartScript(recipe, nil, "")).CombinedOutput() //nolint:gosec // test-built script
	if err != nil {
		t.Fatalf("post_start: %v\n%s", err, out)
	}
	if string(out) != "v0.131.2" {
		t.Errorf("recipe env overrode %s: got %q, want the daemon's v0.131.2", recipes.ReleaseEnvName, out)
	}
}

// exitStatusBoxes models the real box backend's two exec calls on a box whose
// post_start exits non-zero: Exec reports success whatever the command's exit
// status (incus Client.Exec never reads the operation's "return" metadata),
// while ExecWithExitCode reports the status as data.
type exitStatusBoxes struct {
	*fakeRecipeBoxes
	exitCode int
	stderr   string
}

func (b *exitStatusBoxes) ExecWithExitCode(name string, command []string) (string, string, int, error) {
	if _, _, _, err := b.fakeRecipeBoxes.ExecWithExitCode(name, command); err != nil {
		return "", "", 0, err
	}
	return "", b.stderr, b.exitCode, nil
}

const failingPostStartYAML = `recipes:
  - id: failing
    image: x
    post_start:
      - podman pull example.invalid/never-published:v0.0.0
`

func newFailingPostStartServer(t *testing.T, exitCode int) (*RecipeServer, *exitStatusBoxes) {
	t.Helper()
	catalog := recipes.New()
	if err := catalog.LoadFromBytes([]byte(failingPostStartYAML)); err != nil {
		t.Fatal(err)
	}
	boxes := &exitStatusBoxes{fakeRecipeBoxes: &fakeRecipeBoxes{}, exitCode: exitCode, stderr: "Error: manifest unknown\n"}
	return &RecipeServer{catalog: catalog, boxes: boxes}, boxes
}

// syncBuffer is a log sink the async goroutine and the test can share.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func capturePostStartLog(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	})
	return buf
}

// TestDeployRecipe_AsyncPostStartNonZeroExitIsLogged: a post_start that exits
// non-zero on the async path (an image pull that 404s) leaves a line in the
// daemon journal naming the box, the recipe and the exit status.
func TestDeployRecipe_AsyncPostStartNonZeroExitIsLogged(t *testing.T) {
	logs := capturePostStartLog(t)
	srv, _ := newFailingPostStartServer(t, 125)
	ctx := tenantWithScopes("alice", auth.ScopeContainersWrite)
	if _, err := srv.DeployRecipe(ctx, &pb.DeployRecipeRequest{RecipeId: "failing", Name: "alice", Async: true}); err != nil {
		t.Fatalf("async deploy: %v", err)
	}
	const want = `[recipe] async post_start failed on "alice-container" (recipe "failing")`
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(logs.String(), want) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	got := logs.String()
	if !strings.Contains(got, want) {
		t.Fatalf("no async post_start failure in the log; got:\n%s", got)
	}
	if !strings.Contains(got, "exit status 125") {
		t.Errorf("the log line should carry the exit status:\n%s", got)
	}
	if !strings.Contains(got, "ports were not exposed") {
		t.Errorf("the log line should say routes were skipped (#3545):\n%s", got)
	}
	if strings.Contains(got, "manifest unknown") {
		t.Errorf("post_start stderr is not copied into the daemon log:\n%s", got)
	}
}

// TestDeployRecipe_SyncPostStartNonZeroExitFails: the same failure on the
// synchronous path fails the deploy instead of reporting it deployed.
func TestDeployRecipe_SyncPostStartNonZeroExitFails(t *testing.T) {
	srv, _ := newFailingPostStartServer(t, 1)
	ctx := tenantWithScopes("alice", auth.ScopeContainersWrite)
	_, err := srv.DeployRecipe(ctx, &pb.DeployRecipeRequest{RecipeId: "failing", Name: "alice"})
	if status.Code(err) != codes.Internal || !strings.Contains(err.Error(), "post_start failed on alice-container") ||
		!strings.Contains(err.Error(), "exit status 1") {
		t.Fatalf("got %v, want Internal naming the box and exit status 1", err)
	}
}

// #3545: output past the exec capture cap is tolerated only when it is the
// only problem. The incus exec path joins a wait/transport error with the cap
// error, so a bare errors.Is(err, ErrTooLarge) also matches a timeout.

// execResultBoxes returns a fixed ExecWithExitCode result.
type execResultBoxes struct {
	recipeBoxes
	code int
	err  error
}

func (b execResultBoxes) ExecWithExitCode(string, []string) (string, string, int, error) {
	return "", "", b.code, b.err
}

func TestRunPostStart_OverCapOutput(t *testing.T) {
	capErr := fmt.Errorf("exec stdout: %w", limitio.ErrTooLarge)
	transport := errors.New("command execution failed: context deadline exceeded")
	for _, tc := range []struct {
		name    string
		code    int
		err     error
		wantErr string // "" = success
	}{
		{"over cap, exit 0 succeeds", 0, capErr, ""},
		{"over cap on both streams, exit 0 succeeds", 0, errors.Join(capErr, fmt.Errorf("exec stderr: %w", limitio.ErrTooLarge)), ""},
		{"over cap, non-zero exit fails", 3, capErr, "exit status 3"},
		{"over cap plus a transport error fails", 0, errors.Join(transport, capErr), "deadline exceeded"},
		{"transport error alone fails", 0, transport, "deadline exceeded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := runPostStart(execResultBoxes{code: tc.code, err: tc.err}, "alice-container", "true")
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("got %v, want success", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("got %v, want an error containing %q", err, tc.wantErr)
			}
		})
	}
}

// TestDeployRecipe_PostStartZeroExitSucceeds: exit 0 is still a deploy.
func TestDeployRecipe_PostStartZeroExitSucceeds(t *testing.T) {
	srv, boxes := newFailingPostStartServer(t, 0)
	ctx := tenantWithScopes("alice", auth.ScopeContainersWrite)
	if _, err := srv.DeployRecipe(ctx, &pb.DeployRecipeRequest{RecipeId: "failing", Name: "alice"}); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if got := strings.Join(boxes.events, ","); got != "create,exec post_start" {
		t.Errorf("events = %s, want create,exec post_start", got)
	}
}
