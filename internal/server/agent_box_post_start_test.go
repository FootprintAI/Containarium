package server

import (
	"context"
	"errors"
	"io"
	"runtime"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/recipes"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3546: a skill or crew run reuses the box an earlier run provisioned and
// skips the recipe's post_start on it. When that earlier post_start failed,
// the reuse must not hide it: the box records that preparation did not
// complete, and the next run runs post_start again.

// postStartBoxes is a recipeBoxes fake that keeps the state the marker lives
// in: which boxes exist and their Incus config keys. post_start exits with
// exitCode; postStartRuns counts how often it ran, and pendingAtRun records
// whether the box carried the marker each time it did.
type postStartBoxes struct {
	mu            sync.Mutex
	boxes         map[string]map[string]string // container name -> config keys
	exitCode      int
	postStartRuns int
	pendingAtRun  []bool
	// onPostStart, when set, runs inside the post_start exec, before it
	// returns.
	onPostStart func()

	// exitCodes, when not empty, gives the exit status of each post_start
	// in turn (exitCode applies once it runs out).
	exitCodes []int
	// inFlight and maxConcurrent count the post_starts running at once.
	inFlight      int
	maxConcurrent int
	// pendingAtEnd records, per post_start (in start order), whether the
	// box still carried the marker when that post_start returned (#3555).
	pendingAtEnd []bool
	// getCalls counts Get calls; setConfigErr, when set, fails SetConfig.
	getCalls     int
	setConfigErr error
}

func newPostStartBoxes(exitCode int) *postStartBoxes {
	return &postStartBoxes{boxes: map[string]map[string]string{}, exitCode: exitCode}
}

func (b *postStartBoxes) CreateContainer(_ context.Context, req *pb.CreateContainerRequest) (*pb.CreateContainerResponse, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	name := req.GetUsername() + "-container"
	if _, ok := b.boxes[name]; ok {
		return nil, errors.New("already exists")
	}
	b.boxes[name] = map[string]string{}
	return &pb.CreateContainerResponse{}, nil
}

func (b *postStartBoxes) Exec(string, []string) error { return nil }

func (b *postStartBoxes) ExecWithExitCode(name string, command []string) (string, string, int, error) {
	if len(command) == 0 || command[0] != "bash" {
		return "", "", 0, nil
	}
	b.mu.Lock()
	call := b.postStartRuns
	b.postStartRuns++
	b.inFlight++
	if b.inFlight > b.maxConcurrent {
		b.maxConcurrent = b.inFlight
	}
	b.pendingAtRun = append(b.pendingAtRun, b.boxes[name][incus.PostStartPendingKey] == incus.PostStartPendingValue)
	b.pendingAtEnd = append(b.pendingAtEnd, false)
	hook, code := b.onPostStart, b.exitCode
	if len(b.exitCodes) > 0 {
		code, b.exitCodes = b.exitCodes[0], b.exitCodes[1:]
	}
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		b.inFlight--
		b.pendingAtEnd[call] = b.boxes[name][incus.PostStartPendingKey] == incus.PostStartPendingValue
		b.mu.Unlock()
	}()
	if hook != nil {
		hook()
	}
	return "", "", code, nil
}

func (b *postStartBoxes) ExecWithOutput(string, []string) (string, string, error) {
	return "", "", errors.New("postStartBoxes: ExecWithOutput not modelled")
}

func (b *postStartBoxes) PushFile(string, string, io.ReadSeeker, string) error { return nil }

func (b *postStartBoxes) Get(username string) (*incus.ContainerInfo, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.getCalls++
	name := username + "-container"
	cfg, ok := b.boxes[name]
	if !ok {
		return nil, errors.New("not found")
	}
	return &incus.ContainerInfo{
		Name:             name,
		State:            "Running",
		PostStartPending: cfg[incus.PostStartPendingKey] == incus.PostStartPendingValue,
	}, nil
}

func (b *postStartBoxes) SetConfig(name, key, value string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.setConfigErr != nil {
		return b.setConfigErr
	}
	cfg, ok := b.boxes[name]
	if !ok {
		return errors.New("not found")
	}
	cfg[key] = value
	return nil
}

func (b *postStartBoxes) UnsetConfig(name, key string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if cfg, ok := b.boxes[name]; ok {
		delete(cfg, key)
	}
	return nil
}

func (b *postStartBoxes) runs() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.postStartRuns
}

func (b *postStartBoxes) pending(name string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.boxes[name][incus.PostStartPendingKey] == incus.PostStartPendingValue
}

func (b *postStartBoxes) gets() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.getCalls
}

func (b *postStartBoxes) setExitCode(code int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.exitCode = code
}

const postStartSkillRecipeYAML = `recipes:
  - id: prep
    image: x
    post_start:
      - install-the-runtime
`

const postStartSkillBox = "agent-prep-skill-container"

// newPostStartSkillServer is an AgentSkillServer whose recipe deploys go to
// boxes. A second server over the same boxes models a daemon restart.
func newPostStartSkillServer(t *testing.T, boxes *postStartBoxes) (*AgentSkillServer, *pb.AgentSkill) {
	t.Helper()
	catalog := recipes.New()
	if err := catalog.LoadFromBytes([]byte(postStartSkillRecipeYAML)); err != nil {
		t.Fatal(err)
	}
	s := &AgentSkillServer{recipes: &RecipeServer{catalog: catalog, boxes: boxes}}
	return s, &pb.AgentSkill{Id: "prep-skill", Box: &pb.AgentSkill_RecipeId{RecipeId: "prep"}}
}

// TestSkillBox_FailedPostStartIsRunAgainOnNextRun: a run whose post_start
// fails leaves the box marked, and the next run does not reuse it silently.
// While post_start keeps failing, every run runs it again and fails with a
// reason that says the box was never prepared; once it succeeds the marker
// is gone and later runs skip post_start as before.
func TestSkillBox_FailedPostStartIsRunAgainOnNextRun(t *testing.T) {
	boxes := newPostStartBoxes(1)
	s, skill := newPostStartSkillServer(t, boxes)
	ctx := ctxAs("admin", true)

	if _, _, _, err := s.provisionBoxOnly(ctx, skill, "", ""); err == nil {
		t.Fatal("first run: a failing post_start must fail the run")
	}
	if !boxes.pending(postStartSkillBox) {
		t.Fatal("first run: the box must be marked not ready after its post_start failed")
	}

	_, _, fresh, err := s.provisionBoxOnly(ctx, skill, "", "")
	if err == nil {
		t.Fatal("second run reused a box whose post_start never completed and reported success")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("second run: code = %v, want FailedPrecondition", status.Code(err))
	}
	for _, want := range []string{postStartSkillBox, "post_start", "not fully prepared", "exit status 1"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("second run: error %q does not mention %q", err, want)
		}
	}
	if fresh {
		t.Error("second run: a reused box is not fresh")
	}
	if got := boxes.runs(); got != 2 {
		t.Fatalf("post_start ran %d time(s) over two runs, want 2 (the second run must run it again)", got)
	}
	if !boxes.pending(postStartSkillBox) {
		t.Fatal("second run: a post_start that failed again must leave the box marked")
	}

	boxes.setExitCode(0)
	if _, _, _, err := s.provisionBoxOnly(ctx, skill, "", ""); err != nil {
		t.Fatalf("third run: post_start now succeeds, got %v", err)
	}
	if got := boxes.runs(); got != 3 {
		t.Fatalf("post_start ran %d time(s) over three runs, want 3", got)
	}
	if boxes.pending(postStartSkillBox) {
		t.Fatal("third run: a post_start that succeeded must clear the marker")
	}

	if _, _, _, err := s.provisionBoxOnly(ctx, skill, "", ""); err != nil {
		t.Fatalf("fourth run: %v", err)
	}
	if got := boxes.runs(); got != 3 {
		t.Errorf("post_start ran again on a prepared box (%d runs, want 3)", got)
	}
}

// TestSkillBox_PreparedBoxSkipsPostStartOnReuse: the reuse path is unchanged
// for a box whose post_start succeeded, and for a box that carries no marker
// at all (one made before the key existed, or by hand).
func TestSkillBox_PreparedBoxSkipsPostStartOnReuse(t *testing.T) {
	boxes := newPostStartBoxes(0)
	s, skill := newPostStartSkillServer(t, boxes)
	ctx := ctxAs("admin", true)

	if _, _, fresh, err := s.provisionBoxOnly(ctx, skill, "", ""); err != nil || !fresh {
		t.Fatalf("first run: fresh=%v err=%v, want a fresh box and no error", fresh, err)
	}
	if boxes.pending(postStartSkillBox) {
		t.Fatal("first run: a box whose post_start succeeded must not stay marked")
	}
	if got := boxes.pendingAtRun; len(got) != 1 || !got[0] {
		t.Errorf("post_start must run on a box already marked not ready; marker at each run = %v", got)
	}
	for i := 0; i < 2; i++ {
		if _, _, fresh, err := s.provisionBoxOnly(ctx, skill, "", ""); err != nil || fresh {
			t.Fatalf("reuse %d: fresh=%v err=%v, want a reused box and no error", i, fresh, err)
		}
	}
	if got := boxes.runs(); got != 1 {
		t.Errorf("post_start ran %d time(s), want 1: a prepared box is reused without it", got)
	}

	// A box with no marker key is treated as prepared.
	unmarked := newPostStartBoxes(1)
	unmarked.boxes[postStartSkillBox] = map[string]string{}
	s2, _ := newPostStartSkillServer(t, unmarked)
	if _, _, fresh, err := s2.provisionBoxOnly(ctx, skill, "", ""); err != nil || fresh {
		t.Fatalf("unmarked box: fresh=%v err=%v, want it reused", fresh, err)
	}
	if got := unmarked.runs(); got != 0 {
		t.Errorf("post_start ran %d time(s) on an unmarked box, want 0", got)
	}
}

// TestSkillBox_DaemonStopDuringPostStartLeavesBoxNotReady: the marker is set
// before post_start runs, so a daemon that stops while post_start runs (here
// the goroutine ends inside the exec, and nothing after it runs) leaves the
// box marked. The next daemon's run then runs post_start again.
func TestSkillBox_DaemonStopDuringPostStartLeavesBoxNotReady(t *testing.T) {
	boxes := newPostStartBoxes(0)
	boxes.onPostStart = runtime.Goexit
	s, skill := newPostStartSkillServer(t, boxes)
	ctx := ctxAs("admin", true)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _, _ = s.provisionBoxOnly(ctx, skill, "", "")
		t.Error("provisionBoxOnly returned; the exec was meant to never return")
	}()
	<-done
	if !boxes.pending(postStartSkillBox) {
		t.Fatal("a daemon that stopped during post_start left the box marked ready")
	}

	boxes.mu.Lock()
	boxes.onPostStart = nil
	boxes.mu.Unlock()
	restarted, _ := newPostStartSkillServer(t, boxes)
	if _, _, _, err := restarted.provisionBoxOnly(ctx, skill, "", ""); err != nil {
		t.Fatalf("run after restart: %v", err)
	}
	if got := boxes.runs(); got != 2 {
		t.Errorf("post_start ran %d time(s), want 2: the run after the restart must run it again", got)
	}
	if boxes.pending(postStartSkillBox) {
		t.Error("the run after the restart completed post_start; the marker must be gone")
	}
}
