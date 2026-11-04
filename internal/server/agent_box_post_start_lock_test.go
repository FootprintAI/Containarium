package server

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/recipes"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3555: the first deploy of a skill's box and a later run that would re-run
// its post_start share one per-box lock, so two post_starts never run in one
// box at once, and a run that arrives during the first post_start cannot
// clear the not-prepared mark before that post_start has finished.

// waitFor polls cond until it holds, failing the test after a generous
// deadline (the condition is expected to hold within milliseconds).
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// blockFirstPostStart makes the first post_start on boxes wait until the
// returned release func is called; later post_starts return at once.
func blockFirstPostStart(boxes *postStartBoxes) (release func()) {
	gate := make(chan struct{})
	var calls atomic.Int32
	boxes.onPostStart = func() {
		if calls.Add(1) == 1 {
			<-gate
		}
	}
	var closeOnce sync.Once
	return func() { closeOnce.Do(func() { close(gate) }) }
}

// startFirstDeploy runs the box's first deploy: through a skill run's
// provisionBoxOnly (sync), or as an async DeployRecipe, which returns while
// post_start runs in the background. done receives the run's error.
func startFirstDeploy(t *testing.T, s *AgentSkillServer, skill *pb.AgentSkill, async bool) (done chan error) {
	t.Helper()
	ctx := ctxAs("admin", true)
	done = make(chan error, 1)
	go func() {
		if async {
			_, err := s.recipes.deploy(ctx, &pb.DeployRecipeRequest{
				RecipeId: skill.GetRecipeId(), Name: "agent-" + skill.Id, Async: true,
			})
			done <- err
			return
		}
		_, _, _, err := s.provisionBoxOnly(ctx, skill, "", "")
		done <- err
	}()
	return done
}

// TestSkillBox_ConcurrentRunsRunPostStartOneAtATime: a second run that
// arrives while the first deploy's post_start is still running waits for it.
// Only one post_start runs in the box at a time, the first post_start's
// failure leaves the box marked (the second run did not clear the mark under
// it), and the second run then re-runs post_start on the still-marked box.
func TestSkillBox_ConcurrentRunsRunPostStartOneAtATime(t *testing.T) {
	for _, tc := range []struct {
		name  string
		async bool
	}{
		{"sync first deploy", false},
		{"async first deploy", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			boxes := newPostStartBoxes(0)
			boxes.exitCodes = []int{1, 0} // the first post_start fails, the re-run succeeds
			release := blockFirstPostStart(boxes)
			defer release()
			s, skill := newPostStartSkillServer(t, boxes)

			first := startFirstDeploy(t, s, skill, tc.async)
			waitFor(t, "the first post_start to start", func() bool { return boxes.runs() == 1 })
			if tc.async {
				if err := <-first; err != nil {
					t.Fatalf("async deploy: %v", err)
				}
			}

			gets := boxes.gets()
			second := make(chan error, 1)
			go func() {
				_, _, _, err := s.provisionBoxOnly(ctxAs("admin", true), skill, "", "")
				second <- err
			}()
			waitFor(t, "the second run to look up the box", func() bool { return boxes.gets() > gets })
			// Without the shared lock the second run runs its post_start and
			// finishes right after that lookup; give it the time to.
			var secondErr error
			secondDone := false
			select {
			case secondErr = <-second:
				secondDone = true
			case <-time.After(200 * time.Millisecond):
			}
			release()

			if !tc.async {
				if err := <-first; err == nil {
					t.Error("first run: its post_start failed, the run must fail")
				}
			}
			if !secondDone {
				secondErr = <-second
			}
			if secondErr != nil {
				t.Errorf("second run: %v", secondErr)
			}

			boxes.mu.Lock()
			defer boxes.mu.Unlock()
			if boxes.maxConcurrent != 1 {
				t.Errorf("post_start ran %d at once in one box, want 1", boxes.maxConcurrent)
			}
			if boxes.postStartRuns != 2 {
				t.Errorf("post_start ran %d time(s), want 2 (the deploy's, then the second run's re-run)", boxes.postStartRuns)
			}
			if len(boxes.pendingAtEnd) == 0 || !boxes.pendingAtEnd[0] {
				t.Errorf("the mark was gone when the first post_start returned (marker at each post_start's end = %v): a concurrent run cleared it", boxes.pendingAtEnd)
			}
			if len(boxes.pendingAtRun) != 2 || !boxes.pendingAtRun[1] {
				t.Errorf("the re-run must find the failed first post_start's mark; marker at each post_start's start = %v", boxes.pendingAtRun)
			}
			if boxes.boxes[postStartSkillBox][incus.PostStartPendingKey] != "" {
				t.Error("the re-run succeeded; the mark must be gone")
			}
		})
	}
}

// TestSkillBox_WaitingRunHonoursCancel: a run waiting for another run's
// post_start on the same box gives up when its own context ends, instead of
// waiting out the whole post_start, and does not run post_start itself.
func TestSkillBox_WaitingRunHonoursCancel(t *testing.T) {
	boxes := newPostStartBoxes(0)
	release := blockFirstPostStart(boxes)
	defer release()
	s, skill := newPostStartSkillServer(t, boxes)

	first := startFirstDeploy(t, s, skill, false)
	waitFor(t, "the first post_start to start", func() bool { return boxes.runs() == 1 })

	ctx, cancel := context.WithCancel(ctxAs("admin", true))
	second := make(chan error, 1)
	gets := boxes.gets()
	go func() {
		_, _, _, err := s.provisionBoxOnly(ctx, skill, "", "")
		second <- err
	}()
	waitFor(t, "the second run to look up the box", func() bool { return boxes.gets() > gets })
	cancel()

	select {
	case err := <-second:
		if status.Code(err) != codes.Canceled {
			t.Errorf("waiting run: code = %v (%v), want Canceled", status.Code(err), err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a waiting run ignored its cancelled context")
	}
	if got := boxes.runs(); got != 1 {
		t.Errorf("post_start ran %d time(s), want 1: the cancelled run must not run it", got)
	}
	release()
	if err := <-first; err != nil {
		t.Errorf("first run: %v", err)
	}
}

// TestSkillBox_FailedMarkWriteIsReported: when the not-prepared mark cannot
// be written, the deploy goes on (the box is kept, nothing is deleted), and
// the caller is told: in the post_start error when post_start then fails
// (a later run would reuse the box without re-running it), and as a warning
// in an async deploy's message, whose post_start outcome is not known yet.
func TestSkillBox_FailedMarkWriteIsReported(t *testing.T) {
	const want = "could not be marked as not prepared"
	ctx := ctxAs("admin", true)

	t.Run("sync, post_start fails", func(t *testing.T) {
		boxes := newPostStartBoxes(1)
		boxes.setConfigErr = errors.New("config write refused")
		s, skill := newPostStartSkillServer(t, boxes)
		_, _, _, err := s.provisionBoxOnly(ctx, skill, "", "")
		if err == nil {
			t.Fatal("a failed post_start must fail the run")
		}
		for _, w := range []string{"exit status 1", want, "config write refused"} {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("error %q does not mention %q", err, w)
			}
		}
		if _, ok := boxes.boxes[postStartSkillBox]; !ok {
			t.Error("the box was removed; it must be kept")
		}
	})

	t.Run("sync, post_start succeeds", func(t *testing.T) {
		boxes := newPostStartBoxes(0)
		boxes.setConfigErr = errors.New("config write refused")
		s, skill := newPostStartSkillServer(t, boxes)
		if _, _, fresh, err := s.provisionBoxOnly(ctx, skill, "", ""); err != nil || !fresh {
			t.Fatalf("fresh=%v err=%v: a deploy whose post_start succeeded must not fail over the mark", fresh, err)
		}
	})

	t.Run("async", func(t *testing.T) {
		boxes := newPostStartBoxes(0)
		boxes.setConfigErr = errors.New("config write refused")
		s, skill := newPostStartSkillServer(t, boxes)
		resp, err := s.recipes.deploy(ctx, &pb.DeployRecipeRequest{RecipeId: skill.GetRecipeId(), Name: "agent-" + skill.Id, Async: true})
		if err != nil {
			t.Fatalf("async deploy: %v", err)
		}
		if !strings.Contains(resp.GetMessage(), want) {
			t.Errorf("async deploy message %q does not warn that the box %s", resp.GetMessage(), want)
		}
		waitFor(t, "the async post_start to finish", func() bool {
			boxes.mu.Lock()
			defer boxes.mu.Unlock()
			return boxes.postStartRuns == 1 && boxes.inFlight == 0
		})
	})
}

const rerunBranchesRecipeYAML = `recipes:
  - id: gated
    image: x
    guardrail_gate:
      dataset_path: /data/train
      require_kinds: [pii]
    post_start:
      - echo up
  - id: needs-param
    image: x
    parameters:
      - name: model
        label: Model
        type: string
        required: true
    post_start:
      - echo up
`

// TestRerunPendingPostStart_RefusedBranches: a marked box whose post_start
// cannot be re-run (its recipe left the catalog, the recipe is
// guardrail-gated, or its parameters no longer resolve) fails the run with
// FailedPrecondition, does not run post_start, and keeps the box marked.
func TestRerunPendingPostStart_RefusedBranches(t *testing.T) {
	catalog := recipes.New()
	if err := catalog.LoadFromBytes([]byte(rerunBranchesRecipeYAML)); err != nil {
		t.Fatal(err)
	}
	const name = "agent-x"
	const container = name + "-container"
	for _, tc := range []struct {
		name, recipeID, want string
	}{
		{"catalog miss", "gone", `its recipe "gone" is no longer in the catalog`},
		{"guardrail-gated", "gated", `recipe "gated" is guardrail-gated`},
		{"parameters do not resolve", "needs-param", "its parameters no longer resolve"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			boxes := newPostStartBoxes(0)
			boxes.boxes[container] = map[string]string{incus.PostStartPendingKey: incus.PostStartPendingValue}
			s := &RecipeServer{catalog: catalog, boxes: boxes}
			err := s.rerunPendingPostStart(ctxAs("admin", true), tc.recipeID, name, nil)
			if status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("code = %v (%v), want FailedPrecondition", status.Code(err), err)
			}
			for _, w := range []string{container, "not fully prepared", tc.want} {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not mention %q", err, w)
				}
			}
			if got := boxes.runs(); got != 0 {
				t.Errorf("post_start ran %d time(s), want 0", got)
			}
			if !boxes.pending(container) {
				t.Error("the box must stay marked")
			}
		})
	}
}
