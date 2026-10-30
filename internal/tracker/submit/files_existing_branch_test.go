package submit

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// #3288: when head_branch already exists on the remote, PushFiles builds
// the new commit on the head branch's tip and pushes it as a fast-forward;
// it never forces, and a tip that moved under it is refused.

// seedRemote creates a bare remote with one commit on "trunk" and returns
// the remote path, a work tree pushing to it, and the base commit.
func seedRemote(t *testing.T) (root, origin, work, baseSHA string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	root = t.TempDir()
	origin = filepath.Join(root, "origin.git")
	work = filepath.Join(root, "work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	testGit(t, root, "init", "--bare", "-q", origin)
	testGit(t, work, "init", "-q", "-b", "trunk")
	if err := os.WriteFile(filepath.Join(work, "README.md"), []byte("base\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	testGit(t, work, "add", ".")
	testGit(t, work, "commit", "-q", "-m", "base")
	testGit(t, work, "push", "-q", origin, "trunk")
	return root, origin, work, testGit(t, work, "rev-parse", "HEAD")
}

func filesSpec(origin string, files ...ChangeFile) FilesSpec {
	return FilesSpec{
		RemoteURL: origin, Credential: "unused-for-local-file-remote",
		BaseBranch: "trunk", HeadBranch: "containarium/issue-7",
		Message: "Fix the thing\n\nsigned", Files: files,
	}
}

// TestPushFiles_RealGit_ExistingHeadBranch_AppendsOnTip: a second call for
// the same head branch adds exactly one commit on top of the first (keeping
// the first commit's files), and an identical retry of the second call is a
// no-op that returns the same tip.
func TestPushFiles_RealGit_ExistingHeadBranch_AppendsOnTip(t *testing.T) {
	root, origin, _, baseSHA := seedRemote(t)

	first, err := NewGitPusher().PushFiles(context.Background(), filesSpec(origin, ChangeFile{Path: "docs/a.md", Content: "a\n"}))
	if err != nil {
		t.Fatalf("first PushFiles: %v", err)
	}
	if parent := testGit(t, origin, "rev-parse", first.SHA+"^"); parent != baseSHA {
		t.Fatalf("first commit parent = %s, want base %s (fresh branch unchanged)", parent, baseSHA)
	}

	spec := filesSpec(origin, ChangeFile{Path: "docs/b.md", Content: "b\n"})
	second, err := NewGitPusher().PushFiles(context.Background(), spec)
	if err != nil {
		t.Fatalf("second PushFiles on the existing head branch: %v", err)
	}
	if second.SHA == first.SHA || len(second.SHA) != 40 {
		t.Fatalf("second SHA = %q, want a new commit on top of %s", second.SHA, first.SHA)
	}
	if parent := testGit(t, origin, "rev-parse", second.SHA+"^"); parent != first.SHA {
		t.Errorf("second commit parent = %s, want the head branch tip %s", parent, first.SHA)
	}
	if second.BaseSHA != first.SHA {
		t.Errorf("BaseSHA = %s, want the commit it was built on (%s)", second.BaseSHA, first.SHA)
	}
	if got := testGit(t, root, "ls-remote", origin, "refs/heads/containarium/issue-7"); !strings.HasPrefix(got, second.SHA) {
		t.Errorf("remote head branch = %q, want %s", got, second.SHA)
	}
	if got := testGit(t, origin, "show", second.SHA+":docs/a.md"); got != "a" {
		t.Errorf("docs/a.md = %q, the first commit's file must survive", got)
	}
	if got := testGit(t, origin, "show", second.SHA+":docs/b.md"); got != "b" {
		t.Errorf("docs/b.md = %q", got)
	}
	if got := testGit(t, root, "ls-remote", origin, "refs/heads/trunk"); !strings.HasPrefix(got, baseSHA) {
		t.Errorf("base branch moved: %q", got)
	}

	again, err := NewGitPusher().PushFiles(context.Background(), spec)
	if err != nil {
		t.Fatalf("retry PushFiles: %v", err)
	}
	if again.SHA != second.SHA {
		t.Errorf("identical retry produced %s, want the existing tip %s (no empty commit)", again.SHA, second.SHA)
	}
}

// TestPushFiles_RealGit_ExistingHeadBranchFromElsewhere: a head branch
// someone else created (not by PushFiles, with its own commit) is built on,
// not replaced.
func TestPushFiles_RealGit_ExistingHeadBranchFromElsewhere(t *testing.T) {
	_, origin, work, _ := seedRemote(t)
	testGit(t, work, "checkout", "-q", "-b", "containarium/issue-7")
	if err := os.WriteFile(filepath.Join(work, "human.txt"), []byte("human\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	testGit(t, work, "add", ".")
	testGit(t, work, "commit", "-q", "-m", "human commit")
	testGit(t, work, "push", "-q", origin, "containarium/issue-7")
	humanSHA := testGit(t, work, "rev-parse", "HEAD")

	res, err := NewGitPusher().PushFiles(context.Background(), filesSpec(origin, ChangeFile{Path: "docs/a.md", Content: "a\n"}))
	if err != nil {
		t.Fatalf("PushFiles: %v", err)
	}
	if parent := testGit(t, origin, "rev-parse", res.SHA+"^"); parent != humanSHA {
		t.Errorf("parent = %s, want the existing tip %s", parent, humanSHA)
	}
	if got := testGit(t, origin, "show", res.SHA+":human.txt"); got != "human" {
		t.Errorf("human.txt = %q, the existing commit must be kept", got)
	}
}

// TestPushFiles_RealGit_HeadMovedBeforePush_RefusedNeverForced: the head
// branch moves on the remote after PushFiles fetched it (a concurrent
// writer). The non-forced push is rejected, the error says the branch moved,
// and the concurrent writer's commit is still the remote tip.
func TestPushFiles_RealGit_HeadMovedBeforePush_RefusedNeverForced(t *testing.T) {
	root, origin, work, _ := seedRemote(t)
	first, err := NewGitPusher().PushFiles(context.Background(), filesSpec(origin, ChangeFile{Path: "docs/a.md", Content: "a\n"}))
	if err != nil {
		t.Fatalf("first PushFiles: %v", err)
	}

	// The racer: a commit on the head branch pushed just before our push.
	testGit(t, work, "fetch", "-q", origin, "containarium/issue-7")
	testGit(t, work, "checkout", "-q", "-b", "racer", "FETCH_HEAD")
	if err := os.WriteFile(filepath.Join(work, "racer.txt"), []byte("racer\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	testGit(t, work, "add", ".")
	testGit(t, work, "commit", "-q", "-m", "racer")
	racerSHA := testGit(t, work, "rev-parse", "HEAD")

	raced := false
	p := &ExecGitPusher{run: func(ctx context.Context, env, args []string) (string, string, error) {
		if contains(args, "push") && !raced {
			raced = true
			testGit(t, work, "push", "-q", origin, "racer:containarium/issue-7")
		}
		return realGitRun(ctx, env, args)
	}}
	_, err = p.PushFiles(context.Background(), filesSpec(origin, ChangeFile{Path: "docs/b.md", Content: "b\n"}))
	if !errors.Is(err, ErrHeadBranchMoved) {
		t.Fatalf("PushFiles = %v, want ErrHeadBranchMoved", err)
	}
	if !strings.Contains(err.Error(), "containarium/issue-7") {
		t.Errorf("error %q does not name the branch", err)
	}
	if got := testGit(t, root, "ls-remote", origin, "refs/heads/containarium/issue-7"); !strings.HasPrefix(got, racerSHA) {
		t.Errorf("remote head branch = %q, want the racer's %s kept (never forced over %s)", got, racerSHA, first.SHA)
	}
}

// tipRunner is a fake gitRunFunc for the existing-branch path: ls-remote
// reports tip for the head branch, object-writing commands print ids.
func tipRunner(calls *[]recordedCall, tip string) gitRunFunc {
	ids := idRunner(calls, nil)
	return func(ctx context.Context, env, args []string) (string, string, error) {
		if contains(args, "ls-remote") {
			*calls = append(*calls, recordedCall{env: env, args: args})
			if tip == "" {
				return "", "", nil
			}
			return tip + "\trefs/heads/containarium/issue-7\n", "", nil
		}
		if contains(args, "rev-parse") {
			*calls = append(*calls, recordedCall{env: env, args: args})
			if strings.HasSuffix(args[len(args)-1], "^{tree}") {
				return strings.Repeat("e", 40) + "\n", "", nil // never equal to write-tree's
			}
			return strings.Repeat("a", 40) + "\n", "", nil
		}
		return ids(ctx, env, args)
	}
}

// TestPushFiles_NeverForces: on both the fresh-branch and the
// existing-branch path, the push carries no force flag and no "+" refspec.
func TestPushFiles_NeverForces(t *testing.T) {
	for _, tc := range []struct {
		name string
		tip  string
	}{
		{"fresh branch", ""},
		{"existing branch", strings.Repeat("f", 40)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []recordedCall
			p := &ExecGitPusher{run: tipRunner(&calls, tc.tip)}
			if _, err := p.PushFiles(context.Background(), filesSpec("https://tracker.example/acme/widgets.git", ChangeFile{Path: "a", Content: "x"})); err != nil {
				t.Fatalf("PushFiles: %v", err)
			}
			pushes := 0
			for _, c := range calls {
				if !contains(c.args, "push") {
					continue
				}
				pushes++
				for _, a := range c.args {
					if a == "-f" || strings.HasPrefix(a, "--force") || a == "--mirror" || strings.HasPrefix(a, "+") {
						t.Errorf("push argv %q forces (%q)", c.args, a)
					}
				}
			}
			if pushes != 1 {
				t.Fatalf("%d pushes, want 1", pushes)
			}
			fetchedHead := false
			for _, c := range calls {
				if contains(c.args, "fetch") && contains(c.args, "refs/heads/containarium/issue-7") {
					fetchedHead = true
				}
			}
			if fetchedHead != (tc.tip != "") {
				t.Errorf("fetched head branch = %v, want %v", fetchedHead, tc.tip != "")
			}
		})
	}
}
