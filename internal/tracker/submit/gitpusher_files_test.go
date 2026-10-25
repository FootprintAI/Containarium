package submit

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// #2798: PushSpec.Files are committed on top of the bundle's head, in the
// host-side bare repository, before the push, so the pushed branch carries
// them (the sealed Proof Pack).

// TestGitPusher_RealGit_CommitsFilesOnTopOfHead runs real git against a
// local bare remote: the pushed branch's tip is a new commit whose parent is
// the agent's head and whose tree has the file, replacing an agent-planted
// file at the same path.
func TestGitPusher_RealGit_CommitsFilesOnTopOfHead(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	root := t.TempDir()
	originDir := filepath.Join(root, "origin.git")
	workDir := filepath.Join(root, "work")
	if err := os.MkdirAll(filepath.Join(workDir, ".containarium"), 0o755); err != nil {
		t.Fatal(err)
	}
	testGit(t, root, "init", "--bare", "-q", originDir)
	testGit(t, workDir, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(workDir, "README.md"), []byte("base\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	testGit(t, workDir, "add", "README.md")
	testGit(t, workDir, "commit", "-q", "-m", "base")
	baseSHA := testGit(t, workDir, "rev-parse", "HEAD")
	testGit(t, workDir, "remote", "add", "origin", originDir)
	testGit(t, workDir, "push", "-q", "origin", "main")
	// The agent's change plants its own file at the attach path.
	if err := os.WriteFile(filepath.Join(workDir, ".containarium", "proof-pack.json"), []byte("forged\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	testGit(t, workDir, "add", ".")
	testGit(t, workDir, "commit", "-q", "-m", "agent change")
	headSHA := testGit(t, workDir, "rev-parse", "HEAD")
	bundlePath := filepath.Join(root, "out.bundle")
	testGit(t, workDir, "bundle", "create", bundlePath, baseSHA+"..HEAD")

	result, err := NewGitPusher().PushBundle(context.Background(), PushSpec{
		BundlePath: bundlePath, BaseSHA: baseSHA, HeadSHA: headSHA, RemoteURL: originDir,
		Credential: "unused", RunID: "run-files-2798-0001", IssueNumber: 9, Title: "Files",
		Files:        []File{{Path: ".containarium/proof-pack.json", Content: []byte("{\"sealed\":true}\n")}},
		FilesMessage: "Add Proof Pack",
	})
	if err != nil {
		t.Fatalf("PushBundle: %v", err)
	}
	if result.SHA == headSHA || len(result.SHA) != 40 {
		t.Fatalf("result.SHA = %q, want a new commit on top of %s", result.SHA, headSHA)
	}
	remoteTip := testGit(t, root, "ls-remote", originDir, "refs/heads/"+result.Branch)
	if !strings.HasPrefix(remoteTip, result.SHA) {
		t.Fatalf("remote %s = %q, want %s", result.Branch, remoteTip, result.SHA)
	}
	if parent := testGit(t, root, "--git-dir", originDir, "rev-parse", result.SHA+"^"); parent != headSHA {
		t.Errorf("parent = %s, want the agent's head %s", parent, headSHA)
	}
	if got := testGit(t, root, "--git-dir", originDir, "show", result.SHA+":.containarium/proof-pack.json"); got != `{"sealed":true}` {
		t.Errorf("attached file = %q, want the daemon's content, not the agent's", got)
	}
	if got := testGit(t, root, "--git-dir", originDir, "show", result.SHA+":README.md"); got != "base" {
		t.Errorf("README.md = %q, rest of the tree must be unchanged", got)
	}
	if msg := testGit(t, root, "--git-dir", originDir, "log", "-1", "--format=%s", result.SHA); msg != "Add Proof Pack" {
		t.Errorf("commit message = %q", msg)
	}
}

// idRunner is a fake gitRunFunc that records calls and prints a plausible
// object id for each object-writing subcommand, or what out overrides, so a
// test reaches exactly the guard it is about.
func idRunner(calls *[]recordedCall, out map[string]string) gitRunFunc {
	return func(_ context.Context, env []string, args []string) (string, string, error) {
		*calls = append(*calls, recordedCall{env: append([]string(nil), env...), args: append([]string(nil), args...)})
		for _, sub := range []string{"hash-object", "write-tree", "commit-tree"} {
			if contains(args, sub) {
				if v, ok := out[sub]; ok {
					return v, "", nil
				}
				return strings.Repeat("c", 40) + "\n", "", nil
			}
		}
		return "", "", nil
	}
}

func pushedRefspecs(calls []recordedCall) []string {
	var out []string
	for _, c := range calls {
		if contains(c.args, "push") {
			out = append(out, c.args[len(c.args)-1])
		}
	}
	return out
}

func TestGitPusher_FilesRejectsUnsafePaths(t *testing.T) {
	for _, p := range []string{"", "/etc/passwd", "../x", "a/../../x", "a//b", ".git/config", "a/.git/hooks/x", `a\b`} {
		var calls []recordedCall
		spec := validSpec()
		spec.Files = []File{{Path: p, Content: []byte("x")}}
		spec.FilesMessage = "m"
		if _, err := (&ExecGitPusher{run: idRunner(&calls, nil)}).PushBundle(context.Background(), spec); err == nil {
			t.Errorf("path %q accepted", p)
		}
		if len(calls) != 0 {
			t.Errorf("path %q: %d git calls before refusing, want none", p, len(calls))
		}
	}
	// The same runner accepts a safe path and pushes the new commit.
	var calls []recordedCall
	spec := validSpec()
	spec.Files = []File{{Path: ".containarium/proof-pack.json", Content: []byte("x")}}
	spec.FilesMessage = "m"
	res, err := (&ExecGitPusher{run: idRunner(&calls, nil)}).PushBundle(context.Background(), spec)
	if err != nil || res.SHA != strings.Repeat("c", 40) {
		t.Fatalf("safe path: res %+v err %v", res, err)
	}
	if got := pushedRefspecs(calls); len(got) != 1 || !strings.HasPrefix(got[0], strings.Repeat("c", 40)+":refs/heads/") {
		t.Errorf("pushed %v, want the files commit", got)
	}
}

// A commit step that yields no commit id must never reach push: an empty
// sha in "<sha>:refs/heads/<branch>" is a ref DELETION refspec.
func TestGitPusher_FilesEmptyCommitNeverPushes(t *testing.T) {
	var calls []recordedCall
	spec := validSpec()
	spec.Files = []File{{Path: ".containarium/proof-pack.json", Content: []byte("x")}}
	spec.FilesMessage = "m"
	_, err := (&ExecGitPusher{run: idRunner(&calls, map[string]string{"commit-tree": ""})}).PushBundle(context.Background(), spec)
	if err == nil {
		t.Fatal("PushBundle succeeded although the commit step printed no commit id")
	}
	if got := pushedRefspecs(calls); len(got) != 0 {
		t.Fatalf("pushed %v after an empty commit id", got)
	}
}
