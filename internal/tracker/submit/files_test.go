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

func TestValidateChangeFiles(t *testing.T) {
	ok := func(p string) ChangeFile { return ChangeFile{Path: p, Content: "x"} }
	tests := []struct {
		name    string
		files   []ChangeFile
		max     int64
		wantErr error
	}{
		{"one file", []ChangeFile{ok("README.md")}, 10, nil},
		{"nested", []ChangeFile{ok("docs/a/b.md"), ok("src/main.go")}, 10, nil},
		{"none", nil, 10, ErrInvalidChangeFile},
		{"empty path", []ChangeFile{ok("")}, 10, ErrInvalidChangeFile},
		{"absolute", []ChangeFile{ok("/etc/passwd")}, 10, ErrInvalidChangeFile},
		{"dotdot", []ChangeFile{ok("../x")}, 10, ErrInvalidChangeFile},
		{"inner dotdot", []ChangeFile{ok("a/../b")}, 10, ErrInvalidChangeFile},
		{"dot segment", []ChangeFile{ok("./a")}, 10, ErrInvalidChangeFile},
		{"double slash", []ChangeFile{ok("a//b")}, 10, ErrInvalidChangeFile},
		{"trailing slash", []ChangeFile{ok("a/")}, 10, ErrInvalidChangeFile},
		{"git dir", []ChangeFile{ok(".git/config")}, 10, ErrInvalidChangeFile},
		{"git dir any case", []ChangeFile{ok("sub/.GIT/hooks/x")}, 10, ErrInvalidChangeFile},
		{"backslash", []ChangeFile{ok(`a\b`)}, 10, ErrInvalidChangeFile},
		{"control char", []ChangeFile{ok("a\nb")}, 10, ErrInvalidChangeFile},
		{"duplicate", []ChangeFile{ok("a"), ok("a")}, 10, ErrInvalidChangeFile},
		{"at cap", []ChangeFile{{Path: "a", Content: "12345"}, {Path: "b", Content: "67890"}}, 10, nil},
		{"over cap", []ChangeFile{{Path: "a", Content: "12345"}, {Path: "b", Content: "678901"}}, 10, ErrChangeFilesTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateChangeFiles(tt.files, tt.max)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ValidateChangeFiles = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateBranchName(t *testing.T) {
	for _, good := range []string{"main", "containarium/issue-7", "release/1.2", "feat_x"} {
		if err := ValidateBranchName(good); err != nil {
			t.Errorf("ValidateBranchName(%q) = %v, want nil", good, err)
		}
	}
	for _, bad := range []string{"", "-x", "/x", "x/", "a..b", "a//b", "a.lock", "a b", "a~1", "a^", "a:b", "a?", "a*", "a[", `a\b`, "@", "a@{1}", ".hidden", "a/.b", "HEAD", "refs/heads/x"} {
		if err := ValidateBranchName(bad); !errors.Is(err, ErrInvalidBranch) {
			t.Errorf("ValidateBranchName(%q) = %v, want ErrInvalidBranch", bad, err)
		}
	}
}

func TestFilesBranchName_StableAndScoped(t *testing.T) {
	a := FilesBranchName("alice", "default", 7, "Fix the thing")
	if a != FilesBranchName("alice", "default", 7, "Fix the thing") {
		t.Fatal("FilesBranchName is not deterministic")
	}
	if !strings.HasPrefix(a, "agent/") || !strings.HasSuffix(a, "/7-fix-the-thing") {
		t.Errorf("FilesBranchName = %q, want agent/<id>/7-fix-the-thing", a)
	}
	if err := ValidateBranchName(a); err != nil {
		t.Errorf("FilesBranchName produced an invalid branch %q: %v", a, err)
	}
	for _, other := range []string{
		FilesBranchName("bob", "default", 7, "Fix the thing"),
		FilesBranchName("alice", "other", 7, "Fix the thing"),
		FilesBranchName("alice", "default", 8, "Fix the thing"),
	} {
		if other == a {
			t.Errorf("FilesBranchName collided across tenants/connections/issues: %q", a)
		}
	}
}

func TestPushFiles_RefusesHeadEqualToBase(t *testing.T) {
	var calls []recordedCall
	p := &ExecGitPusher{run: fakeRunner(&calls)}
	_, err := p.PushFiles(context.Background(), FilesSpec{
		RemoteURL: "https://tracker.example/acme/widgets.git", BaseBranch: "main", HeadBranch: "main",
		Message: "m", Files: []ChangeFile{{Path: "a", Content: "x"}},
	})
	if !errors.Is(err, ErrInvalidBranch) {
		t.Fatalf("PushFiles = %v, want ErrInvalidBranch", err)
	}
	if len(calls) != 0 {
		t.Errorf("git ran %d times before refusing; want 0", len(calls))
	}
}

func TestPushFiles_CredentialNeverInArgv(t *testing.T) {
	var calls []recordedCall
	p := &ExecGitPusher{run: func(_ context.Context, env, args []string) (string, string, error) {
		calls = append(calls, recordedCall{env: env, args: args})
		return "deadbeef\n", "", nil // a non-empty "sha" so every step runs
	}}
	const cred = "s3cr3t-token-value"
	_, _ = p.PushFiles(context.Background(), FilesSpec{
		RemoteURL: "https://tracker.example/acme/widgets.git", Credential: cred, BaseBranch: "main",
		HeadBranch: "agent/x/1", Message: "m", Files: []ChangeFile{{Path: "a", Content: "x"}},
	})
	if len(calls) == 0 || !contains(calls[len(calls)-1].args, "push") {
		t.Fatalf("last git invocation is not the push; calls=%v", calls)
	}
	for i, c := range calls {
		if strings.Contains(strings.Join(c.args, " "), cred) || contains(c.args, "-c") {
			t.Errorf("call %d argv %q carries the credential or a -c flag", i, c.args)
		}
		if !contains(c.env, "GIT_CONFIG_VALUE_2=AUTHORIZATION: bearer "+cred) || !contains(c.env, "GIT_CONFIG_NOSYSTEM=1") {
			t.Errorf("call %d env lacks the hardened config / auth header", i)
		}
	}
}

// TestPushFiles_RealGit_LocalBareRemote is the real-git integration test
// (no network — the remote is a local bare repository): the pushed branch
// is base + exactly one commit carrying the files, the executable bit of
// an overwritten file survives, base is untouched, and an identical retry
// is a no-op that yields the same commit.
func TestPushFiles_RealGit_LocalBareRemote(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	root := t.TempDir()
	origin := filepath.Join(root, "origin.git")
	work := filepath.Join(root, "work")
	if err := os.MkdirAll(filepath.Join(work, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	testGit(t, root, "init", "--bare", "-q", origin)
	testGit(t, work, "init", "-q", "-b", "trunk")
	if err := os.WriteFile(filepath.Join(work, "README.md"), []byte("base\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "bin", "run.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil { // #nosec G306 -- test fixture must be executable
		t.Fatal(err)
	}
	testGit(t, work, "add", ".")
	testGit(t, work, "commit", "-q", "-m", "base")
	baseSHA := testGit(t, work, "rev-parse", "HEAD")
	testGit(t, work, "push", "-q", origin, "trunk")

	spec := FilesSpec{
		RemoteURL:  origin,
		Credential: "unused-for-local-file-remote",
		BaseBranch: "trunk",
		HeadBranch: "containarium/issue-7",
		Message:    "Fix the thing\n\nsigned",
		Files: []ChangeFile{
			{Path: "README.md", Content: "changed\n"},
			{Path: "docs/new.md", Content: "new\n"},
			{Path: "bin/run.sh", Content: "#!/bin/sh\necho hi\n"},
		},
	}
	res, err := NewGitPusher().PushFiles(context.Background(), spec)
	if err != nil {
		t.Fatalf("PushFiles: %v", err)
	}
	if res.Branch != spec.HeadBranch || len(res.SHA) != 40 {
		t.Fatalf("result = %+v, want branch %q and a full sha", res, spec.HeadBranch)
	}
	if got := testGit(t, root, "ls-remote", origin, "refs/heads/containarium/issue-7"); !strings.HasPrefix(got, res.SHA) {
		t.Errorf("remote head branch = %q, want %s", got, res.SHA)
	}
	if got := testGit(t, root, "ls-remote", origin, "refs/heads/trunk"); !strings.HasPrefix(got, baseSHA) {
		t.Errorf("base branch moved: %q", got)
	}
	if parent := testGit(t, origin, "rev-parse", res.SHA+"^"); parent != baseSHA {
		t.Errorf("commit parent = %s, want base %s", parent, baseSHA)
	}
	if got := testGit(t, origin, "show", res.SHA+":docs/new.md"); got != "new" {
		t.Errorf("docs/new.md = %q", got)
	}
	if got := testGit(t, origin, "show", res.SHA+":README.md"); got != "changed" {
		t.Errorf("README.md = %q", got)
	}
	if got := testGit(t, origin, "ls-tree", res.SHA, "bin/run.sh"); !strings.HasPrefix(got, "100755 ") {
		t.Errorf("bin/run.sh lost its executable bit: %q", got)
	}
	if got := testGit(t, origin, "log", "-1", "--format=%an <%ae>|%s", res.SHA); got != CommitAuthorName+" <"+CommitAuthorEmail+">|Fix the thing" {
		t.Errorf("commit author/subject = %q", got)
	}

	again, err := NewGitPusher().PushFiles(context.Background(), spec)
	if err != nil {
		t.Fatalf("retry PushFiles: %v", err)
	}
	if again.SHA != res.SHA {
		t.Errorf("retry produced %s, want the same commit %s", again.SHA, res.SHA)
	}
}

func TestPushFiles_RealGit_MissingBaseBranch(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	root := t.TempDir()
	origin := filepath.Join(root, "origin.git")
	testGit(t, root, "init", "--bare", "-q", origin)
	_, err := NewGitPusher().PushFiles(context.Background(), FilesSpec{
		RemoteURL: origin, BaseBranch: "nope", HeadBranch: "agent/x/1", Message: "m",
		Files: []ChangeFile{{Path: "a", Content: "x"}},
	})
	if err == nil || !strings.Contains(err.Error(), "fetch base branch") {
		t.Fatalf("PushFiles = %v, want a fetch base branch error", err)
	}
}
