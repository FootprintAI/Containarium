package submit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// DefaultMaxChangeFilesBytes caps the total content of one
// SubmitTrackerChangeFiles request — the same budget a bundle gets.
const DefaultMaxChangeFilesBytes = DefaultMaxBundleBytes

// MaxChangeFiles caps how many files one request may carry: each costs
// two git invocations on the host.
const MaxChangeFiles = 1000

// CommitAuthorName / CommitAuthorEmail are the daemon identity a
// file-set commit is authored and committed as. The acting run or
// operator is named by the stamp in the commit message, not here.
const (
	CommitAuthorName  = "Containarium"
	CommitAuthorEmail = "containarium@noreply.invalid"
)

var (
	// ErrInvalidChangeFile: a file set that is empty, too many files, or
	// has a path that is not clean and repo-relative.
	ErrInvalidChangeFile = errors.New("submit: invalid change file")
	// ErrChangeFilesTooLarge: the file set's total content is over the cap.
	ErrChangeFilesTooLarge = errors.New("submit: change files exceed size cap")
	// ErrInvalidBranch: a base or head branch that is not a plain branch
	// name, or a head branch equal to the base.
	ErrInvalidBranch = errors.New("submit: invalid branch name")
	// ErrHeadBranchMoved: the head branch's remote tip changed between
	// the fetch PushFiles built on and its push, so the non-forced push
	// was refused. Nothing was overwritten; the caller may retry.
	ErrHeadBranchMoved = errors.New("submit: head branch moved on the remote")
)

// ChangeFile is one whole file of a file-set change.
type ChangeFile struct {
	Path    string
	Content string
}

// FilesSpec is PushFiles' input. RemoteURL and Credential come from the
// connection record, as for PushSpec.
type FilesSpec struct {
	RemoteURL  string
	Credential string
	BaseBranch string
	HeadBranch string
	// Message is the full commit message (subject, blank line, body).
	Message string
	Files   []ChangeFile
}

// FilePusher commits a file set on top of a remote branch and pushes it.
type FilePusher interface {
	PushFiles(ctx context.Context, spec FilesSpec) (PushResult, error)
}

// ValidateChangeFiles refuses an empty or oversized file set and any
// path that is not already clean and repo-relative: no leading "/", no
// "", "." or ".." segment, no ".git" segment (any case), no backslash or
// control character, no duplicates.
func ValidateChangeFiles(files []ChangeFile, maxBytes int64) error {
	if len(files) == 0 {
		return fmt.Errorf("%w: at least one file is required", ErrInvalidChangeFile)
	}
	if len(files) > MaxChangeFiles {
		return fmt.Errorf("%w: %d files, max %d", ErrInvalidChangeFile, len(files), MaxChangeFiles)
	}
	seen := make(map[string]struct{}, len(files))
	var total int64
	for _, f := range files {
		if err := validateChangePath(f.Path); err != nil {
			return err
		}
		if _, dup := seen[f.Path]; dup {
			return fmt.Errorf("%w: duplicate path %q", ErrInvalidChangeFile, f.Path)
		}
		seen[f.Path] = struct{}{}
		total += int64(len(f.Content))
	}
	if total > maxBytes {
		return fmt.Errorf("%w: %d bytes, max %d", ErrChangeFilesTooLarge, total, maxBytes)
	}
	return nil
}

func validateChangePath(p string) error {
	if p == "" || strings.HasPrefix(p, "/") || strings.ContainsRune(p, '\\') {
		return fmt.Errorf("%w: path %q must be repo-relative", ErrInvalidChangeFile, p)
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: path %q contains a control character", ErrInvalidChangeFile, p)
		}
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." || strings.EqualFold(seg, ".git") {
			return fmt.Errorf("%w: path %q is not a clean repo-relative path", ErrInvalidChangeFile, p)
		}
	}
	return nil
}

// branchSegment is the conservative subset of git-check-ref-format this
// package accepts for one "/"-separated segment of a branch name.
var branchSegment = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*$`)

// ValidateBranchName accepts a plain branch name (no "refs/" prefix):
// "/"-separated segments of letters, digits, ".", "_" and "-", none
// starting with "." or "-", no "..", no ".lock" suffix, not "HEAD".
func ValidateBranchName(b string) error {
	if b == "" || b == "HEAD" || strings.HasPrefix(b, "refs/") || strings.Contains(b, "..") || strings.HasSuffix(b, ".lock") {
		return fmt.Errorf("%w: %q", ErrInvalidBranch, b)
	}
	for _, seg := range strings.Split(b, "/") {
		if !branchSegment.MatchString(seg) || strings.HasSuffix(seg, ".lock") {
			return fmt.Errorf("%w: %q", ErrInvalidBranch, b)
		}
	}
	return nil
}

// FilesBranchName is the daemon-chosen head branch for a file-set
// change with no head_branch: BranchName's agent/<id>/<issue>-<slug>
// shape, with <id> a stable hash of (username, connection, issue) in
// place of a run id — so a retry of the same request lands on the same
// branch, and two tenants or connections never share one.
func FilesBranchName(username, connection string, issue int64, title string) string {
	sum := sha256.Sum256([]byte(username + "\x00" + connection + "\x00" + strconv.FormatInt(issue, 10)))
	return BranchName(hex.EncodeToString(sum[:]), issue, title)
}

// PushFiles builds one commit carrying spec.Files and pushes it to
// spec.HeadBranch without force, in a fresh temporary bare repository
// through the same hardened environment as PushBundle. The commit is
// built entirely with plumbing (hash-object, update-index on a private
// index, write-tree, commit-tree) — no work tree, so nothing from the
// remote's tree is ever checked out or followed on the host.
//
// What the commit is built on depends on whether spec.HeadBranch already
// exists on the remote (#3288):
//
//   - It does not: spec.BaseBranch is fetched (depth 1) and the commit is
//     built on its tip, creating the head branch.
//   - It does: the head branch is fetched (depth 1) and the commit is
//     built on its tip, so the push is a fast-forward that keeps every
//     commit already there. If the files change nothing on that tip, no
//     commit is made and nothing is pushed; the tip is returned.
//
// The push is never forced. If the head branch's remote tip changed
// between the fetch and the push, git refuses the push and PushFiles
// returns ErrHeadBranchMoved; the remote is left as the other writer
// left it.
//
// The commit's author/committer is the daemon identity and its date is
// its parent's, so the same request on the same parent produces the
// same commit and a retry's push is a no-op rather than a rejected
// non-fast-forward. An existing file keeps its mode (an executable stays
// executable); a new file is 100644.
func (p *ExecGitPusher) PushFiles(ctx context.Context, spec FilesSpec) (PushResult, error) {
	if err := ValidateBranchName(spec.BaseBranch); err != nil {
		return PushResult{}, err
	}
	if err := ValidateBranchName(spec.HeadBranch); err != nil {
		return PushResult{}, err
	}
	if spec.HeadBranch == spec.BaseBranch {
		return PushResult{}, fmt.Errorf("%w: head branch must differ from base branch %q", ErrInvalidBranch, spec.BaseBranch)
	}
	if err := ValidateChangeFiles(spec.Files, DefaultMaxChangeFilesBytes); err != nil {
		return PushResult{}, err
	}

	tmp, err := os.MkdirTemp("", "containarium-submit-files-*")
	if err != nil {
		return PushResult{}, fmt.Errorf("submit: create temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	repo := filepath.Join(tmp, "repo.git")
	env := append(hardenedEnv(tmp, spec.Credential), "GIT_INDEX_FILE="+filepath.Join(tmp, "index"))
	run := p.runner()
	git := func(step string, args ...string) (string, error) {
		out, stderr, err := run(ctx, env, append([]string{"-C", repo}, args...))
		if err != nil {
			return "", wrapGitErr(step, err, stderr, spec.Credential)
		}
		return strings.TrimSpace(out), nil
	}
	headRef := "refs/heads/" + spec.HeadBranch

	if _, stderr, err := run(ctx, env, []string{"init", "--bare", "-q", repo}); err != nil {
		return PushResult{}, wrapGitErr("init bare repo", err, stderr, spec.Credential)
	}
	headTip, err := remoteTip(git, spec.RemoteURL, headRef)
	if err != nil {
		return PushResult{}, err
	}
	parentRef, fetchStep := "refs/heads/"+spec.BaseBranch, "fetch base branch from remote"
	if headTip != "" {
		parentRef, fetchStep = headRef, "fetch head branch from remote"
	}
	if _, err := git(fetchStep, "fetch", "-q", "--depth=1", "--no-tags", spec.RemoteURL, parentRef); err != nil {
		return PushResult{}, err
	}
	parentSHA, err := git("resolve parent commit", "rev-parse", "--verify", "FETCH_HEAD^{commit}")
	if err != nil {
		return PushResult{}, err
	}
	parentDate, err := git("read parent commit date", "log", "-1", "--format=%ct", parentSHA)
	if err != nil {
		return PushResult{}, err
	}
	if _, err := git("read parent tree", "read-tree", parentSHA); err != nil {
		return PushResult{}, err
	}
	modes, err := existingModes(git, parentSHA, spec.Files)
	if err != nil {
		return PushResult{}, err
	}

	for i, f := range spec.Files {
		blobPath := filepath.Join(tmp, "blob-"+strconv.Itoa(i))
		if err := os.WriteFile(blobPath, []byte(f.Content), 0o600); err != nil {
			return PushResult{}, fmt.Errorf("submit: stage file content: %w", err)
		}
		blob, err := git("hash file content", "hash-object", "-w", "--no-filters", "--", blobPath)
		if err != nil {
			return PushResult{}, err
		}
		mode := "100644"
		if modes[f.Path] == "100755" {
			mode = "100755"
		}
		if _, err := git("stage "+strconv.Quote(f.Path), "update-index", "--add", "--cacheinfo", mode+","+blob+","+f.Path); err != nil {
			return PushResult{}, err
		}
	}
	tree, err := git("write tree", "write-tree")
	if err != nil {
		return PushResult{}, err
	}
	if headTip != "" {
		parentTree, err := git("read parent tree id", "rev-parse", "--verify", parentSHA+"^{tree}")
		if err != nil {
			return PushResult{}, err
		}
		if tree == parentTree {
			// The head branch already carries exactly these files (a
			// retry): no empty commit, nothing to push.
			return PushResult{Branch: spec.HeadBranch, SHA: parentSHA, BaseSHA: parentSHA}, nil
		}
	}

	date := "GIT_AUTHOR_DATE=@" + parentDate + " +0000"
	commitEnv := append(append([]string(nil), env...),
		"GIT_AUTHOR_NAME="+CommitAuthorName, "GIT_AUTHOR_EMAIL="+CommitAuthorEmail, date,
		"GIT_COMMITTER_NAME="+CommitAuthorName, "GIT_COMMITTER_EMAIL="+CommitAuthorEmail,
		"GIT_COMMITTER_DATE=@"+parentDate+" +0000",
	)
	out, stderr, err := run(ctx, commitEnv, []string{"-C", repo, "commit-tree", tree, "-p", parentSHA, "-m", spec.Message})
	if err != nil {
		return PushResult{}, wrapGitErr("create commit", err, stderr, spec.Credential)
	}
	commit := strings.TrimSpace(out)
	if commit == "" {
		// An empty source would turn the refspec below into a delete.
		return PushResult{}, fmt.Errorf("submit: create commit: git printed no commit id")
	}

	// Never forced: no --force flag and no "+" refspec, so the remote
	// accepts this only as a fast-forward of the tip it was built on.
	if _, pushErr := git("push to remote", "push", "-q", spec.RemoteURL, commit+":"+headRef); pushErr != nil {
		if now, err := remoteTip(git, spec.RemoteURL, headRef); err == nil && now != headTip {
			return PushResult{}, fmt.Errorf("%w: %q is now at %s, not the %s this commit was built on; refusing to force-push (retry to build on the new tip): %v",
				ErrHeadBranchMoved, spec.HeadBranch, describeTip(now), describeTip(headTip), pushErr)
		}
		return PushResult{}, pushErr
	}
	return PushResult{Branch: spec.HeadBranch, SHA: commit, BaseSHA: parentSHA}, nil
}

// remoteTip returns the commit ref points at on remote, or "" when the
// remote has no such ref.
func remoteTip(git func(string, ...string) (string, error), remote, ref string) (string, error) {
	out, err := git("look up head branch on remote", "ls-remote", remote, ref)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(out, "\n") {
		sha, name, ok := strings.Cut(strings.TrimSpace(line), "\t")
		if ok && name == ref && commitIDPattern.MatchString(sha) {
			return sha, nil
		}
	}
	return "", nil
}

func describeTip(sha string) string {
	if sha == "" {
		return "(no branch)"
	}
	return sha
}

// existingModes returns the base tree's mode for each file path that
// already exists there.
func existingModes(git func(string, ...string) (string, error), baseSHA string, files []ChangeFile) (map[string]string, error) {
	args := []string{"ls-tree", "-z", baseSHA, "--"}
	for _, f := range files {
		args = append(args, f.Path)
	}
	out, err := git("read existing file modes", args...)
	if err != nil {
		return nil, err
	}
	modes := map[string]string{}
	for _, entry := range strings.Split(out, "\x00") {
		// "<mode> <type> <sha>\t<path>"
		meta, path, ok := strings.Cut(entry, "\t")
		if !ok {
			continue
		}
		if fields := strings.Fields(meta); len(fields) == 3 {
			modes[path] = fields[0]
		}
	}
	return modes, nil
}
