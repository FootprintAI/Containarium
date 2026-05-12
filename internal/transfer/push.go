package transfer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// PushOptions extends Options with push-specific knobs.
type PushOptions struct {
	Options

	// Branch — git branch to push. Empty → uses current HEAD branch.
	Branch string

	// IncludeWIP — when set, uncommitted changes are auto-wrapped in a
	// WIP commit before pushing, then rewound after. Off by default,
	// matching the "git ideology" contract: commits ship, working tree
	// changes don't.
	IncludeWIP bool
}

// PushResult summarizes what was pushed.
type PushResult struct {
	Branch        string
	Commits       int    // number of commits in the bundle
	NewHead       string // sha pushed
	PreviousHead  string // sha that was on the remote before this push, or "" for first push
	BundleBytes   int64
	WIPCommitMade bool
}

// pushState is the per-(local-repo, remote-user) state file.
// Stored at .git/containarium-state.json in the local repo.
type pushState struct {
	Remotes map[string]map[string]string `json:"remotes"`
	// Remotes[<username>][<branch>] = last-pushed sha
}

// Push ships committed git history to the container. Uses `git bundle`
// for the wire format — git's pack-protocol-level delta compression
// without needing the bidirectional protocol working over our shell stack.
func Push(opt PushOptions) (*PushResult, error) {
	if err := opt.resolve(); err != nil {
		return nil, err
	}

	gitDir := filepath.Join(opt.LocalPath, ".git")
	if _, err := os.Stat(gitDir); err != nil {
		return nil, fmt.Errorf("local path %s is not a git repository (no .git directory): %w", opt.LocalPath, err)
	}

	// Resolve branch.
	branch := opt.Branch
	if branch == "" {
		out, err := runGit(opt.LocalPath, "rev-parse", "--abbrev-ref", "HEAD")
		if err != nil {
			return nil, fmt.Errorf("detect current branch: %w", err)
		}
		branch = strings.TrimSpace(out)
		if branch == "" || branch == "HEAD" {
			return nil, fmt.Errorf("detached HEAD; pass --branch")
		}
	}

	// Reject dirty working tree unless IncludeWIP is set.
	dirty, err := isWorkingTreeDirty(opt.LocalPath)
	if err != nil {
		return nil, fmt.Errorf("check working tree: %w", err)
	}
	wipCommitMade := false
	if dirty && !opt.IncludeWIP {
		return nil, fmt.Errorf("working tree has uncommitted changes; commit first, or pass --include-wip to auto-create a WIP commit")
	}
	var wipSha string
	if dirty && opt.IncludeWIP {
		sha, err := makeWIPCommit(opt.LocalPath)
		if err != nil {
			return nil, fmt.Errorf("make WIP commit: %w", err)
		}
		wipSha = sha
		wipCommitMade = true
		defer func() {
			// Rewind the WIP commit after the push so the local repo
			// stays clean. Files in the index/working tree are restored
			// via `git reset --mixed`.
			_, _ = runGit(opt.LocalPath, "reset", "--mixed", wipSha+"^")
		}()
	}

	// Load state — find the last sha we pushed for this (user, branch),
	// if any.
	state, _ := loadPushState(gitDir)
	previousHead := state.lastFor(opt.Username, branch)

	// Build the bundle.
	bundlePath := filepath.Join(os.TempDir(), fmt.Sprintf("containarium-push-%d.bundle", os.Getpid()))
	defer os.Remove(bundlePath) // #nosec G104 -- cleanup; not critical to error on.
	if err := buildBundle(opt.LocalPath, bundlePath, branch, previousHead); err != nil {
		return nil, fmt.Errorf("build bundle: %w", err)
	}

	bundleInfo, err := os.Stat(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("stat bundle: %w", err)
	}

	// Count commits in the bundle (everything reachable from <branch>
	// that's not reachable from <previousHead>).
	commitCount, err := countCommits(opt.LocalPath, previousHead, branch)
	if err != nil {
		return nil, fmt.Errorf("count commits: %w", err)
	}

	newHead, err := runGit(opt.LocalPath, "rev-parse", branch)
	if err != nil {
		return nil, fmt.Errorf("resolve new head: %w", err)
	}
	newHead = strings.TrimSpace(newHead)

	// Ship the bundle and apply it remotely.
	if err := shipBundle(opt, bundlePath, branch); err != nil {
		return nil, fmt.Errorf("ship bundle: %w", err)
	}

	// Update state file with the new head.
	state.setLast(opt.Username, branch, newHead)
	if err := state.save(gitDir); err != nil {
		// State is a best-effort hint; if we can't write it the next
		// push just re-bundles everything (still correct).
		fmt.Fprintf(os.Stderr, "[push] warning: could not write state file: %v\n", err)
	}

	return &PushResult{
		Branch:        branch,
		Commits:       commitCount,
		NewHead:       newHead,
		PreviousHead:  previousHead,
		BundleBytes:   bundleInfo.Size(),
		WIPCommitMade: wipCommitMade,
	}, nil
}

// buildBundle creates a git bundle at outPath covering either everything
// reachable from branch (if previousHead is empty) or the delta from
// previousHead..branch.
func buildBundle(repo, outPath, branch, previousHead string) error {
	args := []string{"bundle", "create", outPath}
	if previousHead == "" {
		args = append(args, "--all")
	} else {
		args = append(args, fmt.Sprintf("%s..%s", previousHead, branch), branch)
	}
	_, err := runGit(repo, args...)
	return err
}

// countCommits returns the number of commits between previousHead
// (exclusive) and branch (inclusive). When previousHead is empty, counts
// every commit reachable from branch.
func countCommits(repo, previousHead, branch string) (int, error) {
	args := []string{"rev-list", "--count"}
	if previousHead == "" {
		args = append(args, branch)
	} else {
		args = append(args, fmt.Sprintf("%s..%s", previousHead, branch))
	}
	out, err := runGit(repo, args...)
	if err != nil {
		return 0, err
	}
	var n int
	_, _ = fmt.Sscanf(strings.TrimSpace(out), "%d", &n)
	return n, nil
}

// shipBundle uploads the bundle file via stdin to the container and
// applies it: init-if-needed, fetch, update-ref, checkout.
func shipBundle(opt PushOptions, bundlePath, branch string) error {
	f, err := os.Open(bundlePath) // #nosec G304 -- bundlePath is constructed by us in TempDir.
	if err != nil {
		return err
	}
	defer f.Close()

	// Remote shell script:
	//   1. ensure repo dir + git repo (init if missing)
	//   2. receive bundle on stdin
	//   3. fetch into a temporary remote ref to avoid clobbering the
	//      working tree until the fetch succeeds
	//   4. fast-forward update-ref (allow non-ff with -f to mirror local)
	//   5. checkout the branch
	//   6. cleanup tmp bundle
	script := fmt.Sprintf(`
		set -e
		mkdir -p %s
		cd %s
		if [ ! -d .git ]; then
			git init -q -b %s
		fi
		BUNDLE=$(mktemp)
		trap 'rm -f "$BUNDLE"' EXIT
		cat > "$BUNDLE"
		git fetch -q "$BUNDLE" %s
		git update-ref -f refs/heads/%s FETCH_HEAD
		git checkout -f -q %s
	`,
		shQuote(opt.RemotePath),
		shQuote(opt.RemotePath),
		shQuote(branch),
		shQuote(branch),
		shQuote(branch),
		shQuote(branch),
	)

	args := append(opt.sshBaseArgs(), opt.sshTarget(), script)
	// #nosec G204 -- argv to ssh, not shell-evaluated locally; remote
	// script's variables are shQuote'd.
	cmd := exec.Command("ssh", args...)
	cmd.Stdin = f
	cmd.Stderr = io.Discard
	if opt.Verbose {
		cmd.Stderr = os.Stderr
	}
	return cmd.Run()
}

// isWorkingTreeDirty returns true if there are uncommitted/unstaged
// changes or untracked files.
func isWorkingTreeDirty(repo string) (bool, error) {
	out, err := runGit(repo, "status", "--porcelain")
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(out) != "", nil
}

// makeWIPCommit stages everything (including untracked) and commits.
// Returns the new commit's sha.
func makeWIPCommit(repo string) (string, error) {
	if _, err := runGit(repo, "add", "-A"); err != nil {
		return "", fmt.Errorf("git add -A: %w", err)
	}
	if _, err := runGit(repo, "commit", "-q", "--allow-empty", "-m", "WIP: containarium push --include-wip"); err != nil {
		return "", fmt.Errorf("git commit: %w", err)
	}
	out, err := runGit(repo, "rev-parse", "HEAD")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// runGit runs a git command in repo and returns combined stdout (caller
// trims). Errors include stderr for easier debugging.
func runGit(repo string, args ...string) (string, error) {
	// args are package-internal git subcommands + values pre-validated
	// elsewhere in this file (branch name from git rev-parse, bundle path
	// from os.TempDir). git treats each argv element as one argument, not
	// shell-evaluated.
	cmd := exec.Command("git", args...) // #nosec G204 -- argv to git, not shell-evaluated.
	cmd.Dir = repo
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// --- pushState persistence -------------------------------------------------

const stateFile = "containarium-state.json"

func loadPushState(gitDir string) (*pushState, error) {
	st := &pushState{Remotes: map[string]map[string]string{}}
	path := filepath.Join(gitDir, stateFile)
	data, err := os.ReadFile(path) // #nosec G304 -- path is constructed from caller-supplied gitDir + a constant filename.
	if err != nil {
		return st, nil // missing file = empty state
	}
	if err := json.Unmarshal(data, st); err != nil {
		return st, nil // unparsable = treat as empty
	}
	if st.Remotes == nil {
		st.Remotes = map[string]map[string]string{}
	}
	return st, nil
}

func (s *pushState) lastFor(user, branch string) string {
	if s.Remotes[user] == nil {
		return ""
	}
	return s.Remotes[user][branch]
}

func (s *pushState) setLast(user, branch, sha string) {
	if s.Remotes[user] == nil {
		s.Remotes[user] = map[string]string{}
	}
	s.Remotes[user][branch] = sha
}

func (s *pushState) save(gitDir string) error {
	path := filepath.Join(gitDir, stateFile)
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
