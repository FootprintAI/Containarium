package transfer

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
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

	// DeployCmd — when set, the container-side post-receive hook
	// embeds this shell command and runs it (inside the container's
	// work tree directory) after each successful push. Use it to
	// restart the service, run migrations, rebuild artifacts, etc.
	// Empty deploys the source but runs no command — operator can
	// run anything manually via ssh.
	DeployCmd string

	// RemoteName — the local git remote name to (re)configure. Default
	// "containarium-<username>" so multiple containers can be pushed
	// to from the same local clone without colliding.
	RemoteName string
}

// PushResult summarizes the push.
type PushResult struct {
	Branch        string
	NewHead       string // sha now at the remote tip
	PreviousHead  string // sha that was at remote tip before this push; "" on first push
	RemoteURL     string // ssh-style URL we pushed to, for the caller's records
	WIPCommitMade bool
	SetupRan      bool   // true if we provisioned/refreshed the bare repo + hook this call
	DeployCmd     string // echoed back so callers can audit
}

// Push ships committed git history to the container by running
// `git push` against a container-hosted bare repo. The container side
// installs a post-receive hook on first call (and rewrites it any time
// DeployCmd changes) that checks out the working tree and optionally
// runs DeployCmd.
//
// Why real git push and not a bundle: receive-pack works through our
// SSH stack (sshpiper -> sshd -> containarium-shell -> su -c -> incus
// exec) — empirically verified before this PR. Real git push gives the
// agent + any vanilla git client the same single mechanism, and it
// includes a post-receive hook execution surface for free.
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

	// Working-tree-dirty handling.
	dirty, err := isWorkingTreeDirty(opt.LocalPath)
	if err != nil {
		return nil, fmt.Errorf("check working tree: %w", err)
	}
	wipCommitMade := false
	var wipSha string
	if dirty && !opt.IncludeWIP {
		return nil, fmt.Errorf("working tree has uncommitted changes; commit first, or pass --include-wip to auto-create a WIP commit")
	}
	if dirty && opt.IncludeWIP {
		sha, err := makeWIPCommit(opt.LocalPath)
		if err != nil {
			return nil, fmt.Errorf("make WIP commit: %w", err)
		}
		wipSha = sha
		wipCommitMade = true
		defer func() {
			// Rewind the WIP commit so the local repo stays clean. Files
			// in the index/working tree are restored via `git reset
			// --mixed`.
			_, _ = runGit(opt.LocalPath, "reset", "--mixed", wipSha+"^")
		}()
	}

	// Provision (or refresh) the bare repo + post-receive hook on the
	// container. Idempotent: re-running with the same DeployCmd is a
	// no-op aside from rewriting the hook (cheap).
	if err := ensureRemoteSetup(opt, branch); err != nil {
		return nil, fmt.Errorf("remote setup: %w", err)
	}

	// Configure local git remote so subsequent ad-hoc `git push
	// containarium-<user>` from the same clone works without involving
	// the CLI.
	remoteName := opt.RemoteName
	if remoteName == "" {
		remoteName = "containarium-" + opt.Username
	}
	remoteURL := remoteRepoSSHURL(opt)
	if err := ensureLocalRemote(opt.LocalPath, remoteName, remoteURL); err != nil {
		return nil, fmt.Errorf("configure local remote: %w", err)
	}

	// Capture the remote branch's current sha (if any) BEFORE the push,
	// so we can report previousHead → newHead.
	previousHead, _ := remoteHead(opt, branch)

	// Actually push. Use GIT_SSH_COMMAND so git inherits our key +
	// IdentitiesOnly + no-strict-host-key options. Without
	// IdentitiesOnly, every key in ~/.ssh/ gets offered to sshpiper's
	// failtoban — see PR #132 for the original symptom.
	if err := gitPush(opt, remoteName, branch); err != nil {
		return nil, fmt.Errorf("git push: %w", err)
	}

	// Capture new head.
	newHead, err := runGit(opt.LocalPath, "rev-parse", branch)
	if err != nil {
		return nil, fmt.Errorf("resolve new head: %w", err)
	}

	return &PushResult{
		Branch:        branch,
		NewHead:       strings.TrimSpace(newHead),
		PreviousHead:  previousHead,
		RemoteURL:     remoteURL,
		WIPCommitMade: wipCommitMade,
		SetupRan:      true,
		DeployCmd:     opt.DeployCmd,
	}, nil
}

// remoteRepoSSHURL builds the ssh-style remote URL git push consumes.
// Convention: bare repo lives at "<RemotePath>.git" inside the
// container's home dir; the work tree is at "<RemotePath>" (the hook
// checks out into it).
func remoteRepoSSHURL(opt PushOptions) string {
	// git accepts <user>@<host>:<path-relative-to-home>. So we strip a
	// leading $HOME/ if the caller wrote an absolute path.
	bare := strings.TrimPrefix(opt.RemotePath, "/home/"+opt.Username+"/")
	bare = strings.TrimPrefix(bare, "~/")
	if strings.HasPrefix(bare, "/") {
		// Absolute path that's not under the user's home — pass through
		// as-is.
		return fmt.Sprintf("%s@%s:%s.git", opt.Username, opt.SentinelHost, bare)
	}
	return fmt.Sprintf("%s@%s:%s.git", opt.Username, opt.SentinelHost, bare)
}

// hookData feeds the post-receive template.
type hookData struct {
	Branch    string
	BareRepo  string
	WorkTree  string
	DeployCmd string
}

const hookTemplate = `#!/bin/sh
set -e
while read oldrev newrev refname; do
    branch="${refname#refs/heads/}"
    if [ "$branch" = "{{.Branch}}" ]; then
        echo "[containarium] post-receive: $branch $oldrev..$newrev" >&2
        GIT_WORK_TREE={{.WorkTree}} git --git-dir={{.BareRepo}} checkout -f "$branch"
{{- if .DeployCmd}}
        cd {{.WorkTree}}
        {{.DeployCmd}}
{{- end}}
    fi
done
`

// renderHook produces the post-receive hook body for the given options.
// Split out for testability.
func renderHook(d hookData) (string, error) {
	t, err := template.New("hook").Parse(hookTemplate)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, d); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// ensureRemoteSetup creates the bare repo + post-receive hook + work
// tree directory on the container if missing, and refreshes the hook
// to reflect the current DeployCmd. Idempotent.
//
// One SSH connection per push for setup. The actual `git push` opens
// its own SSH connection; we could share if we cared about latency,
// but ~200ms once per push is fine for v1.
func ensureRemoteSetup(opt PushOptions, branch string) error {
	bareRepo := opt.RemotePath + ".git"
	workTree := opt.RemotePath
	hook, err := renderHook(hookData{
		Branch:    branch,
		BareRepo:  bareRepo,
		WorkTree:  workTree,
		DeployCmd: opt.DeployCmd,
	})
	if err != nil {
		return fmt.Errorf("render hook: %w", err)
	}

	// Two-phase shell script: ensure repo + write hook from stdin.
	// stdin is the hook content; the remote script reads it and chmods.
	script := fmt.Sprintf(`
set -e
which git >/dev/null 2>&1 || { sudo apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq git >/dev/null 2>&1; }
mkdir -p %s
if [ ! -f %s/HEAD ]; then
    git init --bare -q %s
fi
mkdir -p %s
cat > %s/hooks/post-receive
chmod +x %s/hooks/post-receive
`,
		shQuote(bareRepo),
		shQuote(bareRepo),
		shQuote(bareRepo),
		shQuote(workTree),
		shQuote(bareRepo),
		shQuote(bareRepo),
	)

	args := append(opt.sshBaseArgs(), opt.sshTarget(), script)
	// #nosec G204 -- argv to ssh, not shell-evaluated locally; embedded
	// paths are shQuote'd. Hook content is package-controlled + a
	// caller-supplied DeployCmd that goes directly into the user's
	// container, not into our local shell.
	cmd := exec.Command("ssh", args...)
	cmd.Stdin = strings.NewReader(hook)
	cmd.Stderr = io.Discard
	if opt.Verbose {
		cmd.Stderr = os.Stderr
	}
	return cmd.Run()
}

// ensureLocalRemote sets remote.<name>.url to url, creating the remote
// or updating its URL as needed.
func ensureLocalRemote(repo, name, url string) error {
	existing, err := runGit(repo, "remote", "get-url", name)
	switch {
	case err == nil:
		if strings.TrimSpace(existing) == url {
			return nil
		}
		_, err = runGit(repo, "remote", "set-url", name, url)
		return err
	default:
		_, err = runGit(repo, "remote", "add", name, url)
		return err
	}
}

// remoteHead asks the remote what sha its <branch> currently points at.
// Empty string when the branch doesn't exist yet (first push) or the
// remote isn't reachable. Best-effort — failure here doesn't abort the
// push.
func remoteHead(opt PushOptions, branch string) (string, error) {
	env := append(os.Environ(), "GIT_SSH_COMMAND="+gitSSHCommand(opt))
	cmd := exec.Command("git", "ls-remote", remoteRepoSSHURL(opt), "refs/heads/"+branch) // #nosec G204 -- argv to git; URL built from validated config.
	cmd.Env = env
	cmd.Dir = opt.LocalPath
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(out))
	if len(fields) < 1 {
		return "", nil
	}
	return fields[0], nil
}

// gitPush runs `git push <remote> <branch>` with GIT_SSH_COMMAND set to
// pin our key + IdentitiesOnly + no strict host key checking. Stderr
// is captured so a failed push surfaces a helpful error.
func gitPush(opt PushOptions, remoteName, branch string) error {
	env := append(os.Environ(), "GIT_SSH_COMMAND="+gitSSHCommand(opt))
	cmd := exec.Command("git", "push", remoteName, branch) // #nosec G204 -- argv to git; remoteName + branch are package-validated.
	cmd.Env = env
	cmd.Dir = opt.LocalPath
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if opt.Verbose {
		cmd.Stderr = io.MultiWriter(&stderr, os.Stderr)
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w (stderr: %s)", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// gitSSHCommand returns a GIT_SSH_COMMAND value that pins our key + the
// IdentitiesOnly flag. The same options sshBaseArgs uses, but compacted
// into one space-separated string for env-var use.
func gitSSHCommand(opt PushOptions) string {
	parts := append([]string{"ssh"}, opt.sshBaseArgs()...)
	return strings.Join(parts, " ")
}

// isWorkingTreeDirty / makeWIPCommit / runGit are unchanged from the
// pre-rewrite version.

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
	// elsewhere in this file. git treats each argv element as one
	// argument, not shell-evaluated.
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
