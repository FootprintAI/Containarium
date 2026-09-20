package submit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// PushSpec is GitPusher.PushBundle's input.
//
// There is deliberately no raw branch-name field: Title only ever
// contributes a cosmetic slug through BranchName (see branch.go), so
// nothing that constructs a PushSpec from request data has a way to
// make the agent's push land on an arbitrary ref. RemoteURL and
// Credential must be built from the tracker connection record — never
// from the bundle or anything the box reported — so a hostile
// workspace has no path to redirect either one.
type PushSpec struct {
	// BundlePath is a git bundle file already on the host filesystem
	// (pulled out of the box and size/shape-validated by the caller —
	// see #1923 build-order step 8b). PushBundle does not re-validate
	// it beyond what git itself checks while applying it.
	BundlePath string
	// BaseSHA is the run's recorded base commit (git_source's resolved
	// commit) — the bundle's prerequisite. PushBundle fetches it from
	// RemoteURL first so the bare repo it builds can satisfy the
	// bundle's prerequisite and `git bundle verify` is a real fsck
	// check rather than an automatic "prerequisite missing" failure.
	BaseSHA string
	// HeadSHA is the commit the pushed branch should point at — the
	// workspace's HEAD at bundle-creation time.
	HeadSHA string
	// RemoteURL is the tracker connection's project URL. Built by the
	// caller from the connection record; PushBundle trusts it as-is.
	RemoteURL string
	// Credential is supplied to git as an http.extraHeader through
	// process environment only (GIT_CONFIG_COUNT/KEY_N/VALUE_N) — never
	// argv — so it is absent from the host process table. See
	// TestGitPusher_EnvAndArgv.
	Credential string
	// RunID, IssueNumber, and Title feed BranchName. See PushSpec's own
	// doc comment above for why there is no separate branch field.
	RunID       string
	IssueNumber int64
	Title       string
}

// PushResult is what a successful PushBundle produced.
type PushResult struct {
	Branch string
	SHA    string
}

// GitPusher pushes a bundle's commits to a daemon-chosen branch on the
// connection's remote, without ever giving the box (or the bundle's
// origin repository) an opportunity to run with a credential present.
// The one implementation, ExecGitPusher, shells out to host git — see
// docs/architecture/agent-tracker-broker.md decision D2 for why (no
// maintained pure-Go bundle reader exists).
type GitPusher interface {
	PushBundle(ctx context.Context, spec PushSpec) (PushResult, error)
}

// gitRunFunc runs one git invocation with dir as its working directory
// (via `-C`, so dir may be "" for commands that take an explicit path
// argument instead, like `git init --bare <path>`) and env as the
// child's COMPLETE environment — never appended to os.Environ(). That
// is the hardening's whole point: the child sees exactly the variables
// this package decided to give it, not whatever the daemon process
// happens to be carrying. realGitRun is the production implementation;
// tests substitute a fake that records the call instead of executing
// anything.
type gitRunFunc func(ctx context.Context, env []string, args []string) (stdout, stderr string, err error)

// ExecGitPusher is GitPusher's production implementation. The zero
// value is usable; run is nil-checked at call time so a test can
// construct &ExecGitPusher{run: fake} directly without a constructor.
type ExecGitPusher struct {
	run gitRunFunc
}

// NewGitPusher returns an ExecGitPusher that shells out to the host's
// real git binary.
func NewGitPusher() *ExecGitPusher {
	return &ExecGitPusher{}
}

func (p *ExecGitPusher) runner() gitRunFunc {
	if p.run != nil {
		return p.run
	}
	return realGitRun
}

// ErrEmptyBundle is returned when spec.HeadSHA or spec.BaseSHA is
// empty — PushBundle refuses to guess either, since a wrong base or
// head would silently push the wrong commit range.
var ErrEmptyBundle = errors.New("submit: bundle spec is missing a required commit sha")

// PushBundle implements the hardened push described in
// docs/architecture/agent-tracker-broker.md's "Submit path" section:
//
//  1. A fresh temporary bare repository — no hooks, no inherited user
//     or system git config, transfer.fsckObjects=true.
//  2. Fetch spec.BaseSHA from spec.RemoteURL, authenticated with
//     spec.Credential. This is the one unavoidable network call before
//     the bundle is trusted: it satisfies the bundle's prerequisite
//     (git bundle create <base>..HEAD records base as a prerequisite,
//     not as bundled object data) so the verify step below is a real
//     fsck check against a repository that can actually resolve it,
//     not an automatic "prerequisite missing" failure against an empty
//     repo. Bundle shape/size validation that does NOT need the
//     prerequisite (malformed file, zero new commits, over the size
//     cap) happens earlier, in the box-extraction step, strictly
//     before this method is ever called.
//  3. `git bundle verify` against the now-populated repo.
//  4. `git fetch` the bundle itself, landing spec.HeadSHA's object
//     graph in the bare repo.
//  5. `git push` spec.HeadSHA to the daemon-chosen branch (BranchName)
//     on spec.RemoteURL — never --force, so a run can update only its
//     own branch namespace and never overwrite unrelated history.
//
// The temporary directory is removed on every exit path, success or
// failure (TestTmpdir_RemovedOnEveryPath).
func (p *ExecGitPusher) PushBundle(ctx context.Context, spec PushSpec) (PushResult, error) {
	if spec.BaseSHA == "" || spec.HeadSHA == "" {
		return PushResult{}, ErrEmptyBundle
	}

	tmp, err := os.MkdirTemp("", "containarium-submit-*")
	if err != nil {
		return PushResult{}, fmt.Errorf("submit: create temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	env := hardenedEnv(tmp, spec.Credential)
	run := p.runner()

	if _, stderr, err := run(ctx, env, []string{"init", "--bare", "-q", tmp}); err != nil {
		return PushResult{}, wrapGitErr("init bare repo", err, stderr, spec.Credential)
	}

	if _, stderr, err := run(ctx, env, []string{"-C", tmp, "fetch", spec.RemoteURL, spec.BaseSHA}); err != nil {
		return PushResult{}, wrapGitErr("fetch base commit from remote", err, stderr, spec.Credential)
	}

	if _, stderr, err := run(ctx, env, []string{"-C", tmp, "bundle", "verify", spec.BundlePath}); err != nil {
		return PushResult{}, wrapGitErr("verify bundle", err, stderr, spec.Credential)
	}

	if _, stderr, err := run(ctx, env, []string{"-C", tmp, "fetch", spec.BundlePath, spec.HeadSHA}); err != nil {
		return PushResult{}, wrapGitErr("fetch bundle", err, stderr, spec.Credential)
	}

	branch := BranchName(spec.RunID, spec.IssueNumber, spec.Title)
	refspec := spec.HeadSHA + ":refs/heads/" + branch
	if _, stderr, err := run(ctx, env, []string{"-C", tmp, "push", spec.RemoteURL, refspec}); err != nil {
		return PushResult{}, wrapGitErr("push to remote", err, stderr, spec.Credential)
	}

	return PushResult{Branch: branch, SHA: spec.HeadSHA}, nil
}

// hardenedEnv builds the COMPLETE environment for every git invocation
// this package makes. PATH is carried over from the daemon process so
// exec.Command can still locate helper binaries git may shell out to;
// everything else is deliberately explicit rather than inherited.
//
// All three of core.hooksPath, transfer.fsckObjects, and the
// credential's http.extraHeader are delivered the same way — through
// GIT_CONFIG_COUNT/GIT_CONFIG_KEY_N/GIT_CONFIG_VALUE_N (git >= 2.31,
// hence the host-git preflight) — rather than mixing environment
// variables with `-c` argv flags. One delivery mechanism for every
// override keeps TestGitPusher_EnvAndArgv's "credential absent from
// argv" assertion simple to state as "argv never contains -c or the
// credential substring at all", not "argv contains -c flags but never
// this specific one".
func hardenedEnv(home, credential string) []string {
	env := []string{
		"HOME=" + home,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_COUNT=3",
		"GIT_CONFIG_KEY_0=core.hooksPath",
		"GIT_CONFIG_VALUE_0=/dev/null",
		"GIT_CONFIG_KEY_1=transfer.fsckObjects",
		"GIT_CONFIG_VALUE_1=true",
		"GIT_CONFIG_KEY_2=http.extraHeader",
		// Same header shape as pkg/core/container/git_source.go's
		// buildGitFetchScript, for one consistent credential-injection
		// convention across the box-side fetch and the host-side push.
		"GIT_CONFIG_VALUE_2=AUTHORIZATION: bearer " + credential,
	}
	if path, ok := os.LookupEnv("PATH"); ok {
		env = append(env, "PATH="+path)
	}
	return env
}

// wrapGitErr folds a failed step's context and stderr into one error,
// redacting the credential from stderr first — git does not normally
// echo a header value back on failure, but nothing here relies on that
// being true forever, and the redaction costs nothing when the
// substring isn't present.
func wrapGitErr(step string, err error, stderr, credential string) error {
	msg := strings.TrimSpace(stderr)
	if credential != "" {
		msg = strings.ReplaceAll(msg, credential, "[redacted]")
	}
	if msg == "" {
		return fmt.Errorf("submit: %s: %w", step, err)
	}
	return fmt.Errorf("submit: %s: %w: %s", step, err, msg)
}

// realGitRun is gitRunFunc's production implementation: exec.Command
// with an explicit, complete Env (never os.Environ()+append) and no
// Dir (every caller passes an absolute path or `-C <path>` in args
// instead, so there is no ambient working directory for a hostile
// repo's config to matter even if one somehow applied).
func realGitRun(ctx context.Context, env []string, args []string) (stdout, stderr string, err error) {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		return "", "", fmt.Errorf("submit: git not found on PATH: %w", err)
	}
	// #nosec G204 -- argv is package-built from validated fields
	// (temp dir paths this function created, a caller-supplied remote
	// URL/sha treated as opaque git arguments, never shell-evaluated).
	cmd := exec.CommandContext(ctx, gitPath, args...)
	cmd.Env = env
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err = cmd.Run()
	return outBuf.String(), errBuf.String(), err
}

// GitVersionAtLeast reports whether versionOutput (the trimmed stdout
// of `git version`) names a version >= major.minor. Used by the host
// git preflight (#1923 build-order step 8, "Host git is a preflight");
// a separate, tiny parser rather than a general semver library because
// git's own version string format ("git version 2.43.0") is the only
// input it ever needs to handle.
func GitVersionAtLeast(versionOutput string, major, minor int) bool {
	fields := strings.Fields(versionOutput)
	for _, f := range fields {
		parts := strings.SplitN(f, ".", 3)
		if len(parts) < 2 {
			continue
		}
		gotMajor, err1 := parseLeadingInt(parts[0])
		gotMinor, err2 := parseLeadingInt(parts[1])
		if err1 != nil || err2 != nil {
			continue
		}
		if gotMajor != major {
			return gotMajor > major
		}
		return gotMinor >= minor
	}
	return false
}

func parseLeadingInt(s string) (int, error) {
	n := 0
	found := false
	for _, r := range s {
		if r < '0' || r > '9' {
			break
		}
		n = n*10 + int(r-'0')
		found = true
	}
	if !found {
		return 0, fmt.Errorf("submit: no leading digits in %q", s)
	}
	return n, nil
}
