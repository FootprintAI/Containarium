package submit

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// DefaultMaxBundleBytes bounds how large a bundle ExtractBundle will
// pull out of a box, per the design note's "size-capped, default
// 50 MiB". A run that produces more than this in new commits is almost
// certainly not what SubmitTrackerChange is for (binary assets,
// vendored dependencies committed by mistake, or a runaway agent).
const DefaultMaxBundleBytes = 50 * 1024 * 1024

var (
	// ErrBundleTooLarge is returned when the box reports a bundle file
	// larger than the caller's cap. ExtractBundle checks this via an
	// in-box `stat`/`wc -c` BEFORE pulling the file out, so an
	// oversized bundle costs one exec round trip, not a multi-MB
	// transfer that gets thrown away.
	ErrBundleTooLarge = errors.New("submit: bundle exceeds the configured size limit")
	// ErrBundleMalformed is returned when the bytes read back from the
	// box do not parse as a bundle (`git bundle list-heads` fails or
	// reports no heads). `git bundle create` in the box already
	// refuses to produce an empty bundle for an empty commit range —
	// this check exists for the box-to-daemon leg of the journey, not
	// for the box's own git catching a bad range.
	ErrBundleMalformed = errors.New("submit: bundle is malformed or contains no commits")
)

// BoxRunner is the narrow slice of *container.Manager's API
// ExtractBundle needs — one exec, one file read — so this package
// depends on no wider box-management surface and its tests need no
// real box. *container.Manager already satisfies this.
type BoxRunner interface {
	ExecWithOutput(containerName string, command []string) (stdout, stderr string, err error)
	ReadFile(containerName, path string) ([]byte, error)
}

// BundleResult is what a successful ExtractBundle produced: a bundle
// file already on the HOST filesystem (mode 0600, caller's
// responsibility to remove — GitPusher.PushBundle's caller does this
// the same way it cleans up its own temp dir) and the commit the
// bundle's HEAD ref resolves to.
type BundleResult struct {
	BundlePath string
	HeadSHA    string
}

// remoteBundlePath is the well-known in-box path ExtractBundle asks
// the workspace's own git to write the bundle to. A fixed name is
// fine: only one submit runs against a given workspace at a time (the
// run that owns it), and the file is removed from the box after being
// pulled out.
const remoteBundlePath = "/tmp/containarium-submit-out.bundle"

// shellSingleQuote wraps s in single quotes for safe interpolation
// into a /bin/sh -c script. Same technique as
// pkg/core/container/git_source.go's own helper of the same name;
// duplicated rather than imported because internal/tracker/submit must
// not depend on pkg/core/container (see BoxRunner's doc comment) — the
// wiring that lets *container.Manager satisfy BoxRunner lives in
// internal/server, not here.
func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// ExtractBundle execs `git bundle create` inside the box for the
// workspace's HEAD against baseCommit, checks the resulting file's
// size in-box before pulling it out, and rejects a malformed transfer
// — all before any upstream (tracker or provider) call is made.
//
// The bundle range is built as "<baseCommit>..HEAD" using the literal
// ref HEAD, not a resolved sha: `git bundle create` refuses to create
// an empty bundle for a raw sha..sha range even when the underlying
// commit range is non-empty, because it then has no ref to advertise
// (found writing PR #1951's integration test). Using HEAD gives it one.
//
// A bundle whose range is genuinely empty (baseCommit == HEAD, no new
// commits) makes the box's own `git bundle create` fail with "Refusing
// to create empty bundle" — that failure surfaces here as a wrapped
// error, satisfying the "no new commits" rejection without a separate
// check. Deep fsck validation of the bundle's object graph happens
// later, in GitPusher.PushBundle's `git bundle verify` step, which (see
// that package's own doc comment) needs the base commit fetched from
// the real remote first — something this function, running before any
// upstream call, must not do.
func ExtractBundle(box BoxRunner, container, workspace, baseCommit string, maxBytes int64) (BundleResult, error) {
	script := strings.Join([]string{
		"set -e",
		"cd " + shellSingleQuote(workspace),
		"git bundle create " + shellSingleQuote(remoteBundlePath) + " " + shellSingleQuote(baseCommit+"..HEAD"),
		"git rev-parse HEAD",
	}, "\n")

	stdout, stderr, err := box.ExecWithOutput(container, []string{"/bin/sh", "-c", script})
	if err != nil {
		msg := strings.TrimSpace(stderr)
		if msg == "" {
			msg = strings.TrimSpace(stdout)
		}
		return BundleResult{}, fmt.Errorf("submit: create bundle in box: %w: %s", err, msg)
	}
	headSHA := lastNonEmptyLine(stdout)

	sizeScript := "stat -c %s " + shellSingleQuote(remoteBundlePath) +
		" 2>/dev/null || wc -c < " + shellSingleQuote(remoteBundlePath)
	sizeOut, sizeErr, err := box.ExecWithOutput(container, []string{"/bin/sh", "-c", sizeScript})
	if err != nil {
		msg := strings.TrimSpace(sizeErr)
		return BundleResult{}, fmt.Errorf("submit: stat bundle in box: %w: %s", err, msg)
	}
	size, parseErr := strconv.ParseInt(strings.TrimSpace(lastNonEmptyLine(sizeOut)), 10, 64)
	if parseErr != nil {
		return BundleResult{}, fmt.Errorf("submit: could not parse bundle size %q: %w", sizeOut, parseErr)
	}
	if size > maxBytes {
		return BundleResult{}, fmt.Errorf("%w: %d bytes > %d byte limit", ErrBundleTooLarge, size, maxBytes)
	}

	content, err := box.ReadFile(container, remoteBundlePath)
	if err != nil {
		return BundleResult{}, fmt.Errorf("submit: read bundle out of box: %w", err)
	}

	// os.CreateTemp creates the file with mode 0600 already — no
	// separate chmod needed, and no window where a wider mode was ever
	// on disk.
	f, err := os.CreateTemp("", "containarium-submit-*.bundle")
	if err != nil {
		return BundleResult{}, fmt.Errorf("submit: create host bundle file: %w", err)
	}
	path := f.Name()
	if _, err := f.Write(content); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return BundleResult{}, fmt.Errorf("submit: write host bundle file: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return BundleResult{}, fmt.Errorf("submit: close host bundle file: %w", err)
	}

	if err := verifyBundleShape(path); err != nil {
		_ = os.Remove(path)
		return BundleResult{}, err
	}

	return BundleResult{BundlePath: path, HeadSHA: headSHA}, nil
}

// lastNonEmptyLine returns the trailing non-blank line of s, trimmed.
// Same technique as pkg/core/container/git_source.go's helper of the
// same name (duplicated, not imported — see shellSingleQuote's doc
// comment for why): the exec script's last line is always the value
// this function is pulling out, regardless of what git printed before
// it (bundle creation is chatty when it's writing a big pack).
func lastNonEmptyLine(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if line := strings.TrimSpace(lines[i]); line != "" {
			return line
		}
	}
	return ""
}

// verifyBundleShape confirms path parses as a bundle and advertises at
// least one head, WITHOUT needing any prerequisite object present —
// `git bundle list-heads` only reads the bundle's own text header, so
// it works standalone the way `git bundle verify` (which additionally
// checks the current repository has the prerequisites) cannot.
func verifyBundleShape(path string) error {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		return fmt.Errorf("submit: git not found on PATH: %w", err)
	}
	// #nosec G204 -- argv is git + a fixed subcommand + a host tempfile
	// path this function created; not shell-evaluated.
	cmd := exec.Command(gitPath, "bundle", "list-heads", path)
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBundleMalformed, err)
	}
	if strings.TrimSpace(string(out)) == "" {
		return ErrBundleMalformed
	}
	return nil
}
