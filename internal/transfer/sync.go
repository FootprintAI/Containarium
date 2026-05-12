package transfer

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// SyncOptions extends Options with sync-specific knobs.
type SyncOptions struct {
	Options

	// Delete: when true, remove files on the remote that no longer
	// exist locally. Off by default — additive sync is safer for a v1.
	Delete bool

	// Excludes: substring patterns to skip during the local walk. Sensible
	// defaults for common build/cache directories are applied if empty.
	Excludes []string
}

// DefaultSyncExcludes is the noise filter applied when SyncOptions.Excludes
// is empty. Substring match, not glob.
var DefaultSyncExcludes = []string{
	"node_modules/",
	".terraform/",
	"__pycache__/",
	".pytest_cache/",
	".venv/",
	"venv/",
	".DS_Store",
	".idea/",
	".vscode/",
}

// SyncResult summarizes what changed.
type SyncResult struct {
	Added    int
	Modified int
	Deleted  int
	Bytes    int64
}

// Sync mirrors LocalPath to RemotePath, shipping only files whose
// sha256+mode differs. Includes .git/ by design (so committed history,
// branches, stashes carry over). Symlinks and special files are skipped.
//
// On first call (empty remote), every file is shipped. On subsequent
// calls, only the delta.
func Sync(opt SyncOptions) (*SyncResult, error) {
	if err := opt.resolve(); err != nil {
		return nil, err
	}
	if len(opt.Excludes) == 0 {
		opt.Excludes = DefaultSyncExcludes
	}

	// 1. Build local manifest.
	if opt.Verbose {
		fmt.Fprintf(os.Stderr, "[sync] hashing %s ...\n", opt.LocalPath)
	}
	local, err := walkLocal(opt.LocalPath, opt.Excludes)
	if err != nil {
		return nil, fmt.Errorf("walk local: %w", err)
	}

	// 2. Read remote manifest. The remote script tolerates a missing
	// RemotePath by creating it.
	if opt.Verbose {
		fmt.Fprintf(os.Stderr, "[sync] reading remote manifest at %s ...\n", opt.RemotePath)
	}
	remote, err := readRemoteManifest(opt)
	if err != nil {
		return nil, fmt.Errorf("read remote manifest: %w", err)
	}

	// 3. Diff.
	d := local.diff(remote)

	// Empty diff (and not asked to --delete extras) → nothing to do.
	if len(d.ToAddOrModify) == 0 && (!opt.Delete || len(d.ToDelete) == 0) {
		if opt.Verbose {
			fmt.Fprintln(os.Stderr, "[sync] no changes")
		}
		return &SyncResult{}, nil
	}

	// 4. Build a tar of just the changed files (add + modify).
	var tarOut int64
	var tarbuf bytes.Buffer
	if len(d.ToAddOrModify) > 0 {
		if opt.Verbose {
			fmt.Fprintf(os.Stderr, "[sync] packing %d changed file(s) ...\n", len(d.ToAddOrModify))
		}
		var err error
		tarOut, err = buildChangedTar(opt.LocalPath, d.ToAddOrModify, &tarbuf)
		if err != nil {
			return nil, fmt.Errorf("build tar: %w", err)
		}
	}

	// 5. Ship via one-shot ssh-with-command. The remote shell receives
	// the tar on stdin (when there are files), extracts it, and removes
	// any files that should be deleted.
	deleteCmd := ""
	if opt.Delete && len(d.ToDelete) > 0 {
		// rm -f one path per line, no globbing. shell-quote each path.
		// Embedded in the heredoc as a here-string to avoid command-line
		// length limits.
		var b strings.Builder
		b.WriteString("while IFS= read -r p; do rm -f -- \"$p\"; done <<'__DEL__'\n")
		for _, p := range d.ToDelete {
			b.WriteString(p)
			b.WriteString("\n")
		}
		b.WriteString("__DEL__\n")
		deleteCmd = b.String()
	}

	remoteScript := fmt.Sprintf(`
		set -e
		mkdir -p %s
		cd %s
		%s
		%s
	`,
		shQuote(opt.RemotePath),
		shQuote(opt.RemotePath),
		conditional(len(d.ToAddOrModify) > 0, "tar xzf - 2>/dev/null"),
		deleteCmd,
	)

	args := append(opt.sshBaseArgs(), opt.sshTarget(), remoteScript)
	// args is built from package-internal values + caller-supplied paths
	// that pass through shQuote, then handed to ssh as argv (not shell-
	// evaluated locally). Username/host appear only as one argv element
	// to ssh. Safe by construction.
	cmd := exec.Command("ssh", args...) // #nosec G204 -- argv to ssh, not shell-evaluated locally; remote script's variables are shQuote'd.
	cmd.Stdin = &tarbuf
	cmd.Stderr = io.Discard
	if opt.Verbose {
		cmd.Stderr = os.Stderr
	}
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ssh apply: %w", err)
	}

	// 6. Compute add vs modify split from local-vs-remote.
	res := &SyncResult{Bytes: tarOut}
	for _, p := range d.ToAddOrModify {
		if _, present := remote.entries[p]; present {
			res.Modified++
		} else {
			res.Added++
		}
	}
	if opt.Delete {
		res.Deleted = len(d.ToDelete)
	}
	return res, nil
}

// conditional returns s when cond is true; empty otherwise. Tiny helper to
// keep the heredoc readable.
func conditional(cond bool, s string) string {
	if cond {
		return s
	}
	return ""
}

// readRemoteManifest ssh's to the container and runs a manifest script.
// The script is small enough to embed; no remote install needed beyond
// the standard sha256sum and find that come with every distro we target.
func readRemoteManifest(opt SyncOptions) (*manifest, error) {
	script := fmt.Sprintf(`
		set -e
		if [ ! -d %s ]; then
			mkdir -p %s
			exit 0
		fi
		cd %s
		find . -type f -printf '%%m %%p\n' 2>/dev/null \
			| while IFS=' ' read -r mode path; do
				path="${path#./}"
				h=$(sha256sum -- "$path" 2>/dev/null | cut -d ' ' -f1)
				if [ -n "$h" ]; then
					printf '%%s %%s %%s\n' "$h" "$mode" "$path"
				fi
			done
	`,
		shQuote(opt.RemotePath),
		shQuote(opt.RemotePath),
		shQuote(opt.RemotePath),
	)

	args := append(opt.sshBaseArgs(), opt.sshTarget(), script)
	var out bytes.Buffer
	// #nosec G204 -- argv to ssh, not shell-evaluated locally; remote
	// script's variables are shQuote'd.
	cmd := exec.Command("ssh", args...)
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	if opt.Verbose {
		cmd.Stderr = os.Stderr
	}
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ssh manifest: %w", err)
	}
	return parseRemoteManifest(&out)
}

// shQuote wraps s in POSIX shell single quotes, escaping any embedded
// single quotes. Used everywhere we embed a user-controlled path into a
// shell command.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
