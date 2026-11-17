package guardraildropin

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	// Temporary names in the final directories, so the rename is atomic.
	// The drop-in's must not end in .json: every *.json there is read.
	tmpBinaryPath = HookBinaryDir + "/.containarium.new"
	tmpDropInPath = DropInDir + "/.containarium-guardrail.tmp"

	// SmokeMarker is in the hook subcommand's own usage line. A binary
	// without the subcommand prints its parent's help instead, and exits 0
	// all the same, so the exit status alone proves nothing.
	SmokeMarker = "guardrail hook <event>"
)

// errNotRunnable is a hook binary that did not pass the smoke test in the
// box. No drop-in is left behind in that case.
var errNotRunnable = errors.New("the hook binary does not run in this box")

// prepareDirsScript makes the directories the daemon writes into and refuses
// any that is not a real, root-owned directory closed to group and others.
// `mkdir -p` would accept a symlink the box user placed, and the write
// would follow it.
const prepareDirsScript = `for d in "$@"; do
  if [ -L "$d" ]; then echo "$d is a symlink"; exit 3; fi
  if [ ! -e "$d" ]; then mkdir -m 0755 -- "$d" || { echo "cannot create $d"; exit 3; }; fi
  if [ ! -d "$d" ]; then echo "$d is not a directory"; exit 3; fi
  if [ "$(stat -c %u -- "$d")" != 0 ]; then echo "$d is not owned by root"; exit 3; fi
  if [ -n "$(find "$d" -maxdepth 0 -perm /022)" ]; then echo "$d is writable by group or others"; exit 3; fi
done`

// installed is what the daemon last put into a box: the hashes of the hook
// binary and of the drop-in. The manager keeps it on the box's config, on
// the host, where the box user cannot edit it; the check uses it to tell
// "an earlier version of ours" from a change someone else made.
type installed struct{ binary, dropIn string }

func (i installed) String() string { return i.binary + ":" + i.dropIn }

func parseInstalled(s string) installed {
	b, d, _ := strings.Cut(s, ":")
	return installed{binary: b, dropIn: d}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// current is what an install by this daemon, with these flags, leaves.
func (c *checker) current() (installed, error) {
	bin, err := c.binarySHA()
	if err != nil {
		return installed{}, err
	}
	return installed{binary: bin, dropIn: sha256Hex(c.dropIn)}, nil
}

// smoke runs the hook binary at path once, as the box user with a clean
// environment, and reports whether it carries the hook subcommand. It
// proves the file executes in this box (architecture, libc) for the user
// who will run it.
func (c *checker) smoke(container, user, path string) error {
	out, code, err := c.run.run(container, "runuser", "-u", user, "--",
		"env", "-i", "HOME=/nonexistent", "PATH=/usr/bin:/bin", path, "guardrail", "hook", "--help")
	if err != nil {
		return err
	}
	if code != 0 || !strings.Contains(out, SmokeMarker) {
		return fmt.Errorf("%w (exit %d running `guardrail hook --help` as the box user)", errNotRunnable, code)
	}
	return nil
}

// install puts the pinned binary and then the drop-in into a running box.
// The drop-in is written only after the binary it names has run there: with
// onFailure "block", a drop-in naming a command that does not run blocks
// every tool call. Both files are written under a temporary name and
// renamed, which replaces a symlink at the final path instead of following
// it and never exposes a half-written file.
func (c *checker) install(container, user string) error {
	want, err := c.binarySHA()
	if err != nil {
		return err
	}
	if out, code, err := c.run.script(container, prepareDirsScript, ManagedSettingsDir, DropInDir, HookBinaryDir); err != nil {
		return err
	} else if code != 0 {
		return fmt.Errorf("refusing to write into %q: %s", container, strconv.Quote(strings.TrimSpace(out)))
	}

	candidate := HookBinaryPath
	nodes, err := c.stat(container, HookBinaryPath)
	if err != nil {
		return err
	}
	have := ""
	if nodes[0].rootFile() {
		if have, err = c.boxSHA(container, HookBinaryPath); err != nil {
			return err
		}
	}
	if have != want {
		candidate = tmpBinaryPath
		if err := c.run.mustRun(container, "rm", "-f", "--", tmpBinaryPath); err != nil {
			return err
		}
		f, err := c.open()
		if err != nil {
			return fmt.Errorf("open hook binary: %w", err)
		}
		defer func() { _ = f.Close() }()
		if err := c.run.push(container, func() error { return c.box.PushFile(container, tmpBinaryPath, f, "0755") }); err != nil {
			return fmt.Errorf("install hook binary in %q: %w", container, err)
		}
		if pushed, err := c.boxSHA(container, tmpBinaryPath); err != nil {
			return err
		} else if pushed != want {
			return fmt.Errorf("install hook binary in %q: the pushed file does not match the pinned binary", container)
		}
	}
	if err := c.smoke(container, user, candidate); err != nil {
		// Leave nothing that points at it, including a drop-in from an
		// earlier install.
		_ = c.run.mustRun(container, "rm", "-f", "--", DropInPath, tmpBinaryPath)
		return err
	}
	if candidate != HookBinaryPath {
		if err := c.run.mustRun(container, "mv", "-T", "--", tmpBinaryPath, HookBinaryPath); err != nil {
			return err
		}
	}

	if err := c.run.mustRun(container, "rm", "-f", "--", tmpDropInPath); err != nil {
		return err
	}
	if err := c.run.push(container, func() error { return c.box.WriteFile(container, tmpDropInPath, c.dropIn, "0644") }); err != nil {
		return fmt.Errorf("install drop-in in %q: %w", container, err)
	}
	return c.run.mustRun(container, "mv", "-T", "--", tmpDropInPath, DropInPath)
}

// remove takes the drop-in out first, then the binary. It is the
// break-glass, so it must work whatever state the binary is in.
func (c *checker) remove(container string) error {
	if err := c.run.mustRun(container, "rm", "-f", "--", DropInPath, tmpDropInPath); err != nil {
		return err
	}
	if err := c.run.mustRun(container, "rm", "-rf", "--", HookBinaryDir); err != nil {
		return err
	}
	c.mu.Lock()
	delete(c.versions, container)
	c.mu.Unlock()
	return nil
}

// binarySHA is the SHA-256 of the pinned binary, hashed once.
func (c *checker) binarySHA() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.binSHA != "" {
		return c.binSHA, nil
	}
	f, err := c.open()
	if err != nil {
		return "", fmt.Errorf("open hook binary: %w", err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash hook binary: %w", err)
	}
	c.binSHA = hex.EncodeToString(h.Sum(nil))
	return c.binSHA, nil
}

// boxSHA is the SHA-256 of a file in the box; "" when it cannot be read.
// Callers stat the path first: this follows links.
func (c *checker) boxSHA(container, p string) (string, error) {
	out, code, err := c.run.run(container, "sha256sum", "--", p)
	if err != nil || code != 0 {
		return "", err
	}
	return strings.Fields(out + " x")[0], nil
}
