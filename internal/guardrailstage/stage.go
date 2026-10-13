// Package guardrailstage is the daemon-side staging area a gated recipe
// deploy reads its dataset from (#2368;
// docs/architecture/guardrail-inbound-and-server-policy.md, "The gate").
//
// A DeployRecipeRequest names its dataset by staging_ref: a directory under
// one operator-configured staging root on the daemon host. There is no
// platform path that puts a dataset there yet (the `ship` verb is a
// documented gap), so an operator or an out-of-band copy stages it. This
// package does two things with a ref:
//
//   - refuses any ref that does not name a real directory inside the root:
//     absolute paths, "..", non-clean forms, and any symlink on the ref's own
//     path, even one that points back inside the root (another tenant's
//     directory is inside the root too). The ref is opened one component at
//     a time and each opened directory must be the inode that was checked,
//     so swapping a component for a symlink mid-open is refused, not
//     followed;
//   - copies the staged regular files into a fresh private directory (the
//     snapshot). The gate verifies the snapshot and delivers the snapshot, so
//     the bytes verified and the bytes delivered are the same bytes, however
//     the staging area changes in between.
//
// Opens go through os.Root, so no read can leave the staging root even if
// the tree is changed while it is being copied. Symlinks inside the dataset
// are skipped, exactly as guardrail.SubjectDigest skips them. Files are
// opened non-blocking and must still be regular files once open, so a file
// swapped for a FIFO is skipped instead of hanging the snapshot.
//
// Hard links are not symlinks: a hard link inside the dataset to a file
// outside the root is copied. That needs no special handling, because
// whoever stages can only hard-link a file they can already read (and, with
// fs.protected_hardlinks, own or write), so it grants them nothing.
//
// Errors: ErrBadRef and ErrBadParent name only the caller's ref. Any other
// error is internal (it may carry daemon-side detail); callers such as the
// DeployRecipe gate must log it and return a generic message, never echo it.
package guardrailstage

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// ErrNoStagingRoot means the daemon has no staging root configured, so a
// gated deploy has nowhere to read a dataset from and must be refused.
var ErrNoStagingRoot = errors.New("guardrail staging root is not configured")

// ErrBadRef wraps every reason a staging_ref is refused.
var ErrBadRef = errors.New("staging_ref must name a directory inside the guardrail staging root")

// ErrBadParent means the snapshot's parent directory is inside the staging
// root, where whoever stages could swap the snapshot after verification.
var ErrBadParent = errors.New("guardrail snapshot parent must be a daemon-private directory outside the staging root")

// ErrStagingRootUnavailable means the configured root could not be opened
// (removed or unreadable since New). It never embeds the host path.
var ErrStagingRootUnavailable = errors.New("guardrail staging root is unavailable")

// Area is a configured staging root.
type Area struct {
	root string
}

// New checks root is an absolute path to an existing directory.
func New(root string) (*Area, error) {
	if root == "" {
		return nil, ErrNoStagingRoot
	}
	if !filepath.IsAbs(root) {
		return nil, fmt.Errorf("guardrail staging root %q must be an absolute path", root)
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("guardrail staging root: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("guardrail staging root %q is not a directory", root)
	}
	return &Area{root: filepath.Clean(root)}, nil
}

// Snapshot is a private copy of one staged dataset.
type Snapshot struct {
	// Dir holds the copied files; mode 0700, owned by the daemon.
	Dir string
}

// Remove deletes the snapshot.
func (s *Snapshot) Remove() error { return os.RemoveAll(s.Dir) }

// testHook, when set by a test, runs at the named point with the name about
// to be opened. It lets a test change the tree at exactly the instant a
// race would, deterministically. nil in production.
var testHook func(point, name string)

const (
	hookBeforeOpenDir  = "before-open-dir"
	hookBeforeOpenFile = "before-open-file"
)

func hook(point, name string) {
	if testHook != nil {
		testHook(point, name)
	}
}

// validRef is the lexical check: a relative, slash-separated path in clean
// form with no "..", ".", empty or backslash component.
func validRef(ref string) error {
	if ref == "" || ref == "." || strings.ContainsRune(ref, '\\') || !filepath.IsLocal(ref) || filepath.Clean(ref) != ref {
		return fmt.Errorf("%w: %q is not a clean relative path", ErrBadRef, ref)
	}
	return nil
}

// checkParent refuses a snapshot parent inside the staging root ("" is
// os.TempDir()). The parent must be daemon-private (or sticky, like /tmp):
// whoever can rename entries in it could swap the snapshot between
// verification and delivery.
func (a *Area) checkParent(parent string) error {
	if parent == "" {
		parent = os.TempDir()
	}
	p, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBadParent, err)
	}
	r, err := filepath.EvalSymlinks(a.root)
	if err != nil {
		return ErrStagingRootUnavailable
	}
	if rel, err := filepath.Rel(r, p); err == nil && filepath.IsLocal(rel) || p == r {
		return ErrBadParent
	}
	return nil
}

// openNoSymlinks opens ref under root one component at a time. Each
// component must Lstat as a real directory, and the directory then opened
// must be that same inode: a component swapped for a symlink (even one
// staying inside the root) between the check and the open is refused.
func openNoSymlinks(root *os.Root, ref string) (*os.Root, error) {
	cur := root
	release := func() {
		if cur != root {
			_ = cur.Close()
		}
	}
	for _, part := range strings.Split(ref, "/") {
		info, err := cur.Lstat(part)
		if err != nil {
			release()
			return nil, fmt.Errorf("%w: %q: %s: %v", ErrBadRef, ref, part, errors.Unwrap(err))
		}
		if !info.IsDir() {
			release()
			return nil, fmt.Errorf("%w: %q: %s is not a directory (symlinks are refused)", ErrBadRef, ref, part)
		}
		hook(hookBeforeOpenDir, part)
		next, err := cur.OpenRoot(part)
		if err != nil {
			release()
			return nil, fmt.Errorf("%w: %q: %s: %v", ErrBadRef, ref, part, errors.Unwrap(err))
		}
		got, err := next.Stat(".")
		if err != nil || !os.SameFile(info, got) {
			_ = next.Close()
			release()
			return nil, fmt.Errorf("%w: %q: %s changed while it was being opened", ErrBadRef, ref, part)
		}
		release()
		cur = next
	}
	return cur, nil
}

// Snapshot copies the dataset staged at ref into a new directory under
// parent ("" = os.TempDir()). parent must be daemon-private and outside the
// staging root. On any error nothing is left under parent.
func (a *Area) Snapshot(ref, parent string) (*Snapshot, error) {
	if err := validRef(ref); err != nil {
		return nil, err
	}
	if err := a.checkParent(parent); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(a.root)
	if err != nil {
		return nil, ErrStagingRootUnavailable
	}
	defer func() { _ = root.Close() }()

	src, err := openNoSymlinks(root, ref)
	if err != nil {
		return nil, err
	}
	defer func() { _ = src.Close() }()

	dir, err := os.MkdirTemp(parent, "guardrail-snapshot-")
	if err != nil {
		return nil, err
	}
	if err := copyTree(src, dir); err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("snapshot %q: %w", ref, err)
	}
	return &Snapshot{Dir: dir}, nil
}

// copyTree copies every directory and regular file under src into dst.
// Everything else (symlinks, devices, sockets, FIFOs) is skipped.
func copyTree(src *os.Root, dst string) error {
	out, err := os.OpenRoot(dst)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()
	return fs.WalkDir(src.FS(), ".", func(rel string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if d.IsDir() {
			return out.Mkdir(rel, 0o700)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		return copyFile(src, out, rel)
	})
}

// copyFile copies one file, re-checking its type on the open handle: the
// walk's type check is a name lookup, and the name may have been swapped
// since. O_NONBLOCK keeps an open of a swapped-in FIFO from blocking.
func copyFile(src, out *os.Root, rel string) error {
	hook(hookBeforeOpenFile, rel)
	in, err := src.OpenFile(rel, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return nil
	}
	w, err := out.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, in); err != nil {
		_ = w.Close()
		return err
	}
	return w.Close()
}
