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
//     directory is inside the root too);
//   - copies the staged regular files into a fresh private directory (the
//     snapshot). The gate verifies the snapshot and delivers the snapshot, so
//     the bytes verified and the bytes delivered are the same bytes, however
//     the staging area changes in between.
//
// Opens go through os.Root, so no read can leave the staging root even if
// the tree is changed while it is being copied. Symlinks inside the dataset
// are skipped, exactly as guardrail.SubjectDigest skips them.
package guardrailstage

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ErrNoStagingRoot means the daemon has no staging root configured, so a
// gated deploy has nowhere to read a dataset from and must be refused.
var ErrNoStagingRoot = errors.New("guardrail staging root is not configured")

// ErrBadRef wraps every reason a staging_ref is refused.
var ErrBadRef = errors.New("staging_ref must name a directory inside the guardrail staging root")

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

// validRef is the lexical check: a relative, slash-separated path in clean
// form with no "..", ".", empty or backslash component.
func validRef(ref string) error {
	if ref == "" || ref == "." || strings.ContainsRune(ref, '\\') || !filepath.IsLocal(ref) || filepath.Clean(ref) != ref {
		return fmt.Errorf("%w: %q is not a clean relative path", ErrBadRef, ref)
	}
	return nil
}

// Snapshot copies the dataset staged at ref into a new directory under
// parent. On any error nothing is left under parent.
func (a *Area) Snapshot(ref, parent string) (*Snapshot, error) {
	if err := validRef(ref); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(a.root)
	if err != nil {
		return nil, fmt.Errorf("guardrail staging root: %w", err)
	}
	defer func() { _ = root.Close() }()

	// Every component of ref must be a real directory, not a symlink.
	parts := strings.Split(ref, "/")
	for i := range parts {
		p := strings.Join(parts[:i+1], "/")
		info, err := root.Lstat(p)
		if err != nil {
			return nil, fmt.Errorf("%w: %q: %v", ErrBadRef, ref, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("%w: %q: %s is not a directory (symlinks are refused)", ErrBadRef, ref, p)
		}
	}
	src, err := root.OpenRoot(ref)
	if err != nil {
		return nil, fmt.Errorf("%w: %q: %v", ErrBadRef, ref, err)
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
// Everything else (symlinks, devices, sockets) is skipped.
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

func copyFile(src, out *os.Root, rel string) error {
	in, err := src.Open(rel)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
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
