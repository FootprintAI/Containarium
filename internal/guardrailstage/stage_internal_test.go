package guardrailstage

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func put(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func withHook(t *testing.T, h func(point, name string)) {
	t.Helper()
	testHook = h
	t.Cleanup(func() { testHook = nil })
}

func newArea(t *testing.T) (*Area, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "staging")
	put(t, filepath.Join(root, "tenant", "ds", "mine.txt"), "mine\n")
	put(t, filepath.Join(root, "tenant", "ds", "sub", "deep.txt"), "deep\n")
	put(t, filepath.Join(root, "other", "ds", "theirs.txt"), "another tenant's data\n")
	area, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	return area, root
}

// TestValidRef pins the lexical layer on its own: every row is refused by
// validRef itself, before any filesystem lookup could catch it.
func TestValidRef(t *testing.T) {
	for _, ref := range []string{"", ".", "..", "../x", "/etc", "/", `tenant\ds`, `a\..\b`, "a/./b", "a//b", "a/", "a/b/..", "./a"} {
		if err := validRef(ref); !errors.Is(err, ErrBadRef) {
			t.Errorf("validRef(%q) = %v, want ErrBadRef", ref, err)
		}
	}
	for _, ref := range []string{"a", "tenant/ds", "a/b/c", "a.b/c-d"} {
		if err := validRef(ref); err != nil {
			t.Errorf("validRef(%q) = %v, want ok", ref, err)
		}
	}
}

// TestSnapshot_ComponentSwappedForSymlinkBeforeOpenIsRefused is the
// deterministic form of the race: at the instant after a component was
// checked and before it is opened, it is replaced by a symlink to another
// tenant's directory inside the root. The open must be refused, not follow.
func TestSnapshot_ComponentSwappedForSymlinkBeforeOpenIsRefused(t *testing.T) {
	for _, swapAt := range []string{"tenant", "ds"} {
		t.Run(swapAt, func(t *testing.T) {
			area, root := newArea(t)
			swapped := false
			withHook(t, func(point, name string) {
				if point != hookBeforeOpenDir || name != swapAt || swapped {
					return
				}
				swapped = true
				var path, target string
				if swapAt == "tenant" {
					path, target = filepath.Join(root, "tenant"), "other"
				} else {
					path, target = filepath.Join(root, "tenant", "ds"), filepath.Join("..", "other", "ds")
				}
				if err := os.Rename(path, path+".moved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			})
			parent := t.TempDir()
			snap, err := area.Snapshot("tenant/ds", parent)
			if !swapped {
				t.Fatal("hook never ran")
			}
			if err == nil {
				_, theirs := os.Lstat(filepath.Join(snap.Dir, "theirs.txt"))
				t.Fatalf("Snapshot followed a swapped-in symlink (other tenant's file present: %v)", theirs == nil)
			}
			if !errors.Is(err, ErrBadRef) {
				t.Fatalf("err = %v, want ErrBadRef", err)
			}
			if entries, _ := os.ReadDir(parent); len(entries) != 0 {
				t.Fatalf("refused snapshot left %d entries", len(entries))
			}
		})
	}
}

// TestSnapshot_ModesArePrivate: every directory in the snapshot is 0700 and
// every file 0600, not only the top directory.
func TestSnapshot_ModesArePrivate(t *testing.T) {
	area, _ := newArea(t)
	snap, err := area.Snapshot("tenant/ds", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var dirs, files int
	err = filepath.WalkDir(snap.Dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		want := os.FileMode(0o600)
		if d.IsDir() {
			want, dirs = 0o700, dirs+1
		} else {
			files++
		}
		if info.Mode().Perm() != want {
			t.Errorf("%s mode %v, want %v", p, info.Mode().Perm(), want)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if dirs != 2 || files != 2 {
		t.Fatalf("walked %d dirs / %d files, want 2 / 2", dirs, files)
	}
}

// TestSnapshot_CopyErrorLeavesNothingBehind: a file that disappears between
// the walk and its open fails the copy, and the partial snapshot is removed.
func TestSnapshot_CopyErrorLeavesNothingBehind(t *testing.T) {
	area, root := newArea(t)
	withHook(t, func(point, name string) {
		if point == hookBeforeOpenFile && name == "sub/deep.txt" {
			_ = os.Remove(filepath.Join(root, "tenant", "ds", "sub", "deep.txt"))
		}
	})
	parent := t.TempDir()
	if _, err := area.Snapshot("tenant/ds", parent); err == nil {
		t.Fatal("Snapshot = nil error, want the copy error")
	}
	if entries, _ := os.ReadDir(parent); len(entries) != 0 {
		t.Fatalf("a failed copy left %d entries under parent", len(entries))
	}
}

// TestSnapshot_ParentInsideTheStagingRootIsRefused: whoever stages could
// rename a snapshot made inside the staging root after it was verified.
func TestSnapshot_ParentInsideTheStagingRootIsRefused(t *testing.T) {
	area, root := newArea(t)
	for _, parent := range []string{root, filepath.Join(root, "tenant"), filepath.Join(root, "tenant", "ds")} {
		if _, err := area.Snapshot("tenant/ds", parent); !errors.Is(err, ErrBadParent) {
			t.Errorf("Snapshot(parent %s) = %v, want ErrBadParent", parent, err)
		}
	}
	// Reached through a symlink, too.
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(filepath.Join(root, "tenant"), link); err != nil {
		t.Fatal(err)
	}
	if _, err := area.Snapshot("tenant/ds", link); !errors.Is(err, ErrBadParent) {
		t.Errorf("Snapshot(parent via symlink) = %v, want ErrBadParent", err)
	}
	if _, err := area.Snapshot("tenant/ds", t.TempDir()); err != nil {
		t.Errorf("Snapshot(private parent) = %v", err)
	}
}

// TestSnapshot_VanishedRootErrorIsTypedAndHidesThePath.
func TestSnapshot_VanishedRootErrorIsTypedAndHidesThePath(t *testing.T) {
	area, root := newArea(t)
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	_, err := area.Snapshot("tenant/ds", t.TempDir())
	if !errors.Is(err, ErrStagingRootUnavailable) {
		t.Fatalf("err = %v, want ErrStagingRootUnavailable", err)
	}
	if strings.Contains(err.Error(), root) || strings.Contains(err.Error(), filepath.Dir(root)) {
		t.Fatalf("error %q leaks the host path", err)
	}
}
