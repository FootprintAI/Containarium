package guardrailstage_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/footprintai/containarium/internal/guardrail"
	"github.com/footprintai/containarium/internal/guardrailstage"
)

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// layout is a staging root with one good dataset, a file where a directory
// belongs, symlinks to a directory inside the root and to one outside it,
// and a secret outside the root that no ref may reach.
func layout(t *testing.T) (root, outside string) {
	t.Helper()
	base := t.TempDir()
	root, outside = filepath.Join(base, "staging"), filepath.Join(base, "outside")
	write(t, filepath.Join(root, "tenant", "ds1", "a.txt"), "alpha\n")
	write(t, filepath.Join(root, "tenant", "ds1", "sub", "b.txt"), "beta\n")
	write(t, filepath.Join(root, "tenant", "afile"), "not a directory\n")
	write(t, filepath.Join(root, "other", "ds", "x.txt"), "another dataset\n")
	write(t, filepath.Join(outside, "secret.txt"), "host secret\n")
	if err := os.Symlink(outside, filepath.Join(root, "tenant", "out")); err != nil {
		t.Fatal(err)
	}
	// Relative, so os.Root alone would follow it (it stays inside the root);
	// only the package's own no-symlink rule refuses it.
	if err := os.Symlink(filepath.Join("..", "other"), filepath.Join(root, "tenant", "in")); err != nil {
		t.Fatal(err)
	}
	return root, outside
}

func TestNew_RequiresAnAbsoluteDirectory(t *testing.T) {
	root, _ := layout(t)
	if _, err := guardrailstage.New(""); !errors.Is(err, guardrailstage.ErrNoStagingRoot) {
		t.Errorf("New(\"\") = %v, want ErrNoStagingRoot", err)
	}
	for _, bad := range []string{"relative/dir", filepath.Join(root, "tenant", "afile"), filepath.Join(root, "missing")} {
		if _, err := guardrailstage.New(bad); err == nil {
			t.Errorf("New(%q) = nil error, want refused", bad)
		}
	}
	if _, err := guardrailstage.New(root); err != nil {
		t.Errorf("New(root) = %v", err)
	}
}

// TestSnapshot_RefMustStayInsideTheRoot: every ref that names something
// other than a real directory under the root is refused with ErrBadRef, and
// nothing is snapshotted.
func TestSnapshot_RefMustStayInsideTheRoot(t *testing.T) {
	root, _ := layout(t)
	area, err := guardrailstage.New(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{
		"",
		".",
		"/etc",
		root + "/tenant/ds1", // absolute, even when it points inside
		"..",
		"../outside",
		"tenant/../../outside",
		"tenant/./ds1", // not in clean form
		"tenant//ds1",
		"tenant/ds1/",
		"tenant\\ds1",
		"tenant/out",          // symlink leaving the root
		"tenant/out/",         // ...with a trailing slash
		"tenant/in/ds",        // symlink to another directory inside the root
		"tenant/afile",        // not a directory
		"tenant/missing",      // does not exist
		"tenant/ds1/sub/../x", // traversal inside
	} {
		t.Run(ref, func(t *testing.T) {
			parent := t.TempDir()
			snap, err := area.Snapshot(ref, parent)
			if !errors.Is(err, guardrailstage.ErrBadRef) {
				t.Fatalf("Snapshot(%q) = (%v, %v), want ErrBadRef", ref, snap, err)
			}
			if entries, _ := os.ReadDir(parent); len(entries) != 0 {
				t.Fatalf("a refused Snapshot(%q) left %d entries behind", ref, len(entries))
			}
		})
	}
}

// TestSnapshot_CopiesTheDatasetPrivately: the snapshot holds exactly the
// staged regular files, digests the same as the staged tree, is private to
// the daemon, and Remove deletes it.
func TestSnapshot_CopiesTheDatasetPrivately(t *testing.T) {
	root, _ := layout(t)
	area, err := guardrailstage.New(root)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := area.Snapshot("tenant/ds1", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	want, err := guardrail.SubjectDigest(filepath.Join(root, "tenant", "ds1"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := guardrail.SubjectDigest(snap.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("snapshot digest %s != staged digest %s", got, want)
	}
	if b, _ := os.ReadFile(filepath.Join(snap.Dir, "sub", "b.txt")); string(b) != "beta\n" {
		t.Fatalf("sub/b.txt = %q", b)
	}
	info, err := os.Stat(snap.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("snapshot dir mode %v, want 0700", info.Mode().Perm())
	}
	if err := snap.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(snap.Dir); !os.IsNotExist(err) {
		t.Fatalf("snapshot still exists after Remove: %v", err)
	}
}

// TestSnapshot_SymlinksInsideTheDatasetAreNotFollowed: a symlink inside the
// staged directory is skipped, exactly as SubjectDigest skips it, so a
// dataset cannot pull a host file into the box.
func TestSnapshot_SymlinksInsideTheDatasetAreNotFollowed(t *testing.T) {
	root, outside := layout(t)
	ds := filepath.Join(root, "tenant", "ds1")
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(ds, "leak.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(ds, "leakdir")); err != nil {
		t.Fatal(err)
	}
	// A link that stays inside the dataset is skipped too: SubjectDigest
	// skips it, so copying it would deliver bytes the digest never covered.
	if err := os.Symlink("a.txt", filepath.Join(ds, "alias.txt")); err != nil {
		t.Fatal(err)
	}
	area, err := guardrailstage.New(root)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := area.Snapshot("tenant/ds1", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"leak.txt", "leakdir", filepath.Join("leakdir", "secret.txt"), "alias.txt"} {
		if _, err := os.Lstat(filepath.Join(snap.Dir, p)); !os.IsNotExist(err) {
			t.Errorf("%s is in the snapshot (err %v); symlinks must not be copied", p, err)
		}
	}
}

// TestSnapshot_LaterChangesToTheStagingAreaDoNotReachIt: the snapshot is a
// copy, so editing, adding or deleting staged files after it was taken
// changes nothing in it. This is what lets the gate deliver exactly the
// bytes it verified.
func TestSnapshot_LaterChangesToTheStagingAreaDoNotReachIt(t *testing.T) {
	root, _ := layout(t)
	area, err := guardrailstage.New(root)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := area.Snapshot("tenant/ds1", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	before, err := guardrail.SubjectDigest(snap.Dir)
	if err != nil {
		t.Fatal(err)
	}
	ds := filepath.Join(root, "tenant", "ds1")
	write(t, filepath.Join(ds, "a.txt"), "ALPHA, changed\n")
	write(t, filepath.Join(ds, "new.txt"), "added later\n")
	if err := os.Remove(filepath.Join(ds, "sub", "b.txt")); err != nil {
		t.Fatal(err)
	}
	after, err := guardrail.SubjectDigest(snap.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("snapshot digest changed from %s to %s after the staging area changed", before, after)
	}
}
