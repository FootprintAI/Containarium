package stacks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repoRoot walks up from the package directory until it finds go.mod.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Skip("could not locate repo root from the package directory")
	return ""
}

// TestOnlyOneStackCatalogInRepo prevents the drift in #1131 from recurring.
//
// The repo previously carried two catalogs: this embedded one and
// configs/stacks.yaml. Only the embedded copy was maintained, so the other fell 5
// stacks behind and lost every rhel_packages/rhel_pre_install/rhel_post_install
// override — and because DefaultConfigPaths preferred the repo-relative path, a
// CLI run from a checkout silently used the stale one and installed Debian package
// names on RHEL. Nothing failed loudly; the two files simply disagreed.
//
// A second committed stacks.yaml is therefore a defect in itself, regardless of
// its contents.
func TestOnlyOneStackCatalogInRepo(t *testing.T) {
	root := repoRoot(t)
	var found []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable dir; not what this test is about
		}
		if d.IsDir() {
			base := d.Name()
			// Skip VCS, deps, and agent worktrees — those legitimately hold copies.
			if base == ".git" || base == "vendor" || base == "node_modules" || base == ".claude" {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() == "stacks.yaml" {
			rel, _ := filepath.Rel(root, path)
			found = append(found, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	const canonical = "pkg/core/stacks/stacks.yaml"
	if len(found) != 1 || filepath.ToSlash(found[0]) != canonical {
		t.Errorf("expected exactly one stack catalog at %s, found %d: %s\n"+
			"A second committed stacks.yaml drifts silently — see #1131.",
			canonical, len(found), strings.Join(found, ", "))
	}
}

// TestDefaultConfigPathsHasNoRepoRelativeEntry pins the other half of the fix.
// A path like "./configs/stacks.yaml" makes the loaded catalog depend on the
// process's working directory, so the CLI behaves differently inside a checkout
// than on a host. "./stacks.yaml" is kept deliberately as an explicit local
// override, but nothing may point back into the repo layout.
func TestDefaultConfigPathsHasNoRepoRelativeEntry(t *testing.T) {
	for _, p := range DefaultConfigPaths {
		if strings.Contains(p, "configs/") {
			t.Errorf("DefaultConfigPaths contains repo-relative %q; the catalog would "+
				"depend on CWD and can drift from the embedded copy (#1131)", p)
		}
	}
}
