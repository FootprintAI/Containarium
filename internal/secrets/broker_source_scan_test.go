package secrets

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// callSitePattern matches an actual call — `<something>.BrokerCredential(`
// — not the method's own declaration, which reads `) BrokerCredential(`
// with no dot immediately before the name.
var callSitePattern = regexp.MustCompile(`\.BrokerCredential\(`)

// repoRoot walks up from this test file until it finds go.mod, so the
// scan works regardless of `go test`'s working directory.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find go.mod walking up from " + file)
		}
		dir = parent
	}
}

// TestBrokerCredentialCallers_Allowlist pins the fact that
// Store.BrokerCredential — the one path a broker-only secret's plaintext
// can flow through — is called only from where it's meant to be: the
// tracker package that consumes it, the daemon wiring that constructs a
// tracker.Broker, and tests exercising the method directly. A future
// change that reaches for it from, say, an MCP tool handler or a CLI
// command should fail this test rather than quietly widening the
// write-only guarantee's blast radius.
//
// Definition sites (`func (s *Store) BrokerCredential(...)`) don't match:
// callSitePattern requires a `.` immediately before the name, which a
// method declaration's `) BrokerCredential(` never has.
func TestBrokerCredentialCallers_Allowlist(t *testing.T) {
	root := repoRoot(t)
	allowedDirs := []string{
		filepath.Join(root, "internal", "tracker"),
		filepath.Join(root, "internal", "server"),
	}

	var violations []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			base := d.Name()
			if base == ".git" || base == "node_modules" || base == "vendor" || base == "web-ui" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		if !callSitePattern.Match(data) {
			return nil
		}
		// Allowed: this package's own tests (they exercise the method
		// directly), the tracker package, and the server wiring package.
		if strings.HasSuffix(path, "_test.go") && filepath.Dir(path) == filepath.Join(root, "internal", "secrets") {
			return nil
		}
		for _, allowed := range allowedDirs {
			if strings.HasPrefix(filepath.Dir(path), allowed) {
				return nil
			}
		}
		rel, _ := filepath.Rel(root, path)
		violations = append(violations, rel)
		return nil
	})
	if err != nil {
		t.Fatalf("walk repo: %v", err)
	}
	if len(violations) > 0 {
		t.Errorf("BrokerCredential called from outside the allow-list (internal/tracker, internal/server, internal/secrets tests): %v", violations)
	}
}
