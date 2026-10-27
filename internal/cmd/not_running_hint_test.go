package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Issue #2251: connect/code "not running" hints must name the wake verb
// (there is no `containarium start` subcommand for boxes).
func TestNotRunningHintUsesWake(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(thisFile)
	const want = "containarium wake"
	const forbid = "containarium start"
	for _, name := range []string{"connect.go", "code.go"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		body := string(b)
		if !strings.Contains(body, want) {
			t.Errorf("%s: missing %q in source", name, want)
		}
		if strings.Contains(body, forbid) {
			t.Errorf("%s: still contains %q", name, forbid)
		}
	}
}
