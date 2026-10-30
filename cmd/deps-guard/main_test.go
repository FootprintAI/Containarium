package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The CLI's exit status is the workflow's verdict: 1 is a policy failure,
// 2 is "no verdict", and the two must never be confused with a pass.
func TestDiffExitCodes(t *testing.T) {
	notFound := httptest.NewServer(http.NotFoundHandler())
	defer notFound.Close()
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer broken.Close()

	fixture := func(name string) []string {
		d := filepath.Join("..", "..", "internal", "depsguard", "testdata", name)
		return []string{"-base", filepath.Join(d, "base.go.mod"), "-head", filepath.Join(d, "head.go.mod"), "-gosum", filepath.Join(d, "head.go.sum")}
	}
	tests := []struct {
		name    string
		fixture string
		sumdb   string
		want    int
		stderr  string
	}{
		{"new replace is a policy failure", "fail-replace-added", notFound.URL, exitFail, "FAIL replace-added"},
		{"unknown module is a policy failure", "fail-not-in-sumdb", notFound.URL, exitFail, "FAIL not-in-sumdb"},
		{"unreachable checksum database is no verdict", "fail-not-in-sumdb", broken.URL, exitError, "no verdict"},
		{"missing -base is no verdict", "", notFound.URL, exitError, "-base is required"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			report := filepath.Join(t.TempDir(), "report.md")
			args := []string{"diff", "-sumdb", tc.sumdb, "-proxy", notFound.URL, "-report", report}
			if tc.fixture != "" {
				args = append(args, fixture(tc.fixture)...)
			}
			var stdout, stderr bytes.Buffer
			got := run(context.Background(), args, &stdout, &stderr)
			if got != tc.want {
				t.Fatalf("exit %d, want %d; stderr:\n%s", got, tc.want, stderr.String())
			}
			if !strings.Contains(stderr.String(), tc.stderr) {
				t.Fatalf("stderr missing %q:\n%s", tc.stderr, stderr.String())
			}
			if tc.want == exitFail {
				b, err := os.ReadFile(report)
				if err != nil || !strings.HasPrefix(string(b), "<!-- deps-guard -->") {
					t.Fatalf("a failing run must still write the report: %v %q", err, b)
				}
			}
		})
	}
}

// A quoted local replace target can carry a newline followed by a workflow
// command. Neither the log lines nor the ::error annotation may let it
// reach the start of an output line, where the runner would execute it.
func TestHostileTextCannotIssueWorkflowCommands(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "true")
	notFound := httptest.NewServer(http.NotFoundHandler())
	defer notFound.Close()
	d := filepath.Join("..", "..", "internal", "depsguard", "testdata", "fail-replace-hostile-text")
	var stdout, stderr bytes.Buffer
	got := run(context.Background(), []string{"diff", "-sumdb", notFound.URL, "-proxy", notFound.URL,
		"-base", filepath.Join(d, "base.go.mod"), "-head", filepath.Join(d, "head.go.mod"), "-gosum", filepath.Join(d, "head.go.sum")},
		&stdout, &stderr)
	if got != exitFail {
		t.Fatalf("exit %d, want %d; stderr:\n%s", got, exitFail, stderr.String())
	}
	out := stdout.String() + stderr.String()
	sawAnnotation := false
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "::") {
			continue
		}
		if !strings.HasPrefix(line, "::error file=go.mod,title=deps-guard replace-added::") {
			t.Errorf("output line issues a workflow command: %q", line)
			continue
		}
		sawAnnotation = true
		if !strings.Contains(line, "%0A::warning") && !strings.Contains(line, `\n::warning`) {
			t.Errorf("annotation lost or mangled the hostile text instead of escaping it: %q", line)
		}
	}
	if !sawAnnotation {
		t.Fatalf("no annotation printed:\n%s", out)
	}
}

func TestAnnotationEscaping(t *testing.T) {
	for in, want := range map[string]string{
		"plain":      "plain",
		"a\nb":       "a%0Ab",
		"50%\r\n::x": "50%25%0D%0A::x",
	} {
		if got := escapeData(in); got != want {
			t.Errorf("escapeData(%q) = %q, want %q", in, got, want)
		}
	}
}
