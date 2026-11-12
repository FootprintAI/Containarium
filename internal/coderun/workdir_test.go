package coderun

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// #3613: the home-relative path rule, shared by WriteBoxFile's path, the
// daemon's StartBoxRunRequest.workdir, `code run --workdir` and MCP code_run.
func TestCleanHomeRelPath(t *testing.T) {
	for _, ok := range []string{"project", "src/app", ".config/tool", "a b", strings.Repeat("a", MaxHomeRelPathSegmentBytes)} {
		if got, err := CleanHomeRelPath("workdir", ok); err != nil || got != ok {
			t.Errorf("CleanHomeRelPath(%q) = %q, %v; want it accepted unchanged", ok, got, err)
		}
	}
	for _, tc := range []struct{ in, want string }{
		{"", "workdir is required"},
		{"/etc", "relative to the box user's home"},
		{"..", "stay inside the home directory"},
		{"../x", "stay inside the home directory"},
		{"a/../b", "clean relative path"},
		{".", "clean relative path"},
		{"./a", "clean relative path"},
		{"a/", "clean relative path"},
		{"a//b", "clean relative path"},
		{"a\nb", "control characters"},
		{"a\x7fb", "control characters"},
		{".ssh", "the platform manages it"},
		{".containarium/x", "the platform manages it"},
		{strings.Repeat("a", MaxHomeRelPathSegmentBytes+1), "each segment under"},
		{strings.Repeat("a/", MaxHomeRelPathBytes/2) + "a", "at most"},
	} {
		_, err := CleanHomeRelPath("workdir", tc.in)
		if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.HasPrefix(err.Error(), "workdir ") {
			t.Errorf("CleanHomeRelPath(%q) err = %v, want one naming workdir and %q", tc.in, err, tc.want)
		}
	}
}

func TestRunCwd(t *testing.T) {
	if got := RunCwd("/home/alice", ""); got != "/home/alice" {
		t.Errorf("RunCwd without a cwd = %q, want the home", got)
	}
	if got := RunCwd("/home/alice", "/home/alice/project"); got != "/home/alice/project" {
		t.Errorf("RunCwd = %q, want the cwd", got)
	}
}

// A directory under the box user's home resolves to its absolute path, which
// is what ProcessStart then hands process_start as its cwd.
func TestResolveWorkdir_ExistingDirectory(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "src", "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	conn := &boxShellConn{t: t, home: home}
	sess := sessionWith(conn)
	for _, workdir := range []string{"src", "src/app"} {
		got, err := sess.ResolveWorkdir(context.Background(), workdir)
		if err != nil {
			t.Fatalf("ResolveWorkdir(%q): %v", workdir, err)
		}
		if want := home + "/" + workdir; got != want {
			t.Errorf("ResolveWorkdir(%q) = %q, want %q", workdir, got, want)
		}
	}
}

// A missing directory, a file and a directory the box user cannot enter are
// refused, each naming the workdir, and nothing is created.
func TestResolveWorkdir_RefusesWhatTheRunCannotStartIn(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, "notes"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	locked := filepath.Join(home, "locked")
	if err := os.Mkdir(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	cases := []struct{ workdir, want string }{
		{"missing", "does not exist"},
		{"missing/deeper", "does not exist"},
		{"notes", "is not a directory"},
	}
	if os.Geteuid() != 0 { // root enters any directory
		cases = append(cases, struct{ workdir, want string }{"locked", "cannot be entered"})
	}
	for _, tc := range cases {
		t.Run(tc.workdir, func(t *testing.T) {
			conn := &boxShellConn{t: t, home: home}
			got, err := sessionWith(conn).ResolveWorkdir(context.Background(), tc.workdir)
			if err == nil {
				t.Fatalf("ResolveWorkdir(%q) = %q, want a refusal", tc.workdir, got)
			}
			if !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), strconv.Quote(tc.workdir)) {
				t.Errorf("err = %q, want it to name %q and say %q", err, tc.workdir, tc.want)
			}
		})
	}
	if _, err := os.Stat(filepath.Join(home, "missing")); !os.IsNotExist(err) {
		t.Errorf("a missing workdir was created: stat err = %v", err)
	}
}

// An empty workdir is process_start's default and costs no call to the box; a
// non-canonical one is refused before the box is asked anything.
func TestResolveWorkdir_EmptyOrNonCanonicalTouchesNothing(t *testing.T) {
	conn := &scriptedConn{replies: map[string]string{}}
	sess := sessionWith(conn)
	if got, err := sess.ResolveWorkdir(context.Background(), ""); err != nil || got != "" {
		t.Errorf("ResolveWorkdir(\"\") = %q, %v; want \"\", nil", got, err)
	}
	for _, bad := range []string{"/etc", "../x", ".", "a/", ".ssh"} {
		if _, err := sess.ResolveWorkdir(context.Background(), bad); err == nil {
			t.Errorf("ResolveWorkdir(%q) accepted", bad)
		}
	}
	if len(conn.calls) != 0 {
		t.Errorf("the box was called for an empty or non-canonical workdir: %v", conn.calls)
	}
}

// A check that cannot run, or answers with something unexpected, refuses: a
// run that did not look is not known to start where it was asked to.
func TestResolveWorkdir_CheckFailureRefuses(t *testing.T) {
	home := t.TempDir()
	// The first shell_exec is HomeDir; the check is the second.
	conn := &boxShellConn{t: t, home: home, failShellFrom: 2, shellStderr: "sh: not found"}
	_, err := sessionWith(conn).ResolveWorkdir(context.Background(), "project")
	if err == nil || !strings.Contains(err.Error(), "exit 1") || !strings.Contains(err.Error(), `"project"`) {
		t.Fatalf("err = %v, want a refusal naming the workdir and the failed check", err)
	}

	odd := func(context.Context, string) (string, error) {
		return "exit_code: 0\ntimeout_seconds: 30\n--- stdout ---\nsomething else\n--- stderr ---\n", nil
	}
	if _, err := checkWorkdir(context.Background(), odd, home, "project"); err == nil || !strings.Contains(err.Error(), "unexpected output") {
		t.Fatalf("err = %v, want an unexpected-output refusal", err)
	}
}
