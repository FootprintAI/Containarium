package engine

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestClaudeProjectSlug pins the "/" -> "-" convention #2193's accepted
// default commits to (unverified against a live Claude Code install — see
// session_discovery.go's doc comment).
func TestClaudeProjectSlug(t *testing.T) {
	tests := []struct{ cwd, want string }{
		{"/home/alice", "-home-alice"},
		{"/home/alice/myproject", "-home-alice-myproject"},
		{"/", "-"},
	}
	for _, tc := range tests {
		if got := ClaudeProjectSlug(tc.cwd); got != tc.want {
			t.Errorf("ClaudeProjectSlug(%q) = %q, want %q", tc.cwd, got, tc.want)
		}
	}
}

// TestSessionDiscoveryBackgroundCommand_UnknownEngine pins that an engine
// with no discoverable session id (there are none today, but a future engine
// added to Name without updating sessionSearchDir must fail closed, not
// silently poll a made-up path).
func TestSessionDiscoveryBackgroundCommand_UnknownEngine(t *testing.T) {
	if _, ok := SessionDiscoveryBackgroundCommand(Name("made-up"), "/home/alice", "/home/alice", "/tmp/x.session"); ok {
		t.Error("an unknown engine should report ok=false, not a command")
	}
}

// discoveryFixture drives the real prepare/poll shell commands against a
// fake engine session directory, so the tests prove the mechanism against a
// real shell rather than matching on the generated string.
type discoveryFixture struct {
	t       *testing.T
	engine  Name
	home    string
	cwd     string
	dir     string
	suffix  string
	sidecar string
}

func newDiscoveryFixture(t *testing.T, n Name) *discoveryFixture {
	t.Helper()
	home := t.TempDir()
	f := &discoveryFixture{t: t, engine: n, home: home, cwd: filepath.Join(home, "myproject"), sidecar: filepath.Join(t.TempDir(), "run.session")}
	switch n {
	case NameClaude:
		f.dir = filepath.Join(home, ".claude", "projects", ClaudeProjectSlug(f.cwd))
		f.suffix = ".jsonl"
	default:
		f.dir = filepath.Join(home, ".pi", "agent", "sessions")
	}
	mustMkdirAll(t, f.dir)
	return f
}

func (f *discoveryFixture) sh(cmd string) {
	f.t.Helper()
	// #nosec G204 -- cmd is built entirely by the functions under test from
	// test-controlled inputs; this is the test for them.
	c := exec.Command("/bin/sh", "-c", cmd)
	c.Env = append(os.Environ(), "PATH="+setsidShimDir(f.t)+string(os.PathListSeparator)+os.Getenv("PATH"))
	if out, err := c.CombinedOutput(); err != nil {
		f.t.Fatalf("command failed: %v\n%s", err, out)
	}
}

// setsidShimDir returns a directory holding a pass-through `setsid` for
// hosts that lack util-linux's (macOS developer machines). On Linux the
// shim only shadows the real one with an equivalent for these tests.
func setsidShimDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "setsid"), []byte("#!/bin/sh\nexec \"$@\"\n"), 0o755); err != nil { // #nosec G306 -- test shim must be executable
		t.Fatal(err)
	}
	return dir
}

func (f *discoveryFixture) prepare() {
	cmd, ok := SessionDiscoveryPrepareCommand(f.engine, f.home, f.cwd, f.sidecar)
	if !ok {
		f.t.Fatalf("SessionDiscoveryPrepareCommand(%s) ok=false", f.engine)
	}
	f.sh(cmd)
}

func (f *discoveryFixture) poll() {
	cmd, ok := SessionDiscoveryBackgroundCommand(f.engine, f.home, f.cwd, f.sidecar)
	if !ok {
		f.t.Fatalf("SessionDiscoveryBackgroundCommand(%s) ok=false", f.engine)
	}
	f.sh(cmd)
}

func (f *discoveryFixture) seed(id string, mtime time.Time) {
	writeAt(f.t, filepath.Join(f.dir, id+f.suffix), mtime)
}

// waitSettled lets the (backgrounded) poll finish: either the sidecar
// appears, or the whole budget elapses.
func (f *discoveryFixture) waitSettled() (string, bool) {
	deadline := time.Now().Add(time.Duration(sessionDiscoveryAttempts)*time.Duration(sessionDiscoveryIntervalMS)*time.Millisecond + 800*time.Millisecond)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(f.sidecar); err == nil {
			return strings.TrimSpace(string(data)), true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return "", false
}

func withShortDiscoveryBudget(t *testing.T, attempts int) {
	t.Helper()
	old := sessionDiscoveryAttempts
	sessionDiscoveryAttempts = attempts
	t.Cleanup(func() { sessionDiscoveryAttempts = old })
}

// TestSessionDiscovery_AdoptsOnlyAFileCreatedAfterTheSnapshot is the
// regression test for the stale-id bug: the directory holds an older
// conversation when the run starts, the run's own file appears later, and
// the sidecar must name the NEW file, never the older one.
func TestSessionDiscovery_AdoptsOnlyAFileCreatedAfterTheSnapshot(t *testing.T) {
	for _, n := range []Name{NameClaude, NamePi} {
		t.Run(string(n), func(t *testing.T) {
			withShortDiscoveryBudget(t, 10)
			f := newDiscoveryFixture(t, n)
			f.seed("previous-conversation", time.Now().Add(-time.Hour))
			f.prepare()
			f.poll()
			// The engine creates its file a little after the poll started.
			time.Sleep(600 * time.Millisecond)
			f.seed("this-runs-session", time.Now())

			got, ok := f.waitSettled()
			if !ok || got != "this-runs-session" {
				t.Errorf("sidecar = %q (written=%v), want this-runs-session", got, ok)
			}
		})
	}
}

// TestSessionDiscovery_OlderOnlyYieldsNoID pins "never fall back to the
// newest older file": with only pre-existing conversations the sidecar is
// never written.
func TestSessionDiscovery_OlderOnlyYieldsNoID(t *testing.T) {
	for _, n := range []Name{NameClaude, NamePi} {
		t.Run(string(n), func(t *testing.T) {
			withShortDiscoveryBudget(t, 5)
			f := newDiscoveryFixture(t, n)
			f.seed("previous-a", time.Now().Add(-2*time.Hour))
			f.seed("previous-b", time.Now().Add(-time.Hour))
			f.prepare()
			f.poll()
			if got, ok := f.waitSettled(); ok {
				t.Errorf("sidecar written (%q) although no file was created by this run", got)
			}
		})
	}
}

// TestSessionDiscovery_PreviousConversationStillBeingAppendedIsNotAdopted: an
// older file that is modified after the snapshot is still not a NEW file.
func TestSessionDiscovery_PreviousConversationStillBeingAppendedIsNotAdopted(t *testing.T) {
	withShortDiscoveryBudget(t, 5)
	f := newDiscoveryFixture(t, NameClaude)
	f.seed("members-own", time.Now().Add(-time.Hour))
	f.prepare()
	f.seed("members-own", time.Now()) // appended to during the poll window
	f.poll()
	if got, ok := f.waitSettled(); ok {
		t.Errorf("adopted an older, re-touched conversation: %q", got)
	}
}

// TestSessionDiscovery_TwoNewFilesIsAmbiguousAndAdoptsNeither: two
// conversations created in the same window cannot be told apart from the
// directory, so neither is adopted.
func TestSessionDiscovery_TwoNewFilesIsAmbiguousAndAdoptsNeither(t *testing.T) {
	withShortDiscoveryBudget(t, 5)
	f := newDiscoveryFixture(t, NameClaude)
	f.prepare()
	f.seed("run-a", time.Now())
	f.seed("run-b", time.Now())
	f.poll()
	if got, ok := f.waitSettled(); ok {
		t.Errorf("adopted %q although two new files appeared", got)
	}
}

// TestSessionDiscovery_ConcurrentRunsDoNotAdoptEachOthersTranscript: run B
// starts (snapshots) after run A's transcript exists, so B must pick its own
// file, not A's, and A (which saw only its own file) picks A's.
func TestSessionDiscovery_ConcurrentRunsDoNotAdoptEachOthersTranscript(t *testing.T) {
	withShortDiscoveryBudget(t, 10)
	a := newDiscoveryFixture(t, NameClaude)
	b := &discoveryFixture{t: t, engine: NameClaude, home: a.home, cwd: a.cwd, dir: a.dir, suffix: a.suffix, sidecar: filepath.Join(t.TempDir(), "b.session")}

	a.prepare()
	a.poll()
	time.Sleep(300 * time.Millisecond)
	a.seed("session-of-a", time.Now())
	if got, ok := a.waitSettled(); !ok || got != "session-of-a" {
		t.Fatalf("run A sidecar = %q (written=%v), want session-of-a", got, ok)
	}

	b.prepare() // after A's file exists
	b.poll()
	time.Sleep(300 * time.Millisecond)
	b.seed("session-of-b", time.Now())
	if got, ok := b.waitSettled(); !ok || got != "session-of-b" {
		t.Errorf("run B sidecar = %q (written=%v), want session-of-b", got, ok)
	}
}

// TestSessionDiscovery_NoSnapshotFailsClosed: without the pre-launch snapshot
// old and new cannot be told apart, so nothing is written.
func TestSessionDiscovery_NoSnapshotFailsClosed(t *testing.T) {
	withShortDiscoveryBudget(t, 3)
	f := newDiscoveryFixture(t, NameClaude)
	f.seed("whatever", time.Now())
	f.poll()
	if got, ok := f.waitSettled(); ok {
		t.Errorf("sidecar written without a snapshot: %q", got)
	}
}

// TestSessionDiscovery_ClaudeIgnoresNonTranscriptEntries: only *.jsonl
// entries count (the project directory also holds per-session directories).
func TestSessionDiscovery_ClaudeIgnoresNonTranscriptEntries(t *testing.T) {
	withShortDiscoveryBudget(t, 10)
	f := newDiscoveryFixture(t, NameClaude)
	f.prepare()
	f.poll()
	mustMkdirAll(t, filepath.Join(f.dir, "some-subdir"))
	time.Sleep(400 * time.Millisecond)
	f.seed("real-session", time.Now())
	if got, ok := f.waitSettled(); !ok || got != "real-session" {
		t.Errorf("sidecar = %q (written=%v), want real-session", got, ok)
	}
}

// TestSessionDiscovery_MembersSessionFirstThenOwnIsAmbiguous is the
// interleaved ordering: a member's interactive transcript appears before this
// run's own. The poll must NOT adopt the first one it sees; with two new
// entries at the end nothing is written.
func TestSessionDiscovery_MembersSessionFirstThenOwnIsAmbiguous(t *testing.T) {
	for _, n := range []Name{NameClaude, NamePi} {
		t.Run(string(n), func(t *testing.T) {
			withShortDiscoveryBudget(t, 10)
			f := newDiscoveryFixture(t, n)
			f.prepare()
			f.poll()
			time.Sleep(300 * time.Millisecond)
			f.seed("members-interactive", time.Now())
			time.Sleep(700 * time.Millisecond)
			f.seed("this-runs-transcript", time.Now())
			if got, ok := f.waitSettled(); ok {
				t.Errorf("adopted %q although two new transcripts appeared", got)
			}
		})
	}
}

// TestSessionDiscovery_OwnFirstThenMembersSessionIsAmbiguous: the opposite
// order is equally undecidable from the directory (documented as ambiguous).
func TestSessionDiscovery_OwnFirstThenMembersSessionIsAmbiguous(t *testing.T) {
	withShortDiscoveryBudget(t, 10)
	f := newDiscoveryFixture(t, NameClaude)
	f.prepare()
	f.poll()
	time.Sleep(300 * time.Millisecond)
	f.seed("this-runs-transcript", time.Now())
	time.Sleep(700 * time.Millisecond)
	f.seed("members-interactive", time.Now())
	if got, ok := f.waitSettled(); ok {
		t.Errorf("adopted %q although two new transcripts appeared", got)
	}
}

// TestSessionDiscovery_StopsEarlyWhenTheRunHasExited: the exit sidecar ends
// the wait, so a short run is evaluated promptly rather than after the budget.
func TestSessionDiscovery_StopsEarlyWhenTheRunHasExited(t *testing.T) {
	withShortDiscoveryBudget(t, 300) // 60 s if the exit sidecar were ignored
	f := newDiscoveryFixture(t, NameClaude)
	f.prepare()
	f.seed("only-new", time.Now())
	writeAt(t, strings.TrimSuffix(f.sidecar, ".session")+".exit", time.Now())
	start := time.Now()
	f.poll()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(f.sidecar); err == nil {
			if strings.TrimSpace(string(data)) != "only-new" {
				t.Fatalf("sidecar = %q", data)
			}
			if time.Since(start) > 3*time.Second {
				t.Errorf("took %v; exit sidecar was ignored", time.Since(start))
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("sidecar not written after the run exited")
}

// TestSessionDiscoveryPrepareCommand_UnknownEngine: same fail-closed rule as
// the poll command.
func TestSessionDiscoveryPrepareCommand_UnknownEngine(t *testing.T) {
	if _, ok := SessionDiscoveryPrepareCommand(Name("made-up"), "/h", "/h", "/tmp/x.session"); ok {
		t.Error("an unknown engine should report ok=false")
	}
}

func mustMkdirAll(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
}

func writeAt(t *testing.T, path string, mtime time.Time) {
	t.Helper()
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}
