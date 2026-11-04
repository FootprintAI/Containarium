package sdlcskills

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func runAsOwner(t *testing.T, home, script string) string {
	t.Helper()
	cmd := exec.Command("sh", "-c", script)
	cmd.Env = append(os.Environ(), "HOME="+home)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("script failed: %v: %s", err, out)
	}
	return string(out)
}

func TestApplyMarker_TakeCheckRenewRemove(t *testing.T) {
	for _, tc := range []struct {
		name   string
		setup  func(home string)
		levels int
	}{
		{"skills dir exists", func(h string) { _ = os.MkdirAll(filepath.Join(h, ".claude", "skills"), 0o755) }, 0},
		{"only ~/.claude exists", func(h string) { _ = os.MkdirAll(filepath.Join(h, ".claude"), 0o755) }, 1},
		{"neither exists", func(string) {}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			tc.setup(home)
			taken, err := ParseApplyMarkerTaken(runAsOwner(t, home, ApplyMarkerWriteScript(0, ApplyMarkerLease)))
			if err != nil {
				t.Fatal(err)
			}
			if taken.CreatedLevels != tc.levels {
				t.Errorf("created levels = %d, want %d", taken.CreatedLevels, tc.levels)
			}
			c, err := ParseApplyMarkerCheck(runAsOwner(t, home, ApplyMarkerCheckScript()))
			if err != nil || c.Status != ApplyMarkerHeld || c.Marker.StartedAt != taken.StartedAt {
				t.Fatalf("check = %+v, %v; want held from %d", c, err, taken.StartedAt)
			}
			// A renewal keeps the start.
			renewed, err := ParseApplyMarkerTaken(runAsOwner(t, home, ApplyMarkerWriteScript(taken.StartedAt, ApplyMarkerLease)))
			if err != nil || renewed.StartedAt != taken.StartedAt {
				t.Fatalf("renewal = %+v, %v", renewed, err)
			}
			runAsOwner(t, home, ApplyMarkerRemoveScript(taken.CreatedLevels))
			if c, _ := ParseApplyMarkerCheck(runAsOwner(t, home, ApplyMarkerCheckScript())); c.Status != ApplyMarkerAbsent {
				t.Fatalf("after remove: %+v", c)
			}
			// Whatever existed before is still there; what the take created is gone.
			for level, dir := range []string{filepath.Join(home, ".claude", "skills"), filepath.Join(home, ".claude")} {
				_, err := os.Stat(dir)
				if existedBefore := tc.levels <= level; existedBefore != (err == nil) {
					t.Errorf("%s: exists = %v, want %v", dir, err == nil, existedBefore)
				}
			}
		})
	}
}

func TestApplyMarker_RemoveKeepsAFilledSkillsDir(t *testing.T) {
	home := t.TempDir()
	taken, err := ParseApplyMarkerTaken(runAsOwner(t, home, ApplyMarkerWriteScript(0, ApplyMarkerLease)))
	if err != nil {
		t.Fatal(err)
	}
	skill := filepath.Join(home, ".claude", "skills", "qa-unit-test", "SKILL.md")
	if err := os.MkdirAll(filepath.Dir(skill), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(skill, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	runAsOwner(t, home, ApplyMarkerRemoveScript(taken.CreatedLevels))
	if _, err := os.Stat(skill); err != nil {
		t.Fatalf("an installed skill must survive the marker's removal: %v", err)
	}
}

func TestParseApplyMarkerCheck(t *testing.T) {
	const now = 1_800_000_000
	held := `{"version":1,"started_at":1799999990,"expires_at":1800000300}`
	for _, tc := range []struct {
		name, state, marker string
		want                ApplyMarkerStatus
	}{
		{"absent", "absent", "", ApplyMarkerAbsent},
		{"held", "present 7:1:60", held, ApplyMarkerHeld},
		{"held, leading whitespace", "present 7:1:62", "\n  " + held, ApplyMarkerHeld},
		{"lapsed", "present 7:1:60", `{"version":1,"started_at":1799990000,"expires_at":1799999999}`, ApplyMarkerStale},
		{"expires now", "present 7:1:60", `{"version":1,"started_at":1799990000,"expires_at":1800000000}`, ApplyMarkerStale},
		{"beyond a lease", "present 7:1:60", `{"version":1,"started_at":1800000000,"expires_at":1800003600}`, ApplyMarkerStale},
		{"not json", "present 7:1:7", `garbage`, ApplyMarkerStale},
		{"NUL byte", "present 7:1:3", "{\x00}", ApplyMarkerStale},
		{"no expiry", "present 7:1:40", `{"version":1,"started_at":1800000000}`, ApplyMarkerStale},
		{"oversized", "present 7:1:9000", strings.Repeat(" ", ApplyMarkerReadLimit) + held, ApplyMarkerStale},
		{"unreadable", "unreadable 7:1:60", "", ApplyMarkerStale},
		{"time before 1970", "present 7:-315619200:60", `garbage`, ApplyMarkerStale},
		{"time far ahead", "unreadable 7:253370764800:60", "", ApplyMarkerStale},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := ParseApplyMarkerCheck("1800000000\n" + tc.state + "\n" + tc.marker)
			if err != nil {
				t.Fatal(err)
			}
			if c.Status != tc.want || c.Now != now {
				t.Fatalf("status = %v (now %d), want %v", c.Status, c.Now, tc.want)
			}
			if (c.Status == ApplyMarkerStale) != (c.Why != "") {
				t.Errorf("why = %q for status %v", c.Why, c.Status)
			}
			if f := strings.Fields(tc.state); len(f) == 2 && c.ID != f[1] {
				t.Errorf("id = %q, want %q", c.ID, f[1])
			}
		})
	}
	for _, bad := range []string{"not a clock\nabsent\n", "1800000000\n", "1800000000\nsomething\n", "1800000000\npresent ;rm\n{}"} {
		if _, err := ParseApplyMarkerCheck(bad); err == nil {
			t.Errorf("ParseApplyMarkerCheck(%q) must be an error", bad)
		}
	}
	if !strings.Contains(ApplyMarkerWriteScript(0, 90*time.Second), "now + 90") {
		t.Error("the lease is not the one asked for")
	}
	if _, err := ApplyMarkerClearStaleScript("1; rm -rf ~"); err == nil {
		t.Error("an id that is not inode:time:size must not reach a script")
	}
}

// The identity is interpolated into the clear script, so only digits, two
// colons and a sign on the time field get through, as the check and as the
// clear's argument.
func TestApplyMarkerIdentity_OnlyDigitsColonsAndASignedTime(t *testing.T) {
	for _, ok := range []string{"7:1:60", "7:-315619200:60", "123456789:253370764800:0"} {
		if _, err := ApplyMarkerClearStaleScript(ok); err != nil {
			t.Errorf("ApplyMarkerClearStaleScript(%q): %v", ok, err)
		}
	}
	for _, bad := range []string{
		"1; rm -rf ~", "1:-2;rm -rf ~:3", "1:2:3'; rm -rf ~; '", "1:2:3\n", "1:2:3\nrm -rf ~", " 1:2:3",
		"-1:2:3", "1:2:-3", "1:--2:3", "1:+2:3", "1:-:3", "1::3", "1:2", "1:2:3:4", "$(id):1:2", "`id`:1:2", "",
	} {
		if _, err := ApplyMarkerClearStaleScript(bad); err == nil {
			t.Errorf("ApplyMarkerClearStaleScript(%q) must be refused", bad)
		}
		if _, err := ParseApplyMarkerCheck("1800000000\npresent " + bad + "\n{}"); err == nil && !strings.ContainsAny(bad, " \n") {
			t.Errorf("ParseApplyMarkerCheck with id %q must be an error", bad)
		}
	}
	// Run as a script, a refused id never executes: the clear of a hostile id
	// does not exist, and the clear of a valid one only compares it.
	home := t.TempDir()
	canary := filepath.Join(home, "canary")
	writeFile(t, canary, "x", 0o644)
	script, err := ApplyMarkerClearStaleScript("7:-1:60")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(runAsOwner(t, home, script)); got != "kept" {
		t.Fatalf("clear with no marker = %q, want kept", got)
	}
	if _, err := os.Stat(canary); err != nil {
		t.Fatalf("the clear touched a file outside the marker path: %v", err)
	}
}

// checkAndClear runs a check and, for a stale marker, the clear, reporting
// whether the clear removed it.
func checkAndClear(t *testing.T, home string) (ApplyMarkerCheck, ApplyMarkerClearResult) {
	t.Helper()
	c, err := ParseApplyMarkerCheck(runAsOwner(t, home, ApplyMarkerCheckScript()))
	if err != nil {
		t.Fatal(err)
	}
	if c.Status != ApplyMarkerStale {
		return c, ApplyMarkerClearKept
	}
	script, err := ApplyMarkerClearStaleScript(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	cleared, err := ParseApplyMarkerCleared(runAsOwner(t, home, script))
	if err != nil {
		t.Fatal(err)
	}
	return c, cleared
}

// writeFile writes content at f with mode.
func writeFile(t *testing.T, f, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

// outsideDir makes a directory beside the skills tree holding one file, keep:
// a symlink to it at the marker path must be removed as a link, never
// followed.
func outsideDir(t *testing.T, home string) string {
	t.Helper()
	dir := filepath.Join(home, "outside")
	writeFile(t, filepath.Join(dir, "keep"), "x", 0o644)
	return dir
}

// assertOnlyEntries fails when dir holds anything but want: a clear or a
// write must leave no capture or temporary file behind.
func assertOnlyEntries(t *testing.T, dir string, want ...string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range entries {
		got = append(got, e.Name())
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("%s holds %v, want %v", dir, got, want)
	}
}

// Whatever the box user left in the marker's place, a stale one is removed by
// one clear and the next check finds nothing: never refused forever, never a
// "cleared" warning on every run. Nothing outside the marker path is touched
// (a symlink is removed as a link, never followed), and the clear leaves no
// capture file behind.
func TestApplyMarker_StaleMarkersOfAnyContentAreRemoved(t *testing.T) {
	const lapsed = `{"version":1,"started_at":1,"expires_at":2}`
	dated := func(when time.Time) func(t *testing.T, home, f string) {
		return func(t *testing.T, _, f string) {
			writeFile(t, f, lapsed, 0o644)
			if err := os.Chtimes(f, when, when); err != nil {
				t.Fatal(err)
			}
		}
	}
	mkdir := func(mode os.FileMode) func(t *testing.T, home, f string) {
		return func(t *testing.T, _, f string) {
			if err := os.Mkdir(f, mode); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, tc := range []struct {
		name string
		// setup puts something at the marker path f in home.
		setup func(t *testing.T, home, f string)
		// nonRoot: the case means nothing to root, which reads anything.
		nonRoot bool
	}{
		{name: "NUL byte", setup: func(t *testing.T, _, f string) { writeFile(t, f, "{\"version\":1,\x00}\n", 0o644) }},
		{name: "oversized", setup: func(t *testing.T, _, f string) { writeFile(t, f, strings.Repeat("{", 256<<10), 0o644) }},
		{name: "leading whitespace, lapsed", setup: func(t *testing.T, _, f string) { writeFile(t, f, "\n   "+lapsed+"\n", 0o644) }},
		{name: "unreadable", nonRoot: true, setup: func(t *testing.T, _, f string) { writeFile(t, f, lapsed, 0o000) }},
		{name: "mtime before 1970", setup: dated(time.Date(1960, 1, 1, 0, 0, 0, 0, time.UTC))},
		{name: "mtime in year 9999", setup: dated(time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC))},
		{name: "empty directory", setup: mkdir(0o755)},
		{name: "read-only empty directory", setup: mkdir(0o555)},
		{name: "directory with content", setup: func(t *testing.T, home, f string) {
			writeFile(t, filepath.Join(f, "sub", "x"), "x", 0o644)
			// A symlink inside the directory is removed, not its target.
			if err := os.Symlink(outsideDir(t, home), filepath.Join(f, "link")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "symlink to a directory", setup: func(t *testing.T, home, f string) {
			if err := os.Symlink(outsideDir(t, home), f); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "symlink to a file", setup: func(t *testing.T, home, f string) {
			if err := os.Symlink(filepath.Join(outsideDir(t, home), "keep"), f); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "dangling symlink", setup: func(t *testing.T, home, f string) {
			if err := os.Symlink(filepath.Join(home, "nowhere"), f); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.nonRoot && os.Geteuid() == 0 {
				t.Skip("root reads a mode-000 file")
			}
			home := t.TempDir()
			skills := filepath.Join(home, ".claude", "skills")
			f := filepath.Join(skills, ApplyMarkerFile)
			if err := os.MkdirAll(skills, 0o755); err != nil {
				t.Fatal(err)
			}
			tc.setup(t, home, f)
			c, cleared := checkAndClear(t, home)
			if c.Status != ApplyMarkerStale || cleared != ApplyMarkerClearRemoved {
				t.Fatalf("check = %+v, clear = %v; want a stale marker removed", c, cleared)
			}
			if c, _ := checkAndClear(t, home); c.Status != ApplyMarkerAbsent {
				t.Fatalf("after the clear: %+v", c)
			}
			assertOnlyEntries(t, skills)
			if _, err := os.Stat(filepath.Join(home, "outside")); err == nil {
				assertOnlyEntries(t, filepath.Join(home, "outside"), "keep")
			}
		})
	}
}

// A marker path the box user cannot clear (here: a stale marker in a
// read-only skills directory) is reported as failed, not as kept: kept means
// another marker took its place, which is a different refusal.
func TestApplyMarkerClearStaleScript_ReportsAMarkerItCannotRemove(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes a read-only directory")
	}
	home := t.TempDir()
	skills := filepath.Join(home, ".claude", "skills")
	writeFile(t, filepath.Join(skills, ApplyMarkerFile), "junk", 0o644)
	if err := os.Chmod(skills, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(skills, 0o755) })
	c, cleared := checkAndClear(t, home)
	if c.Status != ApplyMarkerStale || cleared != ApplyMarkerClearFailed {
		t.Fatalf("check = %+v, clear = %v; want a stale marker the clear failed to remove", c, cleared)
	}
}

// A new apply's marker that lands between the clear's identity check and its
// capture of the file is put back, not removed, and the clear reports it kept.
func TestApplyMarkerClearStaleScript_PutsBackAMarkerCapturedByMistake(t *testing.T) {
	home := t.TempDir()
	skills := filepath.Join(home, ".claude", "skills")
	writeFile(t, filepath.Join(skills, ApplyMarkerFile), `{"version":1,"started_at":1,"expires_at":2}`, 0o644)
	c, err := ParseApplyMarkerCheck(runAsOwner(t, home, ApplyMarkerCheckScript()))
	if err != nil || c.Status != ApplyMarkerStale {
		t.Fatalf("check = %+v, %v", c, err)
	}
	// The new apply's write runs inside the clear, after its identity check.
	script, err := applyMarkerClearStaleScript(c.ID, "( "+ApplyMarkerWriteScript(0, ApplyMarkerLease)+") >/dev/null\n")
	if err != nil {
		t.Fatal(err)
	}
	cleared, err := ParseApplyMarkerCleared(runAsOwner(t, home, script))
	if err != nil || cleared != ApplyMarkerClearKept {
		t.Fatalf("clear = %v, %v; want kept", cleared, err)
	}
	if c, _ := ParseApplyMarkerCheck(runAsOwner(t, home, ApplyMarkerCheckScript())); c.Status != ApplyMarkerHeld {
		t.Fatalf("the new apply's marker must be put back: %+v", c)
	}
	assertOnlyEntries(t, skills, ApplyMarkerFile)
}

// The apply's write replaces whatever is at the marker path, so the marker it
// holds is the one runs read: a directory, or a symlink to one, is not written
// into, and a symlink at the temporary path is not followed.
func TestApplyMarkerWriteScript_ReplacesANonRegularMarkerPath(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, outside, f string)
	}{
		{"directory", func(t *testing.T, _, f string) { writeFile(t, filepath.Join(f, "sub", "x"), "x", 0o644) }},
		{"empty directory", func(t *testing.T, _, f string) {
			if err := os.Mkdir(f, 0o755); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink to a directory", func(t *testing.T, outside, f string) {
			if err := os.Symlink(outside, f); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink at the temporary path", func(t *testing.T, outside, f string) {
			if err := os.Symlink(filepath.Join(outside, "keep"), f+".tmp"); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			skills := filepath.Join(home, ".claude", "skills")
			if err := os.MkdirAll(skills, 0o755); err != nil {
				t.Fatal(err)
			}
			outside := outsideDir(t, home)
			f := filepath.Join(skills, ApplyMarkerFile)
			tc.setup(t, outside, f)
			if _, err := ParseApplyMarkerTaken(runAsOwner(t, home, ApplyMarkerWriteScript(0, ApplyMarkerLease))); err != nil {
				t.Fatal(err)
			}
			if c, err := ParseApplyMarkerCheck(runAsOwner(t, home, ApplyMarkerCheckScript())); err != nil || c.Status != ApplyMarkerHeld {
				t.Fatalf("check = %+v, %v; want the apply's marker held", c, err)
			}
			if fi, err := os.Lstat(f); err != nil || !fi.Mode().IsRegular() {
				t.Fatalf("the marker path must be a regular file: %v, %v", fi, err)
			}
			assertOnlyEntries(t, skills, ApplyMarkerFile)
			assertOnlyEntries(t, outside, "keep")
			if b, err := os.ReadFile(filepath.Join(outside, "keep")); err != nil || string(b) != "x" {
				t.Fatalf("a file outside the marker path was changed: %q, %v", b, err)
			}
		})
	}
}

func TestApplyMarkerClearStaleScript_KeepsANewerMarker(t *testing.T) {
	home := t.TempDir()
	f := filepath.Join(home, ".claude", "skills", ApplyMarkerFile)
	if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f, []byte(`{"version":1,"started_at":1,"expires_at":2}`), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := ParseApplyMarkerCheck(runAsOwner(t, home, ApplyMarkerCheckScript()))
	if err != nil || c.Status != ApplyMarkerStale {
		t.Fatalf("check = %+v, %v", c, err)
	}
	// A new apply takes the marker between the check and the clear.
	runAsOwner(t, home, ApplyMarkerWriteScript(0, ApplyMarkerLease))
	script, err := ApplyMarkerClearStaleScript(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	cleared, err := ParseApplyMarkerCleared(runAsOwner(t, home, script))
	if err != nil || cleared != ApplyMarkerClearKept {
		t.Fatalf("clear = %v, %v; the clear must keep a marker other than the stale one it read", cleared, err)
	}
	if c, _ := ParseApplyMarkerCheck(runAsOwner(t, home, ApplyMarkerCheckScript())); c.Status != ApplyMarkerHeld {
		t.Fatalf("the new apply's marker must survive: %+v", c)
	}
}
