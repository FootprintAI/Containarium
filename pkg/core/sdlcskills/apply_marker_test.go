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
		t.Error("an id that is not inode:mtime:size must not reach a script")
	}
}

// checkAndClear runs a check and, for a stale marker, the clear, reporting
// whether the clear removed it.
func checkAndClear(t *testing.T, home string) (ApplyMarkerCheck, bool) {
	t.Helper()
	c, err := ParseApplyMarkerCheck(runAsOwner(t, home, ApplyMarkerCheckScript()))
	if err != nil {
		t.Fatal(err)
	}
	if c.Status != ApplyMarkerStale {
		return c, false
	}
	script, err := ApplyMarkerClearStaleScript(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	removed, err := ParseApplyMarkerCleared(runAsOwner(t, home, script))
	if err != nil {
		t.Fatal(err)
	}
	return c, removed
}

// Whatever the box user left in the marker's place, a stale one is removed by
// one clear and the next check finds nothing: never refused forever, never a
// "cleared" warning on every run.
func TestApplyMarker_StaleMarkersOfAnyContentAreRemoved(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content []byte
		mode    os.FileMode
	}{
		{"NUL byte", []byte("{\"version\":1,\x00}\n"), 0o644},
		{"oversized", []byte(strings.Repeat("{", 256<<10)), 0o644},
		{"leading whitespace, lapsed", []byte("\n   {\"version\":1,\"started_at\":1,\"expires_at\":2}\n"), 0o644},
		{"unreadable", []byte(`{"version":1,"started_at":1,"expires_at":2}`), 0o000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.mode == 0 && os.Geteuid() == 0 {
				t.Skip("root reads a mode-000 file")
			}
			home := t.TempDir()
			f := filepath.Join(home, ".claude", "skills", ApplyMarkerFile)
			if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(f, tc.content, tc.mode); err != nil {
				t.Fatal(err)
			}
			c, removed := checkAndClear(t, home)
			if c.Status != ApplyMarkerStale || !removed {
				t.Fatalf("check = %+v, removed = %v; want a stale marker removed", c, removed)
			}
			if c, _ := checkAndClear(t, home); c.Status != ApplyMarkerAbsent {
				t.Fatalf("after the clear: %+v", c)
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
	removed, err := ParseApplyMarkerCleared(runAsOwner(t, home, script))
	if err != nil || removed {
		t.Fatalf("removed = %v, %v; the clear must keep a marker other than the stale one it read", removed, err)
	}
	if c, _ := ParseApplyMarkerCheck(runAsOwner(t, home, ApplyMarkerCheckScript())); c.Status != ApplyMarkerHeld {
		t.Fatalf("the new apply's marker must survive: %+v", c)
	}
}
