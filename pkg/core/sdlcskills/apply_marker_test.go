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
	for _, tc := range []struct {
		name, marker string
		want         ApplyMarkerStatus
	}{
		{"absent", "", ApplyMarkerAbsent},
		{"held", `{"version":1,"started_at":1799999990,"expires_at":1800000300}`, ApplyMarkerHeld},
		{"lapsed", `{"version":1,"started_at":1799990000,"expires_at":1799999999}`, ApplyMarkerStale},
		{"expires now", `{"version":1,"started_at":1799990000,"expires_at":1800000000}`, ApplyMarkerStale},
		{"beyond a lease", `{"version":1,"started_at":1800000000,"expires_at":1800003600}`, ApplyMarkerStale},
		{"not json", `garbage`, ApplyMarkerStale},
		{"no expiry", `{"version":1,"started_at":1800000000}`, ApplyMarkerStale},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := ParseApplyMarkerCheck("1800000000\n" + tc.marker + "\n")
			if err != nil {
				t.Fatal(err)
			}
			if c.Status != tc.want || c.Now != now {
				t.Fatalf("status = %v (now %d), want %v", c.Status, c.Now, tc.want)
			}
			if (c.Status == ApplyMarkerStale) != (c.Why != "") {
				t.Errorf("why = %q for status %v", c.Why, c.Status)
			}
		})
	}
	if _, err := ParseApplyMarkerCheck("not a clock\n"); err == nil {
		t.Error("an unreadable box clock must be an error")
	}
	if !strings.Contains(ApplyMarkerWriteScript(0, 90*time.Second), "now + 90") {
		t.Error("the lease is not the one asked for")
	}
}

func TestApplyMarkerClearStaleScript_KeepsANewerMarker(t *testing.T) {
	home := t.TempDir()
	runAsOwner(t, home, ApplyMarkerWriteScript(0, ApplyMarkerLease))
	runAsOwner(t, home, ApplyMarkerClearStaleScript(`{"version":1,"started_at":1,"expires_at":2}`))
	if c, _ := ParseApplyMarkerCheck(runAsOwner(t, home, ApplyMarkerCheckScript())); c.Status != ApplyMarkerHeld {
		t.Fatalf("a marker other than the stale one read must survive: %+v", c)
	}
}
