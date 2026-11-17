package guardraildropin

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

const (
	testBox  = "alice-container"
	testUser = "alice"
)

var testNow = time.Unix(1_800_000_000, 0)

var testBinary = []byte("pinned hook binary")

// newTestChecker returns a checker over a box that has the drop-in and
// binary installed and nothing wrong with it.
func newTestChecker(t *testing.T) (*checker, *fakeBox) {
	t.Helper()
	box := newFakeBox()
	c, err := newChecker(box, Options{}.withDefaults(), bytesBinary(testBinary))
	if err != nil {
		t.Fatal(err)
	}
	c.clock = func() time.Time { return testNow }
	if err := c.install(testBox); err != nil {
		t.Fatal(err)
	}
	return c, box
}

func epoch(d time.Duration) string { return strconv.FormatInt(testNow.Add(d).Unix(), 10) }

func TestCheck(t *testing.T) {
	const disable = `{"disableAllHooks": true}`
	tests := []struct {
		name  string
		setup func(*fakeBox)
		want  pb.GuardrailHookCoverage
	}{
		{"installed and healthy", func(*fakeBox) {}, pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_COVERED},
		{"drop-in missing", func(b *fakeBox) { delete(b.files, DropInPath) }, pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_NOT_INSTALLED},
		{"hook binary missing", func(b *fakeBox) { delete(b.files, HookBinaryPath) }, pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_NOT_INSTALLED},
		{"drop-in changed", func(b *fakeBox) { b.files[DropInPath] = []byte(`{}`) }, pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_TAMPERED},
		{"hook binary changed", func(b *fakeBox) { b.files[HookBinaryPath] = []byte("#!/bin/true") }, pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_TAMPERED},
		{"second drop-in sorted before ours sets disableAllHooks", func(b *fakeBox) { b.files[DropInDir+"/00-first.json"] = []byte(disable) }, pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_TAMPERED},
		{"second drop-in sorted after ours sets disableAllHooks", func(b *fakeBox) { b.files[DropInDir+"/zz-last.json"] = []byte(disable) }, pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_TAMPERED},
		{"managed-settings.json sets disableAllHooks", func(b *fakeBox) { b.files[ManagedSettingsDir+"/managed-settings.json"] = []byte(disable) }, pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_TAMPERED},
		{"unparseable managed file naming disableAllHooks", func(b *fakeBox) { b.files[DropInDir+"/x.json"] = []byte(`{"disableAllHooks": tru`) }, pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_TAMPERED},
		{"another managed file that leaves hooks on", func(b *fakeBox) {
			b.files[DropInDir+"/x.json"] = []byte(`{"disableAllHooks": false, "env": {"A": "b"}}`)
		}, pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_COVERED},
		{"engine stopped", func(b *fakeBox) { b.engineActive = false }, pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_ENGINE_NOT_RUNNING},
		{"client older than the minimum", func(b *fakeBox) { b.version = "2.1.298 (Claude Code)" }, pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_CLIENT_TOO_OLD},
		{"client newer than the minimum", func(b *fakeBox) { b.version = "2.2.0 (Claude Code)" }, pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_COVERED},
		{"client version unreadable", func(b *fakeBox) { b.version = "garbage" }, pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_UNKNOWN},
		{"no client installed", func(b *fakeBox) { b.claudeStat = "" }, pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_COVERED},
		{"long-running client with no stamp", func(b *fakeBox) { b.ps = "  41 900 claude\n   1 99999 systemd\n" }, pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_HOOKS_NOT_FIRING},
		{"long-running client whose stamp predates it (pid reuse)", func(b *fakeBox) {
			b.ps = "41 900 claude\n"
			b.stamps["41"] = epoch(-2 * time.Hour)
		}, pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_HOOKS_NOT_FIRING},
		{"long-running client with a stamp since it started", func(b *fakeBox) {
			b.ps = "41 900 claude\n"
			b.stamps["41"] = epoch(-10 * time.Minute)
		}, pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_COVERED},
		{"client younger than the grace period, no stamp yet", func(b *fakeBox) { b.ps = "41 30 claude\n" }, pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_COVERED},
		{"another process named differently", func(b *fakeBox) { b.ps = "41 900 claude-helper\n" }, pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_COVERED},
		{"root exec fails", func(b *fakeBox) { b.execErr = errors.New("box unreachable") }, pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_UNKNOWN},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, box := newTestChecker(t)
			tc.setup(box)
			got := c.check(testBox, testUser)
			if got.Coverage != tc.want {
				t.Fatalf("coverage = %v (%s), want %v", got.Coverage, got.Detail, tc.want)
			}
			if got.Detail == "" || !got.CheckedAt.Equal(testNow) {
				t.Errorf("want a detail and CheckedAt=now, got %+v", got)
			}
			if strings.Contains(got.Detail, "disableAllHooks\": true") {
				t.Errorf("detail must not carry file contents: %q", got.Detail)
			}
		})
	}
}

// The client version is read as the box user, and only when the binary
// changed: a check must not start the client on every tick.
func TestCheckReadsVersionOnlyWhenBinaryChanged(t *testing.T) {
	c, box := newTestChecker(t)
	for i := 0; i < 3; i++ {
		if got := c.check(testBox, testUser); got.ClientVersion != "2.1.326" {
			t.Fatalf("client version = %q", got.ClientVersion)
		}
	}
	if box.versionCalls != 1 {
		t.Fatalf("version read %d times for an unchanged binary, want 1", box.versionCalls)
	}
	box.claudeStat = "12:1700009999:300"
	box.version = "2.1.400 (Claude Code)"
	if got := c.check(testBox, testUser); got.ClientVersion != "2.1.400" || box.versionCalls != 2 {
		t.Fatalf("after an upgrade: version %q, %d reads", got.ClientVersion, box.versionCalls)
	}
}

func TestVersionAtLeast(t *testing.T) {
	tests := []struct {
		have, min string
		want      bool
	}{
		{"2.1.326", "2.1.326", true}, {"2.1.327", "2.1.326", true}, {"2.1.325", "2.1.326", false},
		{"2.2", "2.1.326", true}, {"2.1", "2.1.326", false}, {"10.0.0", "2.1.326", true}, {"1.9.999", "2.1.326", false},
	}
	for _, tc := range tests {
		got, err := versionAtLeast(tc.have, tc.min)
		if err != nil || got != tc.want {
			t.Errorf("versionAtLeast(%q, %q) = %v, %v; want %v", tc.have, tc.min, got, err, tc.want)
		}
	}
	if _, err := versionAtLeast("x", "2.1.326"); err == nil {
		t.Error("want an error for a non-numeric version")
	}
}

// The binary goes in before the drop-in that points at it, and comes out
// after it: the drop-in never names a binary that is not there.
func TestInstallAndRemoveOrder(t *testing.T) {
	c, box := newTestChecker(t)
	writes := filterLog(box.log, "write ")
	if len(writes) != 2 || writes[0] != "write "+HookBinaryPath || writes[1] != "write "+DropInPath {
		t.Fatalf("install order = %v", writes)
	}
	// A second install of the same pinned binary does not push it again.
	box.log = nil
	if err := c.install(testBox); err != nil {
		t.Fatal(err)
	}
	if w := filterLog(box.log, "write "); len(w) != 1 || w[0] != "write "+DropInPath {
		t.Fatalf("re-install wrote %v, want only the drop-in", w)
	}
	// Break-glass: with the binary already gone, remove still clears the
	// drop-in, so a blocking hook stops blocking.
	delete(box.files, HookBinaryPath)
	if err := c.remove(testBox); err != nil {
		t.Fatal(err)
	}
	if len(box.files) != 0 {
		t.Fatalf("files left after remove: %v", box.files)
	}
}

func filterLog(log []string, prefix string) []string {
	var out []string
	for _, l := range log {
		if strings.HasPrefix(l, prefix) {
			out = append(out, l)
		}
	}
	return out
}
