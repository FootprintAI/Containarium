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

const (
	covered       = pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_COVERED
	notInstalledC = pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_NOT_INSTALLED
	tamperedC     = pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_TAMPERED
	tooOld        = pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_CLIENT_TOO_OLD
	engineDown    = pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_ENGINE_NOT_RUNNING
	notFiring     = pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_HOOKS_NOT_FIRING
	unknownC      = pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_UNKNOWN
	featureOff    = pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_FEATURE_OFF
)

// newTestChecker returns a checker over a box that has the drop-in and
// binary installed and nothing wrong with it.
func newTestChecker(t *testing.T) (*checker, *fakeBox) {
	t.Helper()
	box := newFakeBox()
	c, err := newChecker(box, operatorEngine.withDefaults(), bytesBinary(testBinary))
	if err != nil {
		t.Fatal(err)
	}
	c.clock = func() time.Time { return testNow }
	if err := c.install(testBox, testUser); err != nil {
		t.Fatal(err)
	}
	return c, box
}

func mustCurrent(t *testing.T, c *checker) installed {
	t.Helper()
	cur, err := c.current()
	if err != nil {
		t.Fatal(err)
	}
	return cur
}

func epoch(d time.Duration) string { return strconv.FormatInt(testNow.Add(d).Unix(), 10) }

func TestCheck(t *testing.T) {
	const disable = `{"disableAllHooks": true}`
	tests := []struct {
		name  string
		setup func(*fakeBox)
		want  pb.GuardrailHookCoverage
	}{
		{"installed and healthy", func(*fakeBox) {}, covered},
		{"drop-in missing", func(b *fakeBox) { delete(b.files, DropInPath) }, notInstalledC},
		{"hook binary missing", func(b *fakeBox) { delete(b.files, HookBinaryPath) }, notInstalledC},
		{"drop-in changed", func(b *fakeBox) { b.files[DropInPath] = []byte(`{}`) }, tamperedC},
		{"hook binary changed", func(b *fakeBox) { b.files[HookBinaryPath] = []byte("#!/bin/true") }, tamperedC},

		// Ownership and type are part of "present and unchanged".
		{"drop-in replaced by a symlink", func(b *fakeBox) { b.meta[DropInPath] = "symbolic link|0|777" }, tamperedC},
		{"hook binary replaced by a FIFO", func(b *fakeBox) { b.meta[HookBinaryPath] = "fifo|0|644" }, tamperedC},
		{"hook binary owned by the box user", func(b *fakeBox) { b.meta[HookBinaryPath] = "regular file|1000|755" }, tamperedC},
		{"drop-in writable by group", func(b *fakeBox) { b.meta[DropInPath] = "regular file|0|664" }, tamperedC},
		{"binary directory owned by the box user", func(b *fakeBox) { b.meta[HookBinaryDir] = "directory|1000|755" }, tamperedC},
		{"drop-in directory writable by others", func(b *fakeBox) { b.meta[DropInDir] = "directory|0|777" }, tamperedC},
		{"managed settings directory is a symlink", func(b *fakeBox) { b.meta[ManagedSettingsDir] = "symbolic link|0|777" }, tamperedC},

		{"second drop-in sorted before ours sets disableAllHooks", func(b *fakeBox) { b.files[DropInDir+"/00-first.json"] = []byte(disable) }, tamperedC},
		{"second drop-in sorted after ours sets disableAllHooks", func(b *fakeBox) { b.files[DropInDir+"/zz-last.json"] = []byte(disable) }, tamperedC},
		{"managed-settings.json sets disableAllHooks", func(b *fakeBox) { b.files[ManagedSettingsDir+"/managed-settings.json"] = []byte(disable) }, tamperedC},
		{"a newline in the file name does not hide it", func(b *fakeBox) { b.files[DropInDir+"/a\nb.json"] = []byte(disable) }, tamperedC},
		{"unparseable managed file naming disableAllHooks", func(b *fakeBox) { b.files[DropInDir+"/x.json"] = []byte(`{"disableAllHooks": tru`) }, tamperedC},
		{"another managed file that leaves hooks on", func(b *fakeBox) {
			b.files[DropInDir+"/x.json"] = []byte(`{"disableAllHooks": false, "env": {"A": "b"}}`)
		}, covered},
		{"a managed file that is a link is reported, not read", func(b *fakeBox) {
			b.files[DropInDir+"/x.json"] = []byte(`{}`)
			b.kinds[DropInDir+"/x.json"] = "l"
		}, tamperedC},
		{"a managed file that is a FIFO is reported, not read", func(b *fakeBox) {
			b.files[DropInDir+"/x.json"] = nil
			b.kinds[DropInDir+"/x.json"] = "p"
		}, tamperedC},
		{"a managed file over the size cap", func(b *fakeBox) { b.files[DropInDir+"/x.json"] = make([]byte, maxManagedFileBytes+1) }, tamperedC},
		{"a json file elsewhere under the directory is not a managed file", func(b *fakeBox) { b.files[ManagedSettingsDir+"/other/x.json"] = []byte(disable) }, covered},

		{"engine stopped", func(b *fakeBox) { b.engineActive = false }, engineDown},
		{"engine socket not reachable by the box user", func(b *fakeBox) { b.socketDenied = true }, engineDown},
		{"client older than the minimum", func(b *fakeBox) { b.version = "2.1.298 (Claude Code)" }, tooOld},
		{"client newer than the minimum", func(b *fakeBox) { b.version = "2.2.0 (Claude Code)" }, covered},
		{"other output ahead of the version", func(b *fakeBox) { b.version = "Welcome back!\nclaude 2.1.326 (Claude Code)" }, covered},
		{"client version unreadable", func(b *fakeBox) { b.version = "garbage" }, unknownC},
		{"no client installed", func(b *fakeBox) { b.claudeStat = "" }, covered},
		{"long-running client with no stamp", func(b *fakeBox) { b.ps = "  41 900 claude\n   1 99999 systemd\n" }, notFiring},
		{"long-running client whose stamp predates it (pid reuse)", func(b *fakeBox) {
			b.ps = "41 900 claude\n"
			b.stamps["41"] = epoch(-2 * time.Hour)
		}, notFiring},
		{"long-running client with a stamp since it started", func(b *fakeBox) {
			b.ps = "41 900 claude\n"
			b.stamps["41"] = epoch(-10 * time.Minute)
		}, covered},
		{"client younger than the grace period, no stamp yet", func(b *fakeBox) { b.ps = "41 30 claude\n" }, covered},
		{"another process named differently", func(b *fakeBox) { b.ps = "41 900 claude-helper\n" }, covered},
		{"root exec fails", func(b *fakeBox) { b.execErr = errors.New("box unreachable") }, unknownC},
		{"a command is killed by its in-box deadline", func(b *fakeBox) { b.exitCode = 124 }, unknownC},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, box := newTestChecker(t)
			prev := mustCurrent(t, c)
			tc.setup(box)
			box.log = nil
			got := c.check(testBox, testUser, prev)
			if got.Coverage != tc.want {
				t.Fatalf("coverage = %v (%s), want %v", got.Coverage, got.Detail, tc.want)
			}
			if got.Detail == "" || !got.CheckedAt.Equal(testNow) {
				t.Errorf("want a detail and CheckedAt=now, got %+v", got)
			}
			if strings.Contains(got.Detail, "disableAllHooks\": true") {
				t.Errorf("detail must not carry file contents: %q", got.Detail)
			}
			if got.stale {
				t.Errorf("nothing here is an earlier install of ours: %+v", got)
			}
			// Nothing but a regular file is ever opened.
			for _, l := range box.logged("exec head ") {
				p := strings.TrimPrefix(l, "exec head ")
				if box.kinds[p] != "" || (box.meta[p] != "" && !strings.HasPrefix(box.meta[p], "regular")) {
					t.Errorf("the check opened %q, which is not a regular file", p)
				}
			}
		})
	}
}

// client_installed is typed, so a consumer can tell "covered, hooks seen to
// be in place for a client" from "covered, nothing to run them".
func TestCheckReportsWhetherAClientIsInstalled(t *testing.T) {
	c, box := newTestChecker(t)
	if got := c.check(testBox, testUser, mustCurrent(t, c)); !got.ClientInstalled || got.ClientVersion != "2.1.326" {
		t.Fatalf("with a client: %+v", got)
	}
	box.claudeStat = ""
	if got := c.check(testBox, testUser, mustCurrent(t, c)); got.ClientInstalled || got.ClientVersion != "" || got.Coverage != covered {
		t.Fatalf("without a client: %+v", got)
	}
	// Too old still says a client is there.
	box.claudeStat, box.version = "9:9:9", "2.0.0"
	if got := c.check(testBox, testUser, mustCurrent(t, c)); !got.ClientInstalled || got.Coverage != tooOld {
		t.Fatalf("old client: %+v", got)
	}
}

// The client version is read as the box user, and only when the binary
// changed: a check must not start the client on every tick.
func TestCheckReadsVersionOnlyWhenBinaryChanged(t *testing.T) {
	c, box := newTestChecker(t)
	prev := mustCurrent(t, c)
	for i := 0; i < 3; i++ {
		if got := c.check(testBox, testUser, prev); got.ClientVersion != "2.1.326" {
			t.Fatalf("client version = %q", got.ClientVersion)
		}
	}
	if box.versionCalls != 1 {
		t.Fatalf("version read %d times for an unchanged binary, want 1", box.versionCalls)
	}
	box.claudeStat = "12:1700009999:300"
	box.version = "2.1.400 (Claude Code)"
	if got := c.check(testBox, testUser, prev); got.ClientVersion != "2.1.400" || box.versionCalls != 2 {
		t.Fatalf("after an upgrade: version %q, %d reads", got.ClientVersion, box.versionCalls)
	}
}

// Files that match what the daemon recorded for an earlier install are an
// upgrade or a flag change, not tampering. With no such record they are.
func TestCheckTellsAnEarlierInstallFromTampering(t *testing.T) {
	c, box := newTestChecker(t)
	oldBin, oldDropIn := []byte("last release's binary"), []byte(`{"hooks":{}}`)
	earlier := installed{binary: sha256Hex(oldBin), dropIn: sha256Hex(oldDropIn)}

	box.files[HookBinaryPath] = oldBin
	if got := c.check(testBox, testUser, earlier); !got.stale || !got.repair {
		t.Fatalf("earlier binary: %+v", got)
	}
	if got := c.check(testBox, testUser, mustCurrent(t, c)); got.stale || got.Coverage != tamperedC {
		t.Fatalf("same bytes with no record of them: %+v", got)
	}
	box.files[HookBinaryPath] = testBinary
	box.files[DropInPath] = oldDropIn
	if got := c.check(testBox, testUser, earlier); !got.stale || !got.repair {
		t.Fatalf("earlier drop-in: %+v", got)
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
	for _, bad := range []string{"x", "", "2..1"} {
		if _, err := versionAtLeast(bad, "2.1.326"); err == nil {
			t.Errorf("want an error for version %q", bad)
		}
	}
}

// The binary goes in, is run once, and only then is the drop-in written;
// both land by rename from a temporary name. On removal the drop-in goes
// first. The drop-in never names a binary that does not run.
func TestInstallAndRemoveOrder(t *testing.T) {
	c, box := newTestChecker(t)
	var steps []string
	for _, l := range box.log {
		if strings.HasPrefix(l, "write ") || strings.HasPrefix(l, "mv ") || strings.HasPrefix(l, "exec runuser") {
			steps = append(steps, strings.Fields(l)[0]+" "+strings.Fields(l)[len(strings.Fields(l))-1])
		}
	}
	want := []string{"write " + tmpBinaryPath, "exec --help", "mv " + HookBinaryPath, "write " + tmpDropInPath, "mv " + DropInPath}
	if strings.Join(steps, ", ") != strings.Join(want, ", ") {
		t.Fatalf("install steps:\n got %v\nwant %v", steps, want)
	}
	if strings.HasSuffix(tmpDropInPath, ".json") {
		t.Fatal("the temporary drop-in must not be picked up as a managed settings file")
	}
	// A second install of the same pinned binary does not push it again,
	// but still proves it runs.
	box.log = nil
	if err := c.install(testBox, testUser); err != nil {
		t.Fatal(err)
	}
	if w := box.logged("write "); len(w) != 1 || w[0] != "write "+tmpDropInPath {
		t.Fatalf("re-install wrote %v, want only the drop-in", w)
	}
	if len(box.logged("exec runuser")) != 1 {
		t.Fatal("re-install did not smoke-test the binary")
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

// A binary that does not run in the box (wrong libc, no hook subcommand)
// must leave no drop-in at all: with onFailure "block" it would block every
// tool call. That includes a drop-in from an earlier, working install.
func TestInstallLeavesNoDropInWhenTheBinaryDoesNotRun(t *testing.T) {
	c, box := newTestChecker(t)
	box.smokeBroken = true
	box.files[HookBinaryPath] = []byte("an older binary") // forces a new push
	err := c.install(testBox, testUser)
	if !errors.Is(err, errNotRunnable) {
		t.Fatalf("err = %v, want errNotRunnable", err)
	}
	if box.has(DropInPath) || box.has(tmpDropInPath) || box.has(tmpBinaryPath) {
		t.Fatalf("left behind: %v", box.files)
	}
	if string(box.files[HookBinaryPath]) != "an older binary" {
		t.Fatal("the binary that failed the smoke test replaced the one in place")
	}
}

// Root writes must not follow a link the box user placed.
func TestInstallRefusesAndReplacesLinks(t *testing.T) {
	for _, dir := range []string{ManagedSettingsDir, DropInDir, HookBinaryDir} {
		box := newFakeBox()
		c, err := newChecker(box, operatorEngine.withDefaults(), bytesBinary(testBinary))
		if err != nil {
			t.Fatal(err)
		}
		box.meta[dir] = "symbolic link|0|777"
		if err := c.install(testBox, testUser); err == nil || !strings.Contains(err.Error(), "refusing") {
			t.Fatalf("%s as a symlink: err = %v", dir, err)
		}
		if box.fileCount() != 0 {
			t.Fatalf("%s as a symlink: wrote %v", dir, box.files)
		}
	}
	// A link at a file's own path is replaced by the rename, not followed.
	c, box := newTestChecker(t)
	box.meta[DropInPath] = "symbolic link|0|777"
	box.meta[HookBinaryPath] = "symbolic link|0|777"
	if err := c.install(testBox, testUser); err != nil {
		t.Fatal(err)
	}
	if got := c.check(testBox, testUser, mustCurrent(t, c)); got.Coverage != covered {
		t.Fatalf("after replacing the links: %+v", got)
	}
}

// A command that never returns must not hold the check: the daemon stops
// waiting once its own deadline passes.
func TestCheckDoesNotWaitForAHungExec(t *testing.T) {
	c, box := newTestChecker(t)
	prev := mustCurrent(t, c)
	c.run.timeout, c.run.grace = 20*time.Millisecond, 0
	release := make(chan struct{})
	defer close(release)
	box.hang[testBox] = release

	done := make(chan Result, 1)
	go func() { done <- c.check(testBox, testUser, prev) }()
	select {
	case got := <-done:
		if got.Coverage != unknownC || !strings.Contains(got.Detail, "timed out") {
			t.Fatalf("got %+v, want UNKNOWN with a timeout detail", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the check is still waiting on a hung exec")
	}
}
