package guardraildropin

import (
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
)

func newTestManager(t *testing.T, state string, sw incus.GuardrailHookSwitch) (*Manager, *fakeBox, *fakeInstances) {
	t.Helper()
	box := newFakeBox()
	inst := &fakeInstances{boxes: map[string]*incus.ContainerInfo{
		testBox: {Name: testBox, State: state, GuardrailHook: sw},
	}}
	return managerOver(t, inst, box, testBinary), box, inst
}

func managerOver(t *testing.T, inst *fakeInstances, box *fakeBox, binary []byte) *Manager {
	t.Helper()
	m, err := newManager(inst, box, Options{}, bytesBinary(binary))
	if err != nil {
		t.Fatal(err)
	}
	m.checker.clock = func() time.Time { return testNow }
	return m
}

func TestEnableInstallsAndDisableRemoves(t *testing.T) {
	m, box, inst := newTestManager(t, "Running", incus.GuardrailHookOff)

	got, err := m.SetEnabled(testUser, true)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Enabled || got.Coverage != covered {
		t.Fatalf("after enable: %+v", got)
	}
	if !box.has(DropInPath) {
		t.Fatal("drop-in not written into the running box")
	}
	if inst.sw(testBox) != incus.GuardrailHookOn {
		t.Fatalf("switch = %q, want on", inst.sw(testBox))
	}

	// Break-glass: the hook binary is gone (a broken hook blocks every
	// tool); turning the feature off must still remove the drop-in.
	delete(box.files, HookBinaryPath)
	got, err = m.SetEnabled(testUser, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.Enabled || got.Coverage != featureOff {
		t.Fatalf("after disable: %+v", got)
	}
	if box.fileCount() != 0 {
		t.Fatalf("files left in the box after disable: %v", box.files)
	}
	if inst.sw(testBox) != incus.GuardrailHookOff || inst.config[testBox] != "" {
		t.Fatalf("switch = %q, installed record = %q; want both cleared", inst.sw(testBox), inst.config[testBox])
	}
}

// Enabling a box whose binary does not run there reports not installed and
// leaves no drop-in behind.
func TestEnableWithABinaryThatDoesNotRun(t *testing.T) {
	m, box, _ := newTestManager(t, "Running", incus.GuardrailHookOff)
	box.smokeBroken = true
	got, err := m.SetEnabled(testUser, true)
	if err != nil {
		t.Fatal(err)
	}
	if got.Coverage != notInstalledC || !strings.Contains(got.Detail, "does not run") {
		t.Fatalf("got %+v", got)
	}
	if box.has(DropInPath) {
		t.Fatal("a drop-in was written for a binary that does not run")
	}
}

func TestSetEnabledUnknownBox(t *testing.T) {
	m, _, _ := newTestManager(t, "Running", incus.GuardrailHookOff)
	if _, err := m.SetEnabled("nobody", true); err != ErrBoxNotFound {
		t.Fatalf("err = %v, want ErrBoxNotFound", err)
	}
}

// A stopped box is never exec'd into, and a check writes no box config, so
// it cannot look like activity (auto-sleep reads the last-start stamp and
// network traffic only) or wake a box.
func TestTickSkipsStoppedBoxesAndWritesNoConfig(t *testing.T) {
	m, box, inst := newTestManager(t, "Stopped", incus.GuardrailHookOn)
	m.tick()
	if n := len(box.logged("exec ")); n != 0 {
		t.Fatalf("%d exec(s) into a stopped box", n)
	}
	got, err := m.Coverage(testUser)
	if err != nil || got.Coverage != unknownC {
		t.Fatalf("stopped box coverage = %+v, %v", got, err)
	}

	inst.set(testBox, func(b *incus.ContainerInfo) { b.State = "Running" })
	m.BoxStarted(testUser) // installs at start while the switch is on
	afterInstall := len(inst.writes)
	for _, w := range inst.writes {
		if !strings.Contains(w, incus.GuardrailHookInstalledKey) {
			t.Fatalf("the install wrote more than its own record: %v", inst.writes)
		}
	}
	m.tick()
	m.tick()
	if len(inst.writes) != afterInstall {
		t.Fatalf("a check wrote box config: %v", inst.writes[afterInstall:])
	}
	if len(box.logged("write ")) != 2 {
		t.Fatalf("a check wrote into the box: %v", box.logged("write "))
	}
	if got, _ := m.Coverage(testUser); got.Coverage != covered {
		t.Fatalf("after start: %+v", got)
	}
}

// Boxes that never had the feature on cost nothing per tick.
func TestTickIgnoresBoxesWithTheSwitchOff(t *testing.T) {
	m, box, _ := newTestManager(t, "Running", incus.GuardrailHookOff)
	m.tick()
	if n := len(box.logged("exec ")); n != 0 {
		t.Fatalf("%d exec(s) into a box with the switch off", n)
	}
	got, _ := m.Coverage(testUser)
	if got.Coverage != featureOff {
		t.Fatalf("coverage = %+v", got)
	}
}

// A tampered box is reported at the check that sees it, then repaired, so
// the report is not lost to the repair.
func TestTickReportsTamperThenRepairs(t *testing.T) {
	m, box, _ := newTestManager(t, "Running", incus.GuardrailHookOff)
	if _, err := m.SetEnabled(testUser, true); err != nil {
		t.Fatal(err)
	}
	box.files[DropInPath] = []byte(`{}`)
	m.tick()
	if got, _ := m.Coverage(testUser); got.Coverage != tamperedC {
		t.Fatalf("first check: %+v", got)
	}
	m.tick()
	if got, _ := m.Coverage(testUser); got.Coverage != covered {
		t.Fatalf("after repair: %+v", got)
	}

	// Another managed file is not ours to delete: it stays reported.
	box.files[DropInDir+"/zz.json"] = []byte(`{"disableAllHooks": true}`)
	m.tick()
	m.tick()
	if got, _ := m.Coverage(testUser); got.Coverage != tamperedC {
		t.Fatalf("foreign disableAllHooks: %+v", got)
	}
	if !box.has(DropInDir + "/zz.json") {
		t.Fatal("the daemon removed a managed file it does not own")
	}
}

// A daemon upgrade changes the pinned binary, and a flag change the
// drop-in. The first check afterwards replaces both and reports the box as
// it is after that, never as tampered.
func TestUpgradeIsRepairedWithoutReportingTamper(t *testing.T) {
	m, box, inst := newTestManager(t, "Running", incus.GuardrailHookOff)
	if _, err := m.SetEnabled(testUser, true); err != nil {
		t.Fatal(err)
	}
	before := inst.config[testBox]

	upgraded := managerOver(t, inst, box, []byte("next release's binary"))
	upgraded.checker.dropIn = append([]byte(nil), []byte(`{"hooks":{},"env":{}}`)...)
	upgraded.tick()
	got, _ := upgraded.Coverage(testUser)
	if got.Coverage != covered {
		t.Fatalf("first check after an upgrade: %+v", got)
	}
	if string(box.files[HookBinaryPath]) != "next release's binary" {
		t.Fatal("the new binary was not installed")
	}
	if inst.config[testBox] == before || inst.config[testBox] == "" {
		t.Fatalf("installed record not updated: %q", inst.config[testBox])
	}
}

// Disabling while the box is stopped cannot remove the file yet; the
// removal is owed and happens when the box next starts.
func TestDisableWhileStoppedRemovesAtNextStart(t *testing.T) {
	m, box, inst := newTestManager(t, "Running", incus.GuardrailHookOff)
	if _, err := m.SetEnabled(testUser, true); err != nil {
		t.Fatal(err)
	}
	inst.set(testBox, func(b *incus.ContainerInfo) { b.State = "Stopped" })
	got, err := m.SetEnabled(testUser, false)
	if err != nil || got.Enabled {
		t.Fatalf("disable while stopped: %+v, %v", got, err)
	}
	if inst.sw(testBox) != incus.GuardrailHookRemoving {
		t.Fatalf("switch = %q, want removing", inst.sw(testBox))
	}
	if !box.has(DropInPath) {
		t.Fatal("test setup: drop-in should still be on the stopped box's disk")
	}
	inst.set(testBox, func(b *incus.ContainerInfo) { b.State = "Running" })
	m.BoxStarted(testUser)
	if box.fileCount() != 0 || inst.sw(testBox) != incus.GuardrailHookOff {
		t.Fatalf("after start: files %v, switch %q", box.files, inst.sw(testBox))
	}
}

// One box whose check is stuck must not hold up another box, and must not
// hold up the break-glass for itself either.
func TestAStuckCheckBlocksNeitherOtherBoxesNorDisable(t *testing.T) {
	const otherBox, otherUser = "bob-container", "bob"
	m, box, inst := newTestManager(t, "Running", incus.GuardrailHookOff)
	inst.boxes[otherBox] = &incus.ContainerInfo{Name: otherBox, State: "Running"}
	for _, u := range []string{testUser, otherUser} {
		if _, err := m.SetEnabled(u, true); err != nil {
			t.Fatal(err)
		}
	}
	// alice's check hangs inside the box, for far longer than the test.
	m.checker.run.timeout = time.Minute
	release := make(chan struct{})
	box.mu.Lock()
	box.hang[testBox] = release
	box.mu.Unlock()
	tickDone := make(chan struct{})
	go func() { m.reconcile(testBox, false); close(tickDone) }()
	<-box.entered

	within := func(what string, fn func()) {
		t.Helper()
		done := make(chan struct{})
		go func() { fn(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s waited behind the stuck check", what)
		}
	}
	within("another box's check", func() { m.reconcile(otherBox, false) })
	if got, _ := m.Coverage(otherUser); got.Coverage != covered {
		t.Fatalf("other box: %+v", got)
	}
	within("another box's disable", func() {
		if _, err := m.SetEnabled(otherUser, false); err != nil {
			t.Error(err)
		}
	})
	within("the stuck box's own disable", func() {
		if _, err := m.SetEnabled(testUser, false); err != nil {
			t.Error(err)
		}
	})
	if box.has(DropInPath) || inst.sw(testBox) != incus.GuardrailHookOff {
		t.Fatal("the stuck box still has its drop-in after disable")
	}

	close(release)
	<-tickDone
	if box.has(DropInPath) {
		t.Fatal("the check that was in flight put the drop-in back after disable")
	}
}

// Disable does not wait for an install in flight. If it lands while the
// files are being written, the install takes them out again.
func TestDisableDuringInstallLeavesNoDropIn(t *testing.T) {
	m, box, inst := newTestManager(t, "Running", incus.GuardrailHookOn)
	box.onWrite = func(path string) {
		if path == tmpDropInPath {
			// The operator switches off; its removal runs before our write lands.
			inst.set(testBox, func(b *incus.ContainerInfo) { b.GuardrailHook = incus.GuardrailHookOff })
		}
	}
	m.BoxStarted(testUser)
	if box.fileCount() != 0 {
		t.Fatalf("files left after a disable that raced the install: %v", box.files)
	}
}

func TestListReturnsOnlySwitchedOnBoxes(t *testing.T) {
	m, _, inst := newTestManager(t, "Running", incus.GuardrailHookOn)
	inst.boxes["bob-container"] = &incus.ContainerInfo{Name: "bob-container", State: "Running"}
	inst.boxes["core-postgres"] = &incus.ContainerInfo{Name: "core-postgres", State: "Running", Role: incus.RolePostgres, GuardrailHook: incus.GuardrailHookOn}
	got, err := m.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Username != testUser {
		t.Fatalf("list = %+v", got)
	}
	if !strings.Contains(got[0].Detail, "not checked") {
		t.Errorf("an unchecked box should say so: %q", got[0].Detail)
	}
}

func TestRequireStaticELF(t *testing.T) {
	if err := requireStaticELF(strings.NewReader("#!/bin/sh\necho not a binary\n")); err == nil {
		t.Fatal("a script was accepted as the hook binary")
	}
}
