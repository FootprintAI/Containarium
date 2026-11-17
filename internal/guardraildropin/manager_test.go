package guardraildropin

import (
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func newTestManager(t *testing.T, state string, sw incus.GuardrailHookSwitch) (*Manager, *fakeBox, *fakeInstances) {
	t.Helper()
	box := newFakeBox()
	inst := &fakeInstances{boxes: map[string]*incus.ContainerInfo{
		testBox: {Name: testBox, State: state, GuardrailHook: sw},
	}}
	m, err := newManager(inst, box, Options{}, bytesBinary(testBinary))
	if err != nil {
		t.Fatal(err)
	}
	m.checker.clock = func() time.Time { return testNow }
	return m, box, inst
}

func TestEnableInstallsAndDisableRemoves(t *testing.T) {
	m, box, inst := newTestManager(t, "Running", incus.GuardrailHookOff)

	got, err := m.SetEnabled(testUser, true)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Enabled || got.Coverage != pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_COVERED {
		t.Fatalf("after enable: %+v", got)
	}
	if _, ok := box.files[DropInPath]; !ok {
		t.Fatal("drop-in not written into the running box")
	}
	if inst.boxes[testBox].GuardrailHook != incus.GuardrailHookOn {
		t.Fatalf("switch = %q, want on", inst.boxes[testBox].GuardrailHook)
	}

	// Break-glass: the hook binary is gone (a broken hook blocks every
	// tool); turning the feature off must still remove the drop-in.
	delete(box.files, HookBinaryPath)
	got, err = m.SetEnabled(testUser, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.Enabled || got.Coverage != pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_FEATURE_OFF {
		t.Fatalf("after disable: %+v", got)
	}
	if len(box.files) != 0 {
		t.Fatalf("files left in the box after disable: %v", box.files)
	}
	if inst.boxes[testBox].GuardrailHook != incus.GuardrailHookOff {
		t.Fatalf("switch = %q, want off", inst.boxes[testBox].GuardrailHook)
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
	if n := box.execCount(); n != 0 {
		t.Fatalf("%d exec(s) into a stopped box", n)
	}
	got, err := m.Coverage(testUser)
	if err != nil || got.Coverage != pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_UNKNOWN {
		t.Fatalf("stopped box coverage = %+v, %v", got, err)
	}

	inst.boxes[testBox].State = "Running"
	m.BoxStarted(testUser) // installs at start while the switch is on
	m.tick()
	if len(inst.writes) != 0 {
		t.Fatalf("start + check wrote box config: %v", inst.writes)
	}
	if got, _ := m.Coverage(testUser); got.Coverage != pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_COVERED {
		t.Fatalf("after start: %+v", got)
	}
}

// Boxes that never had the feature on cost nothing per tick.
func TestTickIgnoresBoxesWithTheSwitchOff(t *testing.T) {
	m, box, _ := newTestManager(t, "Running", incus.GuardrailHookOff)
	m.tick()
	if n := box.execCount(); n != 0 {
		t.Fatalf("%d exec(s) into a box with the switch off", n)
	}
	got, _ := m.Coverage(testUser)
	if got.Coverage != pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_FEATURE_OFF {
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
	if got, _ := m.Coverage(testUser); got.Coverage != pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_TAMPERED {
		t.Fatalf("first check: %+v", got)
	}
	m.tick()
	if got, _ := m.Coverage(testUser); got.Coverage != pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_COVERED {
		t.Fatalf("after repair: %+v", got)
	}

	// Another managed file is not ours to delete: it stays reported.
	box.files[DropInDir+"/zz.json"] = []byte(`{"disableAllHooks": true}`)
	m.tick()
	m.tick()
	if got, _ := m.Coverage(testUser); got.Coverage != pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_TAMPERED {
		t.Fatalf("foreign disableAllHooks: %+v", got)
	}
	if _, ok := box.files[DropInDir+"/zz.json"]; !ok {
		t.Fatal("the daemon removed a managed file it does not own")
	}
}

// Disabling while the box is stopped cannot remove the file yet; the
// removal is owed and happens when the box next starts.
func TestDisableWhileStoppedRemovesAtNextStart(t *testing.T) {
	m, box, inst := newTestManager(t, "Running", incus.GuardrailHookOff)
	if _, err := m.SetEnabled(testUser, true); err != nil {
		t.Fatal(err)
	}
	inst.boxes[testBox].State = "Stopped"
	got, err := m.SetEnabled(testUser, false)
	if err != nil || got.Enabled {
		t.Fatalf("disable while stopped: %+v, %v", got, err)
	}
	if inst.boxes[testBox].GuardrailHook != incus.GuardrailHookRemoving {
		t.Fatalf("switch = %q, want removing", inst.boxes[testBox].GuardrailHook)
	}
	if _, ok := box.files[DropInPath]; !ok {
		t.Fatal("test setup: drop-in should still be on the stopped box's disk")
	}
	inst.boxes[testBox].State = "Running"
	m.BoxStarted(testUser)
	if len(box.files) != 0 || inst.boxes[testBox].GuardrailHook != incus.GuardrailHookOff {
		t.Fatalf("after start: files %v, switch %q", box.files, inst.boxes[testBox].GuardrailHook)
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
