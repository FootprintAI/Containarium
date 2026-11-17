package cmd

import (
	"bytes"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

type fakeGuardrailDropInAPI struct {
	sets  []string
	boxes []*pb.GuardrailHookBoxCoverage
}

func (f *fakeGuardrailDropInAPI) SetGuardrailHook(username string, enabled bool) (*pb.GuardrailHookBoxCoverage, error) {
	if enabled {
		f.sets = append(f.sets, "on "+username)
		return &pb.GuardrailHookBoxCoverage{Username: username, Enabled: true, Coverage: pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_COVERED, Detail: "ok"}, nil
	}
	f.sets = append(f.sets, "off "+username)
	return &pb.GuardrailHookBoxCoverage{Username: username, Coverage: pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_FEATURE_OFF, Detail: "off"}, nil
}

func (f *fakeGuardrailDropInAPI) GetGuardrailHookCoverage(username string) (*pb.GuardrailHookBoxCoverage, error) {
	return &pb.GuardrailHookBoxCoverage{Username: username, Enabled: true,
		Coverage: pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_HOOKS_NOT_FIRING, Detail: "client process 41 has no stamp", ClientVersion: "2.1.326"}, nil
}

func (f *fakeGuardrailDropInAPI) ListGuardrailHookCoverage() ([]*pb.GuardrailHookBoxCoverage, error) {
	return f.boxes, nil
}

func runGuardrailDropIn(t *testing.T, f *fakeGuardrailDropInAPI, args ...string) string {
	t.Helper()
	prev := newGuardrailDropInAPI
	newGuardrailDropInAPI = func() (guardrailDropInAPI, func(), error) { return f, func() {}, nil }
	t.Cleanup(func() { newGuardrailDropInAPI = prev; guardrailDropInJSON = false })
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs(append([]string{"guardrail", "dropin"}, args...))
	t.Cleanup(func() { rootCmd.SetOut(nil); rootCmd.SetErr(nil); rootCmd.SetArgs(nil) })
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out.String())
	}
	return out.String()
}

func TestGuardrailDropInCoverageShowsPerBoxCoverage(t *testing.T) {
	f := &fakeGuardrailDropInAPI{boxes: []*pb.GuardrailHookBoxCoverage{
		{Username: "alice", Enabled: true, Coverage: pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_COVERED, Detail: "fine", ClientVersion: "2.1.326"},
		{Username: "bob", Enabled: true, Coverage: pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_TAMPERED, Detail: "another managed settings file sets disableAllHooks"},
	}}
	out := runGuardrailDropIn(t, f, "coverage")
	for _, want := range []string{"alice", "COVERED", "bob", "NOT_COVERED_TAMPERED", "disableAllHooks", "2.1.326"} {
		if !strings.Contains(out, want) {
			t.Errorf("list output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "GUARDRAIL_HOOK_COVERAGE_") {
		t.Errorf("the enum prefix should be trimmed for people:\n%s", out)
	}

	out = runGuardrailDropIn(t, f, "coverage", "carol")
	if !strings.Contains(out, "carol") || !strings.Contains(out, "NOT_COVERED_HOOKS_NOT_FIRING") || !strings.Contains(out, "process 41") {
		t.Errorf("single-box output:\n%s", out)
	}

	out = runGuardrailDropIn(t, f, "coverage", "carol", "--json")
	if !strings.Contains(out, `"GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_HOOKS_NOT_FIRING"`) {
		t.Errorf("--json should carry the full enum name:\n%s", out)
	}
}

func TestGuardrailDropInCoverageEmpty(t *testing.T) {
	out := runGuardrailDropIn(t, &fakeGuardrailDropInAPI{}, "coverage")
	if !strings.Contains(out, "No box has the guardrail hook switched on") {
		t.Errorf("empty list output:\n%s", out)
	}
}

func TestGuardrailDropInEnableDisable(t *testing.T) {
	f := &fakeGuardrailDropInAPI{}
	if out := runGuardrailDropIn(t, f, "enable", "alice"); !strings.Contains(out, "COVERED") {
		t.Errorf("enable output:\n%s", out)
	}
	if out := runGuardrailDropIn(t, f, "disable", "alice"); !strings.Contains(out, "NOT_COVERED_FEATURE_OFF") {
		t.Errorf("disable output:\n%s", out)
	}
	if strings.Join(f.sets, ",") != "on alice,off alice" {
		t.Fatalf("calls = %v", f.sets)
	}
}
