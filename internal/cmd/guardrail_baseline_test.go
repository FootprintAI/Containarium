package cmd

import (
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakeGuardrailBaselineAPI records the mode each set sends.
type fakeGuardrailBaselineAPI struct {
	got []pb.GuardrailBaselineMode
	err error
}

func (f *fakeGuardrailBaselineAPI) SetGuardrailBaselineMode(mode pb.GuardrailBaselineMode) (*pb.SetGuardrailBaselineModeResponse, error) {
	f.got = append(f.got, mode)
	if f.err != nil {
		return nil, f.err
	}
	return &pb.SetGuardrailBaselineModeResponse{Baseline: &pb.GuardrailBaselineSetting{
		Mode: mode, Revision: int64(len(f.got)), UpdatedBy: "ops", UpdatedAt: timestamppb.Now(),
	}}, nil
}

func withFakeGuardrailBaselineAPI(t *testing.T, f *fakeGuardrailBaselineAPI) {
	t.Helper()
	prev := newGuardrailBaselineAPI
	newGuardrailBaselineAPI = func() (guardrailBaselineAPI, func(), error) { return f, func() {}, nil }
	t.Cleanup(func() { newGuardrailBaselineAPI = prev })
}

func runGuardrailBaselineSetCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	guardrailBaselineMode = ""
	return runGuardrail(t, append([]string{"baseline", "set"}, args...)...)
}

// TestGuardrailBaselineSetCLI_SendsTypedMode (#2738): --mode block|log maps
// to the proto enum and the stored setting is printed.
func TestGuardrailBaselineSetCLI_SendsTypedMode(t *testing.T) {
	cases := []struct {
		flag string
		want pb.GuardrailBaselineMode
		out  string
	}{
		{"block", pb.GuardrailBaselineMode_GUARDRAIL_BASELINE_MODE_BLOCK, "Baseline mode set to block: revision 1"},
		{"log", pb.GuardrailBaselineMode_GUARDRAIL_BASELINE_MODE_LOG, "Baseline mode set to log: revision 1"},
		{"BLOCK", pb.GuardrailBaselineMode_GUARDRAIL_BASELINE_MODE_BLOCK, "Baseline mode set to block"},
	}
	for _, tc := range cases {
		t.Run(tc.flag, func(t *testing.T) {
			f := &fakeGuardrailBaselineAPI{}
			withFakeGuardrailBaselineAPI(t, f)
			out, err := runGuardrailBaselineSetCLI(t, "--mode", tc.flag)
			if err != nil {
				t.Fatalf("baseline set --mode %s: %v (%s)", tc.flag, err, out)
			}
			if len(f.got) != 1 || f.got[0] != tc.want {
				t.Fatalf("sent %v, want [%v]", f.got, tc.want)
			}
			if !strings.Contains(out, tc.out) {
				t.Fatalf("output %q missing %q", out, tc.out)
			}
		})
	}
}

// TestGuardrailBaselineSetCLI_Refusals: a missing or unknown mode never
// reaches the daemon; a daemon refusal (non-admin) is a command error.
func TestGuardrailBaselineSetCLI_Refusals(t *testing.T) {
	for _, args := range [][]string{nil, {"--mode", "warn"}, {"--mode", ""}, {"--mode", "unspecified"}} {
		f := &fakeGuardrailBaselineAPI{}
		withFakeGuardrailBaselineAPI(t, f)
		if out, err := runGuardrailBaselineSetCLI(t, args...); err == nil {
			t.Fatalf("baseline set %v succeeded (%s), want an error", args, out)
		}
		if len(f.got) != 0 {
			t.Fatalf("baseline set %v reached the daemon with %v", args, f.got)
		}
	}

	denied := &fakeGuardrailBaselineAPI{err: errors.New("set guardrail baseline mode: rpc error: code = PermissionDenied")}
	withFakeGuardrailBaselineAPI(t, denied)
	out, err := runGuardrailBaselineSetCLI(t, "--mode", "block")
	if err == nil || strings.Contains(out, "Baseline mode set") {
		t.Fatalf("non-admin set = (%q, %v), want an error and no success line", out, err)
	}
}

// TestGuardrailBaselineSetCLI_NeedsServer: without --server it fails.
func TestGuardrailBaselineSetCLI_NeedsServer(t *testing.T) {
	if _, err := runGuardrailBaselineSetCLI(t, "--mode", "block"); !errors.Is(err, errNoGuardrailServer) {
		t.Fatalf("baseline set without --server = %v, want errNoGuardrailServer", err)
	}
}
