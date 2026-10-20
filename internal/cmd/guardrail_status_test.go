package cmd

import (
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fixedGuardrailStatusAPI answers GetGuardrailStatus with resp or err.
type fixedGuardrailStatusAPI struct {
	resp  *pb.GetGuardrailStatusResponse
	err   error
	calls int
}

func (f *fixedGuardrailStatusAPI) GetGuardrailStatus() (*pb.GetGuardrailStatusResponse, error) {
	f.calls++
	return f.resp, f.err
}

func withFixedGuardrailStatusAPI(t *testing.T, f *fixedGuardrailStatusAPI) {
	t.Helper()
	prev := newGuardrailStatusAPI
	newGuardrailStatusAPI = func() (guardrailStatusAPI, func(), error) { return f, func() {}, nil }
	t.Cleanup(func() { newGuardrailStatusAPI = prev })
}

func runGuardrailStatusCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	guardrailStatusJSON = false
	return runGuardrail(t, append([]string{"status"}, args...)...)
}

// TestGuardrailStatusCLI_PrintsEachEffectivePolicy (#2737): the command
// prints the daemon's effective response policy as the word the Verify
// steps look for (none / baseline / admin).
func TestGuardrailStatusCLI_PrintsEachEffectivePolicy(t *testing.T) {
	cases := []struct {
		name string
		resp *pb.GetGuardrailStatusResponse
		want []string
	}{
		{"baseline", &pb.GetGuardrailStatusResponse{
			ResponsePolicy:  pb.GuardrailEffectivePolicy_GUARDRAIL_EFFECTIVE_POLICY_BASELINE,
			BaselineRuleIds: []string{"baseline.pem_private_key"},
		}, []string{"Response policy: baseline", "baseline.pem_private_key"}},
		{"admin", &pb.GetGuardrailStatusResponse{
			ResponsePolicy:    pb.GuardrailEffectivePolicy_GUARDRAIL_EFFECTIVE_POLICY_ADMIN,
			PolicyRevision:    3,
			InboundBlockKinds: []pb.GuardrailKind{pb.GuardrailKind_GUARDRAIL_KIND_UNSAFE_CODE},
		}, []string{"Response policy: admin", "revision 3", "UNSAFE_CODE"}},
		{"none", &pb.GetGuardrailStatusResponse{
			ResponsePolicy: pb.GuardrailEffectivePolicy_GUARDRAIL_EFFECTIVE_POLICY_NONE,
			PolicyRevision: 4,
		}, []string{"Response policy: none", "revision 4"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fixedGuardrailStatusAPI{resp: tc.resp}
			withFixedGuardrailStatusAPI(t, f)
			out, err := runGuardrailStatusCLI(t)
			if err != nil {
				t.Fatalf("guardrail status: %v (%s)", err, out)
			}
			if f.calls != 1 {
				t.Fatalf("GetGuardrailStatus called %d times, want 1", f.calls)
			}
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("output missing %q:\n%s", w, out)
				}
			}

			out, err = runGuardrailStatusCLI(t, "--json")
			if err != nil {
				t.Fatalf("guardrail status --json: %v", err)
			}
			var decoded pb.GetGuardrailStatusResponse
			if err := protojson.Unmarshal([]byte(out), &decoded); err != nil {
				t.Fatalf("--json is not the response's protojson: %v\n%s", err, out)
			}
			if !proto.Equal(&decoded, tc.resp) {
				t.Fatalf("--json = %v, want %v", &decoded, tc.resp)
			}
		})
	}
}

// TestGuardrailStatusCLI_ErrorIsAnError: a failed read is a command error,
// never printed as an effective policy.
func TestGuardrailStatusCLI_ErrorIsAnError(t *testing.T) {
	withFixedGuardrailStatusAPI(t, &fixedGuardrailStatusAPI{err: errors.New("get guardrail status: read guardrail policy failed")})
	for _, args := range [][]string{nil, {"--json"}} {
		out, err := runGuardrailStatusCLI(t, args...)
		if err == nil || strings.Contains(out, "Response policy:") {
			t.Fatalf("status %v on a failed read = (%q, %v), want an error and no policy", args, out, err)
		}
	}
}

// TestGuardrailStatusCLI_NeedsServer: without --server the command fails
// rather than reporting a local guess.
func TestGuardrailStatusCLI_NeedsServer(t *testing.T) {
	if _, err := runGuardrailStatusCLI(t); !errors.Is(err, errNoGuardrailServer) {
		t.Fatalf("status without --server = %v, want errNoGuardrailServer", err)
	}
}
