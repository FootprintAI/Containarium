package cmd

import (
	"bytes"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakeSkillSetApplier struct {
	got  *pb.ApplyBoxSkillSetsRequest
	resp *pb.ApplyBoxSkillSetsResponse
	err  error
}

func (f *fakeSkillSetApplier) ApplyBoxSkillSets(req *pb.ApplyBoxSkillSetsRequest) (*pb.ApplyBoxSkillSetsResponse, error) {
	f.got = req
	return f.resp, f.err
}

// `code skill-sets` is a thin wrapper: --skill-sets becomes the RPC's explicit
// target list (ids as given, none as the empty list, all expanded from this
// CLI's lock), --release passes through, and the response is rendered as what
// the box now has and what changed.
func TestCodeSkillSets(t *testing.T) {
	tests := []struct {
		name        string
		value       string
		release     string
		resp        *pb.ApplyBoxSkillSetsResponse
		wantSets    string
		wantRelease string
		want        []string
		absent      []string
	}{
		{
			name: "ids as given, installed and removed rendered", value: "qa,sdlc", release: "v1.2.3",
			resp: &pb.ApplyBoxSkillSetsResponse{
				SkillSets: []string{"qa", "sdlc"}, Release: "v1.2.3",
				Installed: []*pb.BoxSkillSetChange{{SkillSet: "qa", Skills: []string{"qa-sprint-verify", "qa-unit-test"}}},
				Removed:   []*pb.BoxSkillSetChange{{SkillSet: "security", Skills: []string{"security-triage"}}},
			},
			wantSets: "qa,sdlc", wantRelease: "v1.2.3",
			want:   []string{"alice: skill sets now qa, sdlc (from v1.2.3)", "installed qa: qa-sprint-verify, qa-unit-test", "removed security: security-triage"},
			absent: []string{"unchanged"},
		},
		{
			name: "unchanged says so", value: "qa",
			resp:     &pb.ApplyBoxSkillSetsResponse{SkillSets: []string{"qa"}, Unchanged: true, Release: "v1.2.3"},
			wantSets: "qa",
			want:     []string{"alice: skill sets unchanged (qa); nothing installed or removed, files refreshed from v1.2.3"},
		},
		{
			name: "none is the empty list", value: "none",
			resp:     &pb.ApplyBoxSkillSetsResponse{Release: "v1.2.3", Removed: []*pb.BoxSkillSetChange{{SkillSet: "qa", Skills: []string{"qa-unit-test"}}}},
			wantSets: "",
			want:     []string{"alice: skill sets now none (from v1.2.3)", "removed qa: qa-unit-test"},
		},
		{
			name: "all expands to this CLI's lock", value: "all",
			resp:     &pb.ApplyBoxSkillSetsResponse{SkillSets: []string{"qa", "sdlc", "security"}, Unchanged: true, Release: "v1"},
			wantSets: "qa,sdlc,security",
			want:     []string{"unchanged (qa, sdlc, security)"},
		},
		{
			name: "a removal the lock no longer attributes is still shown", value: "sdlc",
			resp:     &pb.ApplyBoxSkillSetsResponse{SkillSets: []string{"sdlc"}, Release: "v1", Removed: []*pb.BoxSkillSetChange{{Skills: []string{"old-thing"}}}},
			wantSets: "sdlc",
			want:     []string{"removed (no set in this release's lock): old-thing"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeSkillSetApplier{resp: tt.resp}
			var out bytes.Buffer
			if err := codeApplySkillSets(f, "alice", tt.value, tt.release, &out); err != nil {
				t.Fatal(err)
			}
			if f.got.GetUsername() != "alice" || strings.Join(f.got.GetSkillSets(), ",") != tt.wantSets || f.got.GetRelease() != tt.wantRelease {
				t.Errorf("request = %v", f.got)
			}
			if tt.value == "none" && f.got.SkillSets == nil {
				t.Error("none must send an explicit empty list, not an absent field")
			}
			for _, w := range tt.want {
				if !strings.Contains(out.String(), w) {
					t.Errorf("output %q missing %q", out.String(), w)
				}
			}
			for _, a := range tt.absent {
				if strings.Contains(out.String(), a) {
					t.Errorf("output %q has %q", out.String(), a)
				}
			}
		})
	}
}

// Bad input never reaches the daemon; a typed refusal is rendered with its
// reason; an old daemon is named as such with the SSH fallback.
func TestCodeSkillSets_Errors(t *testing.T) {
	refusal := func(reason pb.BoxSkillSetsRefusal, msg string) error {
		st, _ := status.New(codes.FailedPrecondition, msg).WithDetails(&errdetails.PreconditionFailure{
			Violations: []*errdetails.PreconditionFailure_Violation{{Type: reason.String(), Subject: "alice-container", Description: msg}},
		})
		return st.Err()
	}
	badRequest := func(reason pb.BoxSkillSetsRefusal, msg string) error {
		st, _ := status.New(codes.InvalidArgument, msg).WithDetails(&errdetails.BadRequest{
			FieldViolations: []*errdetails.BadRequest_FieldViolation{{Field: "skill_sets", Description: msg, Reason: reason.String()}},
		})
		return st.Err()
	}
	tests := []struct {
		name     string
		value    string
		release  string
		err      error
		wantErr  string
		wantCall bool
	}{
		{"empty --skill-sets", "", "", nil, "--skill-sets is required", false},
		{"all with ids", "all,qa", "", nil, "cannot be combined", false},
		{"shell syntax", "qa;rm -rf /", "", nil, "not a valid set id", false},
		{"bad release", "qa", "v1;x", nil, "--release", false},
		{"run in progress", "qa", "", refusal(pb.BoxSkillSetsRefusal_BOX_SKILL_SETS_REFUSAL_RUN_IN_PROGRESS, `alice-container has a run in progress (code run(s) "code")`), `refused (RUN_IN_PROGRESS): alice-container has a run in progress (code run(s) "code")`, true},
		{"set predates manifest", "qa", "", refusal(pb.BoxSkillSetsRefusal_BOX_SKILL_SETS_REFUSAL_SET_PREDATES_MANIFEST, "keep it in the list"), "refused (SET_PREDATES_MANIFEST): keep it in the list", true},
		{"unknown set", "qa", "", badRequest(pb.BoxSkillSetsRefusal_BOX_SKILL_SETS_REFUSAL_UNKNOWN_SKILL_SET, `unknown skill set "qa"; known skill sets: sdlc`), `refused (UNKNOWN_SKILL_SET): unknown skill set "qa"; known skill sets: sdlc`, true},
		{"old daemon", "qa", "", status.Error(codes.Unimplemented, "unknown method"), "does not support re-applying skill sets (ApplyBoxSkillSets); upgrade it, or re-run `containarium code install alice --skill-sets qa`", true},
		{"plain error", "qa", "", status.Error(codes.Unavailable, "boom"), "apply skill sets on alice: ", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeSkillSetApplier{err: tt.err}
			err := codeApplySkillSets(f, "alice", tt.value, tt.release, &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
			if (f.got != nil) != tt.wantCall {
				t.Errorf("daemon called = %v, want %v", f.got != nil, tt.wantCall)
			}
		})
	}
}

// The `code install` help documents the relationship between the two paths
// (acceptance criterion of #3374), and the new command is wired under code.
func TestCodeSkillSets_DocumentedFromInstall(t *testing.T) {
	if !strings.Contains(codeInstallCmd.Long, "code skill-sets") {
		t.Error("code install --help does not point at `code skill-sets` for changing the sets later")
	}
	usage := codeInstallCmd.Flags().Lookup("skill-sets").Usage
	if !strings.Contains(usage, "code skill-sets") {
		t.Errorf("--skill-sets usage %q does not name the re-apply command", usage)
	}
	found := false
	for _, c := range codeCmd.Commands() {
		if c.Name() == "skill-sets" {
			found = true
		}
	}
	if !found {
		t.Error("code skill-sets is not registered under code")
	}
	if f := codeSkillSetsCmd.Flags().Lookup("skill-sets"); f == nil || f.Annotations[cobra.BashCompOneRequiredFlag] == nil {
		t.Error("--skill-sets must be required: the list is the whole request")
	}
}
