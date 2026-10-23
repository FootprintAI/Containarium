package cmd

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakeRetentionAPI records each request and answers with a fixed shape.
type fakeRetentionAPI struct {
	sets     []*pb.SetRetentionPolicyRequest
	holds    []*pb.SetLegalHoldRequest
	released []string
	refresh  []bool
}

func (f *fakeRetentionAPI) GetRetentionReport(refresh bool) (*pb.GetRetentionReportResponse, error) {
	f.refresh = append(f.refresh, refresh)
	return &pb.GetRetentionReportResponse{Report: &pb.RetentionReport{
		Mode:           pb.RetentionMode_RETENTION_MODE_DRY_RUN,
		GeneratedAt:    timestamppb.New(time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)),
		PolicyRevision: 2,
		ActiveHolds:    1,
		Stores: []*pb.RetentionStoreReport{
			{Class: pb.RetentionClass_RETENTION_CLASS_PROMPTS, Store: "agent_tasks", Status: pb.RetentionSweepStatus_RETENTION_SWEEP_STATUS_COUNTED,
				WindowDays: 7, Cutoff: timestamppb.New(time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)), OlderThanCutoff: 5, Eligible: 3, Held: 2},
			{Class: pb.RetentionClass_RETENTION_CLASS_GATEWAY_LOGS, Store: "audit_logs", Status: pb.RetentionSweepStatus_RETENTION_SWEEP_STATUS_NOT_SWEPT,
				WindowDays: 90, Note: "hash-chained; handled by #2878"},
			{Class: pb.RetentionClass_RETENTION_CLASS_RESPONSES, Store: "agent_task_results", Status: pb.RetentionSweepStatus_RETENTION_SWEEP_STATUS_ERROR,
				WindowDays: 30, Note: "count agent_task_results: connection refused"},
		},
	}}, nil
}

func (f *fakeRetentionAPI) GetRetentionPolicy() (*pb.GetRetentionPolicyResponse, error) {
	return &pb.GetRetentionPolicyResponse{Policy: &pb.RetentionPolicy{Revision: 2, UpdatedBy: "ops", Windows: []*pb.RetentionWindow{
		{Class: pb.RetentionClass_RETENTION_CLASS_PROMPTS, Days: 7},
		{Class: pb.RetentionClass_RETENTION_CLASS_EVIDENCE_BUNDLES, Days: 365, IsDefault: true},
	}}}, nil
}

func (f *fakeRetentionAPI) SetRetentionPolicy(req *pb.SetRetentionPolicyRequest) (*pb.SetRetentionPolicyResponse, error) {
	f.sets = append(f.sets, req)
	return &pb.SetRetentionPolicyResponse{Policy: &pb.RetentionPolicy{Revision: 3, UpdatedBy: "ops"}}, nil
}

func (f *fakeRetentionAPI) ListLegalHolds() (*pb.ListLegalHoldsResponse, error) {
	return &pb.ListLegalHoldsResponse{Holds: []*pb.LegalHold{{OrgId: "org-a", Reason: "case 7", SetBy: "ops"}}}, nil
}

func (f *fakeRetentionAPI) SetLegalHold(req *pb.SetLegalHoldRequest) (*pb.SetLegalHoldResponse, error) {
	f.holds = append(f.holds, req)
	return &pb.SetLegalHoldResponse{Hold: &pb.LegalHold{OrgId: req.GetOrgId(), Reason: req.GetReason(), SetBy: "ops"}}, nil
}

func (f *fakeRetentionAPI) ReleaseLegalHold(orgID string) (*pb.ReleaseLegalHoldResponse, error) {
	f.released = append(f.released, orgID)
	return &pb.ReleaseLegalHoldResponse{Hold: &pb.LegalHold{OrgId: orgID}}, nil
}

func runRetentionCLI(t *testing.T, f *fakeRetentionAPI, args ...string) (string, error) {
	t.Helper()
	prev := newRetentionAPI
	newRetentionAPI = func() (retentionAPI, func(), error) { return f, func() {}, nil }
	t.Cleanup(func() { newRetentionAPI = prev })
	// cobra keeps flag values and Changed marks across Execute calls.
	for _, c := range []interface{ Flags() *pflag.FlagSet }{retentionPolicySetCmd, retentionHoldSetCmd, retentionReportCmd} {
		c.Flags().VisitAll(func(fl *pflag.Flag) { _ = fl.Value.Set(fl.DefValue); fl.Changed = false })
	}
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs(append([]string{"retention"}, args...))
	defer rootCmd.SetArgs(nil)
	err := rootCmd.Execute()
	return out.String(), err
}

func TestRetentionPolicySetCLI_SendsOnlyTheGivenClasses(t *testing.T) {
	f := &fakeRetentionAPI{}
	out, err := runRetentionCLI(t, f, "policy", "set", "--prompts", "7", "--evidence-bundles", "400")
	if err != nil {
		t.Fatalf("policy set: %v (%s)", err, out)
	}
	want := &pb.SetRetentionPolicyRequest{Windows: []*pb.RetentionWindow{
		{Class: pb.RetentionClass_RETENTION_CLASS_PROMPTS, Days: 7},
		{Class: pb.RetentionClass_RETENTION_CLASS_EVIDENCE_BUNDLES, Days: 400},
	}}
	if len(f.sets) != 1 || !proto.Equal(f.sets[0], want) {
		t.Fatalf("sent %v, want %v", f.sets, want)
	}
	if !strings.Contains(out, "revision 3") {
		t.Fatalf("output %q does not name the new revision", out)
	}
}

func TestRetentionPolicySetCLI_NoClassIsAnError(t *testing.T) {
	f := &fakeRetentionAPI{}
	if _, err := runRetentionCLI(t, f, "policy", "set"); err == nil || len(f.sets) != 0 {
		t.Fatalf("policy set with no class = %v, sent %v; want a local error and nothing sent", err, f.sets)
	}
}

func TestRetentionPolicyGetCLI_PrintsEveryWindow(t *testing.T) {
	out, err := runRetentionCLI(t, &fakeRetentionAPI{}, "policy", "get")
	if err != nil {
		t.Fatalf("policy get: %v", err)
	}
	for _, want := range []string{"prompts", "7 days", "evidence-bundles", "365 days (default)", "revision 2", "Not enforced"} {
		if !strings.Contains(out, want) {
			t.Errorf("output %q missing %q", out, want)
		}
	}
}

func TestRetentionHoldCLI(t *testing.T) {
	f := &fakeRetentionAPI{}
	if out, err := runRetentionCLI(t, f, "hold", "set", "org-a", "--reason", "case 7"); err != nil || !strings.Contains(out, "org-a") {
		t.Fatalf("hold set = (%q, %v)", out, err)
	}
	if len(f.holds) != 1 || f.holds[0].GetOrgId() != "org-a" || f.holds[0].GetReason() != "case 7" {
		t.Fatalf("hold set sent %v", f.holds)
	}
	if _, err := runRetentionCLI(t, f, "hold", "set", "org-b"); err == nil {
		t.Fatal("hold set without --reason succeeded")
	}
	if out, err := runRetentionCLI(t, f, "hold", "list"); err != nil || !strings.Contains(out, "org-a") || !strings.Contains(out, "case 7") {
		t.Fatalf("hold list = (%q, %v)", out, err)
	}
	if _, err := runRetentionCLI(t, f, "hold", "release", "org-a"); err != nil || len(f.released) != 1 || f.released[0] != "org-a" {
		t.Fatalf("hold release = %v, released %v", err, f.released)
	}
}

func TestRetentionReportCLI_PrintsCountsCutoffAndMode(t *testing.T) {
	f := &fakeRetentionAPI{}
	out, err := runRetentionCLI(t, f, "report")
	if err != nil {
		t.Fatalf("report: %v (%s)", err, out)
	}
	for _, want := range []string{
		"mode: dry-run", "nothing is deleted", "policy revision 2", "1 active legal hold",
		"prompts", "agent_tasks", "7d", "2026-10-16T12:00:00Z", "5", "3", "2",
		"audit_logs", "not swept", "#2878",
		"agent_task_results", "error", "connection refused",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if len(f.refresh) != 1 || f.refresh[0] {
		t.Errorf("refresh flags sent = %v, want one false", f.refresh)
	}
}

func TestRetentionReportCLI_RefreshFlag(t *testing.T) {
	f := &fakeRetentionAPI{}
	if _, err := runRetentionCLI(t, f, "report", "--refresh"); err != nil {
		t.Fatal(err)
	}
	if len(f.refresh) != 1 || !f.refresh[0] {
		t.Errorf("refresh flags sent = %v, want one true", f.refresh)
	}
}
