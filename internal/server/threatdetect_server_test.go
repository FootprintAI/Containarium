package server

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/netbpf"
	"github.com/footprintai/containarium/internal/threatdetect"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestGetSentryStatus_Disabled(t *testing.T) {
	s := NewThreatDetectionServer(nil, false, false, "")
	resp, err := s.GetSentryStatus(context.Background(), &pb.GetSentryStatusRequest{})
	if err != nil {
		t.Fatalf("GetSentryStatus: %v", err)
	}
	if resp.State != pb.SentryState_SENTRY_STATE_DISABLED {
		t.Errorf("state = %v, want DISABLED", resp.State)
	}
	if resp.Reason == "" {
		t.Error("reason is empty, want an explanation")
	}
}

// Enabled but no eBPF object loaded: must report UNAVAILABLE with a reason,
// never silently "no findings" — the #1640 acceptance criterion.
func TestGetSentryStatus_UnavailableWithoutEBPF(t *testing.T) {
	s := NewThreatDetectionServer(nil, true, false, "eBPF object not loaded (set CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT)")
	resp, err := s.GetSentryStatus(context.Background(), &pb.GetSentryStatusRequest{})
	if err != nil {
		t.Fatalf("GetSentryStatus: %v", err)
	}
	if resp.State != pb.SentryState_SENTRY_STATE_UNAVAILABLE {
		t.Errorf("state = %v, want UNAVAILABLE", resp.State)
	}
	if resp.Reason != "eBPF object not loaded (set CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT)" {
		t.Errorf("reason = %q, want the wired unavailableReason", resp.Reason)
	}
}

func TestGetSentryStatus_Degraded(t *testing.T) {
	engine := threatdetect.NewEngine(&fakeFindingSink{}, "backend-1", true /* degraded */, nil, nil)
	s := NewThreatDetectionServer(engine, true, true, "")
	resp, err := s.GetSentryStatus(context.Background(), &pb.GetSentryStatusRequest{})
	if err != nil {
		t.Fatalf("GetSentryStatus: %v", err)
	}
	if resp.State != pb.SentryState_SENTRY_STATE_DEGRADED {
		t.Errorf("state = %v, want DEGRADED", resp.State)
	}
	if resp.Reason == "" {
		t.Error("reason is empty, want an explanation of the missing persistence")
	}
}

func TestGetSentryStatus_OKWithRuleHealth(t *testing.T) {
	engine := threatdetect.NewEngine(&fakeFindingSink{}, "backend-1", false, nil, nil)
	engine.Register(&fakeRule{id: pb.ThreatRuleId_THREAT_RULE_ID_BAD_DESTINATION})
	s := NewThreatDetectionServer(engine, true, true, "")

	resp, err := s.GetSentryStatus(context.Background(), &pb.GetSentryStatusRequest{})
	if err != nil {
		t.Fatalf("GetSentryStatus: %v", err)
	}
	if resp.State != pb.SentryState_SENTRY_STATE_OK {
		t.Errorf("state = %v, want OK", resp.State)
	}
	if len(resp.Rules) != 1 || resp.Rules[0].Rule != pb.ThreatRuleId_THREAT_RULE_ID_BAD_DESTINATION || !resp.Rules[0].Healthy {
		t.Errorf("rules = %+v, want one healthy BAD_DESTINATION entry", resp.Rules)
	}
}

func TestListBadDestinations_NoRule_ReturnsUnavailable(t *testing.T) {
	s := NewThreatDetectionServer(nil, false, false, "")
	if _, err := s.ListBadDestinations(context.Background(), &pb.ListBadDestinationsRequest{}); err == nil {
		t.Fatal("ListBadDestinations with no rule wired should error, got nil")
	}
}

func TestAddThenListBadDestination(t *testing.T) {
	s := NewThreatDetectionServer(nil, false, false, "")
	rule, err := threatdetect.NewBadDestinationRule(context.Background(), nil)
	if err != nil {
		t.Fatalf("NewBadDestinationRule: %v", err)
	}
	s.SetBadDestinationRule(rule)

	addResp, err := s.AddBadDestination(context.Background(), &pb.AddBadDestinationRequest{Cidr: "192.0.2.55/32", Label: "test entry"})
	if err != nil {
		t.Fatalf("AddBadDestination: %v", err)
	}
	if addResp.GetEntry().GetCidr() != "192.0.2.55/32" || addResp.GetEntry().GetSource() != "operator" {
		t.Errorf("AddBadDestination entry = %+v, want cidr=192.0.2.55/32 source=operator", addResp.GetEntry())
	}

	listResp, err := s.ListBadDestinations(context.Background(), &pb.ListBadDestinationsRequest{})
	if err != nil {
		t.Fatalf("ListBadDestinations: %v", err)
	}
	found := false
	for _, e := range listResp.GetEntries() {
		if e.GetCidr() == "192.0.2.55/32" {
			found = true
		}
	}
	if !found {
		t.Errorf("ListBadDestinations = %+v, want the just-added entry", listResp.GetEntries())
	}
}

func TestAddBadDestination_MissingCidr(t *testing.T) {
	s := NewThreatDetectionServer(nil, false, false, "")
	rule, err := threatdetect.NewBadDestinationRule(context.Background(), nil)
	if err != nil {
		t.Fatalf("NewBadDestinationRule: %v", err)
	}
	s.SetBadDestinationRule(rule)

	if _, err := s.AddBadDestination(context.Background(), &pb.AddBadDestinationRequest{Label: "no cidr"}); err == nil {
		t.Fatal("AddBadDestination with no cidr should error, got nil")
	}
}

func TestRemoveBadDestination_NotFound(t *testing.T) {
	s := NewThreatDetectionServer(nil, false, false, "")
	rule, err := threatdetect.NewBadDestinationRule(context.Background(), nil)
	if err != nil {
		t.Fatalf("NewBadDestinationRule: %v", err)
	}
	s.SetBadDestinationRule(rule)

	if _, err := s.RemoveBadDestination(context.Background(), &pb.RemoveBadDestinationRequest{Cidr: "192.0.2.99/32"}); err == nil {
		t.Fatal("RemoveBadDestination on a never-added entry should error, got nil")
	}
}

func TestRemoveBadDestination_RoundTrip(t *testing.T) {
	s := NewThreatDetectionServer(nil, false, false, "")
	rule, err := threatdetect.NewBadDestinationRule(context.Background(), nil)
	if err != nil {
		t.Fatalf("NewBadDestinationRule: %v", err)
	}
	s.SetBadDestinationRule(rule)

	if _, err := s.AddBadDestination(context.Background(), &pb.AddBadDestinationRequest{Cidr: "192.0.2.55/32", Label: "temp"}); err != nil {
		t.Fatalf("AddBadDestination: %v", err)
	}
	if _, err := s.RemoveBadDestination(context.Background(), &pb.RemoveBadDestinationRequest{Cidr: "192.0.2.55/32"}); err != nil {
		t.Fatalf("RemoveBadDestination: %v", err)
	}
	listResp, err := s.ListBadDestinations(context.Background(), &pb.ListBadDestinationsRequest{})
	if err != nil {
		t.Fatalf("ListBadDestinations: %v", err)
	}
	for _, e := range listResp.GetEntries() {
		if e.GetCidr() == "192.0.2.55/32" {
			t.Errorf("entry still listed after removal: %+v", e)
		}
	}
}

func TestListFindings_NoStore_ReturnsUnavailable(t *testing.T) {
	s := NewThreatDetectionServer(nil, false, false, "")
	ctx := auth.ContextWithTestSubject(context.Background(), "alice", auth.RoleAdmin)
	_, err := s.ListFindings(ctx, &pb.ListFindingsRequest{})
	if status.Code(err) != codes.Unavailable {
		t.Errorf("code = %v, want Unavailable", status.Code(err))
	}
}

func TestListFindings_Unauthenticated(t *testing.T) {
	s := NewThreatDetectionServer(nil, false, false, "")
	s.SetFindingStore(&fakeFindingReader{})
	if _, err := s.ListFindings(context.Background(), &pb.ListFindingsRequest{}); err == nil {
		t.Fatal("ListFindings with no authenticated subject should error, got nil")
	}
}

// Admin sees every tenant: an explicit tenant_id filter passes through
// unchanged to the store.
func TestListFindings_Admin_SeesRequestedTenant(t *testing.T) {
	store := &fakeFindingReader{
		findings: []*threatdetect.Finding{{ID: 1, TenantID: "bob", Severity: pb.ThreatSeverity_THREAT_SEVERITY_HIGH, State: threatdetect.FindingStateOpen}},
	}
	s := NewThreatDetectionServer(nil, false, false, "")
	s.SetFindingStore(store)

	ctx := auth.ContextWithTestSubject(context.Background(), "alice", auth.RoleAdmin)
	resp, err := s.ListFindings(ctx, &pb.ListFindingsRequest{TenantId: "bob"})
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if store.lastFilter.TenantID != "bob" {
		t.Errorf("store received TenantID = %q, want %q (admin's explicit filter passed through)", store.lastFilter.TenantID, "bob")
	}
	if len(resp.Findings) != 1 || resp.Findings[0].TenantId != "bob" {
		t.Errorf("Findings = %+v, want the one bob finding", resp.Findings)
	}
}

// Non-admin: an unset tenant_id filter is forced to the caller's own
// subject, same as ListContainersRequest.username — findings are the same
// "who can see whose stuff" boundary as containers.
func TestListFindings_NonAdmin_ForcedToOwnTenant(t *testing.T) {
	store := &fakeFindingReader{}
	s := NewThreatDetectionServer(nil, false, false, "")
	s.SetFindingStore(store)

	ctx := auth.ContextWithTestSubject(context.Background(), "alice", "member")
	if _, err := s.ListFindings(ctx, &pb.ListFindingsRequest{}); err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if store.lastFilter.TenantID != "alice" {
		t.Errorf("store received TenantID = %q, want %q (forced to subject)", store.lastFilter.TenantID, "alice")
	}
}

// Non-admin requesting a different tenant's findings is denied outright —
// never silently rewritten to their own (that would look like "it worked"
// while actually returning the wrong data).
func TestListFindings_NonAdmin_ExplicitOtherTenant_Denied(t *testing.T) {
	store := &fakeFindingReader{}
	s := NewThreatDetectionServer(nil, false, false, "")
	s.SetFindingStore(store)

	ctx := auth.ContextWithTestSubject(context.Background(), "alice", "member")
	if _, err := s.ListFindings(ctx, &pb.ListFindingsRequest{TenantId: "bob"}); err == nil {
		t.Fatal("ListFindings for another tenant as non-admin should error, got nil")
	}
}

func TestListFindings_FiltersPassThrough(t *testing.T) {
	store := &fakeFindingReader{}
	s := NewThreatDetectionServer(nil, false, false, "")
	s.SetFindingStore(store)

	ctx := auth.ContextWithTestSubject(context.Background(), "alice", auth.RoleAdmin)
	_, err := s.ListFindings(ctx, &pb.ListFindingsRequest{
		Severity: pb.ThreatSeverity_THREAT_SEVERITY_CRITICAL,
		State:    pb.FindingState_FINDING_STATE_OPEN,
		Limit:    10,
	})
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if store.lastFilter.Severity != pb.ThreatSeverity_THREAT_SEVERITY_CRITICAL {
		t.Errorf("Severity = %v, want CRITICAL", store.lastFilter.Severity)
	}
	if store.lastFilter.State != threatdetect.FindingStateOpen {
		t.Errorf("State = %v, want open", store.lastFilter.State)
	}
	if store.lastFilter.Limit != 10 {
		t.Errorf("Limit = %d, want 10", store.lastFilter.Limit)
	}
}

func TestResolveFinding_NoStore_ReturnsUnavailable(t *testing.T) {
	s := NewThreatDetectionServer(nil, false, false, "")
	ctx := auth.ContextWithTestSubject(context.Background(), "alice", auth.RoleAdmin)
	_, err := s.ResolveFinding(ctx, &pb.ResolveFindingRequest{Id: 1})
	if status.Code(err) != codes.Unavailable {
		t.Errorf("code = %v, want Unavailable", status.Code(err))
	}
}

func TestResolveFinding_MissingID(t *testing.T) {
	s := NewThreatDetectionServer(nil, false, false, "")
	s.SetFindingStore(&fakeFindingReader{})
	ctx := auth.ContextWithTestSubject(context.Background(), "alice", auth.RoleAdmin)
	_, err := s.ResolveFinding(ctx, &pb.ResolveFindingRequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", status.Code(err))
	}
}

func TestResolveFinding_NotFound(t *testing.T) {
	s := NewThreatDetectionServer(nil, false, false, "")
	s.SetFindingStore(&fakeFindingReader{resolveErr: threatdetect.ErrFindingNotFound})
	ctx := auth.ContextWithTestSubject(context.Background(), "alice", auth.RoleAdmin)
	_, err := s.ResolveFinding(ctx, &pb.ResolveFindingRequest{Id: 99})
	if status.Code(err) != codes.NotFound {
		t.Errorf("code = %v, want NotFound", status.Code(err))
	}
}

func TestResolveFinding_AlreadyResolved(t *testing.T) {
	s := NewThreatDetectionServer(nil, false, false, "")
	s.SetFindingStore(&fakeFindingReader{resolveErr: threatdetect.ErrFindingNotOpen})
	ctx := auth.ContextWithTestSubject(context.Background(), "alice", auth.RoleAdmin)
	_, err := s.ResolveFinding(ctx, &pb.ResolveFindingRequest{Id: 1})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", status.Code(err))
	}
}

func TestResolveFinding_Success(t *testing.T) {
	store := &fakeFindingReader{
		resolved: &threatdetect.Finding{ID: 1, State: threatdetect.FindingStateResolved},
	}
	s := NewThreatDetectionServer(nil, false, false, "")
	s.SetFindingStore(store)
	ctx := auth.ContextWithTestSubject(context.Background(), "alice", auth.RoleAdmin)
	resp, err := s.ResolveFinding(ctx, &pb.ResolveFindingRequest{Id: 1})
	if err != nil {
		t.Fatalf("ResolveFinding: %v", err)
	}
	if resp.Finding.State != pb.FindingState_FINDING_STATE_RESOLVED {
		t.Errorf("state = %v, want RESOLVED", resp.Finding.State)
	}
}

// fakeFindingReader is a minimal threatdetect.FindingReader test double.
type fakeFindingReader struct {
	findings   []*threatdetect.Finding
	lastFilter threatdetect.ListFilter
	resolved   *threatdetect.Finding
	resolveErr error
}

func (f *fakeFindingReader) Get(ctx context.Context, id int64) (*threatdetect.Finding, error) {
	return nil, threatdetect.ErrFindingNotFound
}

func (f *fakeFindingReader) List(ctx context.Context, filter threatdetect.ListFilter) ([]*threatdetect.Finding, error) {
	f.lastFilter = filter
	return f.findings, nil
}

func (f *fakeFindingReader) Resolve(ctx context.Context, id int64) (*threatdetect.Finding, error) {
	if f.resolveErr != nil {
		return nil, f.resolveErr
	}
	return f.resolved, nil
}

// fakeFindingSink and fakeRule are minimal threatdetect.FindingSink /
// threatdetect.Rule test doubles — this file only needs an Engine to exist
// and report status, not to actually detect anything.
type fakeFindingSink struct{}

func (fakeFindingSink) Upsert(ctx context.Context, f *threatdetect.Finding) (*threatdetect.Finding, error) {
	return f, nil
}

type fakeRule struct{ id pb.ThreatRuleId }

func (r *fakeRule) ID() pb.ThreatRuleId { return r.id }
func (r *fakeRule) OnFlows(threatdetect.RuleContext, []netbpf.FlowRecord) []threatdetect.RawFinding {
	return nil
}
func (r *fakeRule) OnDeny(threatdetect.RuleContext, netbpf.DenyEvent) []threatdetect.RawFinding {
	return nil
}
func (r *fakeRule) Sweep(threatdetect.RuleContext, time.Time) []threatdetect.RawFinding {
	return nil
}
