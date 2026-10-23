package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/retention"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func newRetentionTestServer() (*RetentionServer, *fakeAuditLogger) {
	s := NewRetentionServer(retention.NewMemoryStore())
	a := &fakeAuditLogger{}
	s.SetAuditStore(a)
	return s, a
}

func promptsDays(days int32) *pb.SetRetentionPolicyRequest {
	return &pb.SetRetentionPolicyRequest{Windows: []*pb.RetentionWindow{
		{Class: pb.RetentionClass_RETENTION_CLASS_PROMPTS, Days: days},
	}}
}

// TestRetentionServer_AdminOnly: every RPC refuses a non-admin and an
// unauthenticated caller, and a refused change writes no audit entry.
func TestRetentionServer_AdminOnly(t *testing.T) {
	calls := map[string]func(context.Context, *RetentionServer) error{
		"get policy": func(ctx context.Context, s *RetentionServer) error {
			_, err := s.GetRetentionPolicy(ctx, &pb.GetRetentionPolicyRequest{})
			return err
		},
		"get report": func(ctx context.Context, s *RetentionServer) error {
			_, err := s.GetRetentionReport(ctx, &pb.GetRetentionReportRequest{})
			return err
		},
		"get mode": func(ctx context.Context, s *RetentionServer) error {
			_, err := s.GetRetentionMode(ctx, &pb.GetRetentionModeRequest{})
			return err
		},
		"set mode": func(ctx context.Context, s *RetentionServer) error {
			_, err := s.SetRetentionMode(ctx, &pb.SetRetentionModeRequest{Mode: pb.RetentionMode_RETENTION_MODE_ENFORCE})
			return err
		},
		"set policy": func(ctx context.Context, s *RetentionServer) error {
			_, err := s.SetRetentionPolicy(ctx, promptsDays(7))
			return err
		},
		"list holds": func(ctx context.Context, s *RetentionServer) error {
			_, err := s.ListLegalHolds(ctx, &pb.ListLegalHoldsRequest{})
			return err
		},
		"set hold": func(ctx context.Context, s *RetentionServer) error {
			_, err := s.SetLegalHold(ctx, &pb.SetLegalHoldRequest{OrgId: "org-a", Reason: "case"})
			return err
		},
		"release hold": func(ctx context.Context, s *RetentionServer) error {
			_, err := s.ReleaseLegalHold(ctx, &pb.ReleaseLegalHoldRequest{OrgId: "org-a"})
			return err
		},
	}
	callers := map[string]struct {
		ctx  context.Context
		want codes.Code
	}{
		"non-admin":       {gpUserCtx(), codes.PermissionDenied},
		"unauthenticated": {context.Background(), codes.Unauthenticated},
	}
	for name, call := range calls {
		for who, c := range callers {
			t.Run(name+" as "+who, func(t *testing.T) {
				s, a := newRetentionTestServer()
				if _, err := s.SetLegalHold(gpAdminCtx(), &pb.SetLegalHoldRequest{OrgId: "org-a", Reason: "seed"}); err != nil {
					t.Fatalf("seed hold: %v", err)
				}
				before := len(a.entries)
				if got := status.Code(call(c.ctx, s)); got != c.want {
					t.Fatalf("%s as %s = %v, want %v", name, who, got, c.want)
				}
				if len(a.entries) != before {
					t.Fatalf("a refused call wrote %d audit entries", len(a.entries)-before)
				}
			})
		}
	}
}

// TestRetentionServer_ChangesAreAuditedWithTheCaller: a set, a hold and a
// release each write one entry naming the admin who made it. The hold is
// released by a different admin, so the release entry must name the releaser
// while its detail keeps who set the hold.
func TestRetentionServer_ChangesAreAuditedWithTheCaller(t *testing.T) {
	s, a := newRetentionTestServer()
	ctx := gpAdminCtx()
	resp, err := s.SetRetentionPolicy(ctx, promptsDays(7))
	if err != nil {
		t.Fatalf("SetRetentionPolicy: %v", err)
	}
	if resp.GetPolicy().GetRevision() != 1 || resp.GetPolicy().GetUpdatedBy() != "ops" {
		t.Fatalf("policy = %v, want revision 1 by ops", resp.GetPolicy())
	}
	if _, err := s.SetLegalHold(ctx, &pb.SetLegalHoldRequest{OrgId: "org-a", Reason: "case 7"}); err != nil {
		t.Fatalf("SetLegalHold: %v", err)
	}
	releaser := auth.ContextWithTestSubject(context.Background(), "ops-2", auth.RoleAdmin)
	if _, err := s.ReleaseLegalHold(releaser, &pb.ReleaseLegalHoldRequest{OrgId: "org-a"}); err != nil {
		t.Fatalf("ReleaseLegalHold: %v", err)
	}
	entry := func(action, by string) string {
		t.Helper()
		got := a.byAction(action)
		if len(got) != 1 || got[0].Username != by {
			t.Fatalf("%s entries = %+v, want one by %s", action, got, by)
		}
		return got[0].Detail
	}
	var pol retentionPolicyAuditDetail
	if err := json.Unmarshal([]byte(entry(retentionPolicySetAction, "ops")), &pol); err != nil {
		t.Fatalf("policy detail: %v", err)
	}
	wantPol := retentionPolicyAuditDetail{PreviousRevision: 0, Revision: 1,
		Windows: []retentionAuditWindow{{Class: "RETENTION_CLASS_PROMPTS", Days: 7}}}
	if fmt.Sprint(pol) != fmt.Sprint(wantPol) {
		t.Errorf("policy detail = %+v, want %+v", pol, wantPol)
	}
	for action, by := range map[string]string{retentionHoldSetAction: "ops", retentionHoldReleaseAction: "ops-2"} {
		var hold retentionHoldAuditDetail
		if err := json.Unmarshal([]byte(entry(action, by)), &hold); err != nil {
			t.Fatalf("%s detail: %v", action, err)
		}
		if hold.OrgID != "org-a" || hold.Reason != "case 7" || hold.SetBy != "ops" {
			t.Errorf("%s detail = %+v, want org-a, case 7, set by ops", action, hold)
		}
	}
}

// TestRetentionServer_FailedAuditFailsTheChange: when the audit entry cannot
// be written, the call fails with INTERNAL and nothing changes.
func TestRetentionServer_FailedAuditFailsTheChange(t *testing.T) {
	ctx := gpAdminCtx()
	s, a := newRetentionTestServer()
	if _, err := s.SetLegalHold(ctx, &pb.SetLegalHoldRequest{OrgId: "org-held", Reason: "seed"}); err != nil {
		t.Fatalf("seed hold: %v", err)
	}
	a.err = errors.New("audit store down")

	if _, err := s.SetRetentionPolicy(ctx, promptsDays(7)); status.Code(err) != codes.Internal {
		t.Fatalf("SetRetentionPolicy with audit down = %v, want Internal", err)
	}
	if _, err := s.SetLegalHold(ctx, &pb.SetLegalHoldRequest{OrgId: "org-new", Reason: "case"}); status.Code(err) != codes.Internal {
		t.Fatalf("SetLegalHold with audit down = %v, want Internal", err)
	}
	if _, err := s.ReleaseLegalHold(ctx, &pb.ReleaseLegalHoldRequest{OrgId: "org-held"}); status.Code(err) != codes.Internal {
		t.Fatalf("ReleaseLegalHold with audit down = %v, want Internal", err)
	}
	p, _ := s.GetRetentionPolicy(ctx, &pb.GetRetentionPolicyRequest{})
	if p.GetPolicy().GetRevision() != 0 || p.GetPolicy().GetWindows()[0].GetDays() != 30 {
		t.Fatalf("policy after a failed audit = %v, want unchanged defaults", p.GetPolicy())
	}
	holds, _ := s.ListLegalHolds(ctx, &pb.ListLegalHoldsRequest{})
	if len(holds.GetHolds()) != 1 || holds.GetHolds()[0].GetOrgId() != "org-held" {
		t.Fatalf("holds after a failed audit = %v, want only org-held", holds.GetHolds())
	}
}

// TestRetentionServer_NoAuditStoreStillChanges: with no audit store (no
// Postgres, REST disabled, or an audit store that failed to start) a change
// succeeds and writes no entry, as for the guardrail baseline switch.
func TestRetentionServer_NoAuditStoreStillChanges(t *testing.T) {
	s := NewRetentionServer(retention.NewMemoryStore())
	if _, err := s.SetRetentionPolicy(gpAdminCtx(), promptsDays(7)); err != nil {
		t.Fatalf("SetRetentionPolicy with no audit store: %v", err)
	}
}

// TestRetentionServer_ErrorCodes maps store errors onto gRPC codes.
func TestRetentionServer_ErrorCodes(t *testing.T) {
	ctx := gpAdminCtx()
	s, _ := newRetentionTestServer()
	cases := []struct {
		name string
		call func() error
		want codes.Code
	}{
		{"zero days", func() error { _, err := s.SetRetentionPolicy(ctx, promptsDays(0)); return err }, codes.InvalidArgument},
		{"unknown class", func() error {
			_, err := s.SetRetentionPolicy(ctx, &pb.SetRetentionPolicyRequest{Windows: []*pb.RetentionWindow{{Class: 99, Days: 5}}})
			return err
		}, codes.InvalidArgument},
		{"hold without reason", func() error {
			_, err := s.SetLegalHold(ctx, &pb.SetLegalHoldRequest{OrgId: "org-a"})
			return err
		}, codes.InvalidArgument},
		{"release unknown org", func() error {
			_, err := s.ReleaseLegalHold(ctx, &pb.ReleaseLegalHoldRequest{OrgId: "org-none"})
			return err
		}, codes.NotFound},
		{"hold twice", func() error {
			if _, err := s.SetLegalHold(ctx, &pb.SetLegalHoldRequest{OrgId: "org-b", Reason: "r"}); err != nil {
				return err
			}
			_, err := s.SetLegalHold(ctx, &pb.SetLegalHoldRequest{OrgId: "org-b", Reason: "r"})
			return err
		}, codes.AlreadyExists},
		{"store unavailable", func() error {
			_, err := NewRetentionServer(unavailableRetentionStore{}).GetRetentionPolicy(ctx, &pb.GetRetentionPolicyRequest{})
			return err
		}, codes.Unavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := status.Code(tc.call()); got != tc.want {
				t.Fatalf("%s = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

// countingSource answers with a fixed count and tallies its calls.
type countingSource struct {
	calls int
	count retention.Count
}

func (c *countingSource) Class() pb.RetentionClass { return pb.RetentionClass_RETENTION_CLASS_PROMPTS }
func (c *countingSource) Store() string            { return "agent_tasks" }
func (c *countingSource) Count(context.Context, time.Time, []string) (retention.Count, error) {
	c.calls++
	return c.count, nil
}

func TestRetentionServer_GetRetentionReport(t *testing.T) {
	s, _ := newRetentionTestServer()
	src := &countingSource{count: retention.Count{Older: 3, Eligible: 3}}
	s.SetReporter(retention.NewReporter(retention.NewSweeper(retention.NewMemoryStore(), []retention.Source{src},
		[]retention.Unswept{{Class: pb.RetentionClass_RETENTION_CLASS_EVIDENCE_BUNDLES, Store: "evidence_bundles", Note: "no store yet (#2879)"}})))

	resp, err := s.GetRetentionReport(gpAdminCtx(), &pb.GetRetentionReportRequest{})
	if err != nil {
		t.Fatalf("GetRetentionReport: %v", err)
	}
	if resp.GetReport().GetMode() != pb.RetentionMode_RETENTION_MODE_DRY_RUN || len(resp.GetReport().GetStores()) != 2 {
		t.Fatalf("report = %v", resp.GetReport())
	}
	if _, err := s.GetRetentionReport(gpAdminCtx(), &pb.GetRetentionReportRequest{}); err != nil || src.calls != 1 {
		t.Fatalf("second call: err=%v, sweeps=%d; want the kept report (1 sweep)", err, src.calls)
	}
	if _, err := s.GetRetentionReport(gpAdminCtx(), &pb.GetRetentionReportRequest{Refresh: true}); err != nil || src.calls != 2 {
		t.Fatalf("refresh: err=%v, sweeps=%d; want a new sweep (2)", err, src.calls)
	}
}

func TestRetentionServer_GetRetentionReportWithoutAReporterIsUnavailable(t *testing.T) {
	s, _ := newRetentionTestServer()
	_, err := s.GetRetentionReport(gpAdminCtx(), &pb.GetRetentionReportRequest{})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v (%v), want Unavailable", status.Code(err), err)
	}
}

func TestRetentionServer_GetRetentionReportWithAnUnavailableStoreIsUnavailable(t *testing.T) {
	s, _ := newRetentionTestServer()
	s.SetReporter(retention.NewReporter(retention.NewSweeper(unavailableRetentionStore{}, nil, nil)))
	_, err := s.GetRetentionReport(gpAdminCtx(), &pb.GetRetentionReportRequest{})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v (%v), want Unavailable", status.Code(err), err)
	}
}

// With no database pool the daemon still answers: every Postgres-backed store
// is listed NOT_SWEPT with the reason, next to the chained and bundle classes.
func TestNewRetentionReporter_NoPoolListsEveryStoreNotSwept(t *testing.T) {
	rep, err := newRetentionReporter(retention.NewMemoryStore(), nil).Report(context.Background(), false)
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	notes := map[string]string{}
	for _, s := range rep.GetStores() {
		if s.GetStatus() != pb.RetentionSweepStatus_RETENTION_SWEEP_STATUS_NOT_SWEPT {
			t.Errorf("%v/%s status = %v, want NOT_SWEPT with no database", s.GetClass(), s.GetStore(), s.GetStatus())
		}
		notes[s.GetClass().String()+"/"+s.GetStore()] = s.GetNote()
	}
	for key, want := range map[string]string{
		"RETENTION_CLASS_PROMPTS/agent_tasks":               "no database",
		"RETENTION_CLASS_GATEWAY_LOGS/traffic_connections":  "no database",
		"RETENTION_CLASS_GATEWAY_LOGS/audit_logs":           "#2878",
		"RETENTION_CLASS_SESSION_TRANSCRIPTS/audit_logs":    "#2878",
		"RETENTION_CLASS_EVIDENCE_BUNDLES/evidence_bundles": "#2879",
	} {
		if got, ok := notes[key]; !ok || !strings.Contains(got, want) {
			t.Errorf("%s note = %q (present %v), want it to mention %q", key, got, ok, want)
		}
	}
}

// removingSource is a count-and-delete source that tallies its removals.
type removingSource struct {
	countingSource
	removals int
}

func (r *removingSource) Remove(context.Context, time.Time, []string, int) (int64, error) {
	r.removals++
	return r.count.Eligible, nil
}

// TestRetentionServer_ModeStartsDryRunAndSwitchIsAuditedWithTheCaller: the
// default is DRY_RUN; a switch writes one entry naming the admin, with the
// mode it replaced.
func TestRetentionServer_ModeStartsDryRunAndSwitchIsAuditedWithTheCaller(t *testing.T) {
	s, a := newRetentionTestServer()
	ctx := gpAdminCtx()
	got, err := s.GetRetentionMode(ctx, &pb.GetRetentionModeRequest{})
	if err != nil || got.GetState().GetMode() != pb.RetentionMode_RETENTION_MODE_DRY_RUN {
		t.Fatalf("default mode = %v (%v), want DRY_RUN", got.GetState(), err)
	}
	set, err := s.SetRetentionMode(ctx, &pb.SetRetentionModeRequest{Mode: pb.RetentionMode_RETENTION_MODE_ENFORCE})
	if err != nil {
		t.Fatalf("SetRetentionMode: %v", err)
	}
	if set.GetState().GetMode() != pb.RetentionMode_RETENTION_MODE_ENFORCE || set.GetState().GetUpdatedBy() != "ops" {
		t.Fatalf("state = %v, want ENFORCE by ops", set.GetState())
	}
	entries := a.byAction(retentionModeSetAction)
	if len(entries) != 1 || entries[0].Username != "ops" {
		t.Fatalf("%s entries = %+v, want one by ops", retentionModeSetAction, entries)
	}
	var d retentionModeAuditDetail
	if err := json.Unmarshal([]byte(entries[0].Detail), &d); err != nil {
		t.Fatalf("detail: %v", err)
	}
	if d.PreviousMode != "RETENTION_MODE_DRY_RUN" || d.Mode != "RETENTION_MODE_ENFORCE" {
		t.Errorf("detail = %+v, want DRY_RUN -> ENFORCE", d)
	}
}

func TestRetentionServer_ASwitchWithADownAuditStoreChangesNothing(t *testing.T) {
	s, a := newRetentionTestServer()
	a.err = errors.New("audit store down")
	if _, err := s.SetRetentionMode(gpAdminCtx(), &pb.SetRetentionModeRequest{Mode: pb.RetentionMode_RETENTION_MODE_ENFORCE}); status.Code(err) != codes.Internal {
		t.Fatalf("SetRetentionMode with audit down = %v, want Internal", err)
	}
	if got, _ := s.GetRetentionMode(gpAdminCtx(), &pb.GetRetentionModeRequest{}); got.GetState().GetMode() != pb.RetentionMode_RETENTION_MODE_DRY_RUN {
		t.Errorf("mode after a failed audit = %v, want DRY_RUN kept", got.GetState().GetMode())
	}
}

func TestRetentionServer_AnInvalidModeIsRefusedAndNotAudited(t *testing.T) {
	s, a := newRetentionTestServer()
	for _, m := range []pb.RetentionMode{pb.RetentionMode_RETENTION_MODE_UNSPECIFIED, pb.RetentionMode(42)} {
		if _, err := s.SetRetentionMode(gpAdminCtx(), &pb.SetRetentionModeRequest{Mode: m}); status.Code(err) != codes.InvalidArgument {
			t.Errorf("SetRetentionMode(%v) = %v, want InvalidArgument", m, err)
		}
	}
	if len(a.entries) != 0 {
		t.Errorf("refused switches wrote %d audit entries", len(a.entries))
	}
}

// TestRetentionServer_AnEnforcedSweepWritesOneEntryWithCountsOnly: the entry
// carries per-class, per-store counts and no record content; a DRY_RUN sweep
// writes none.
func TestRetentionServer_AnEnforcedSweepWritesOneEntryWithCountsOnly(t *testing.T) {
	store := retention.NewMemoryStore()
	src := &removingSource{countingSource: countingSource{count: retention.Count{Older: 5, Eligible: 4}}}
	reporter := retention.NewReporter(retention.NewSweeper(store, []retention.Source{src}, nil))
	s, a := newRetentionTestServer()
	s.SetStore(store)
	s.SetReporter(reporter)

	runOnce := func() {
		t.Helper()
		prev := reporter.Last()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { reporter.Run(ctx, time.Hour); close(done) }()
		deadline := time.After(5 * time.Second)
		for reporter.Last() == prev { // wait for this run's start-up sweep
			select {
			case <-deadline:
				t.Fatal("no sweep ran")
			case <-time.After(5 * time.Millisecond):
			}
		}
		cancel()
		<-done
	}

	runOnce() // DRY_RUN
	if n := len(a.byAction(retentionSweepAction)); n != 0 || src.removals != 0 {
		t.Fatalf("a DRY_RUN sweep wrote %d entries and removed %d times, want neither", n, src.removals)
	}
	if _, err := s.SetRetentionMode(gpAdminCtx(), &pb.SetRetentionModeRequest{Mode: pb.RetentionMode_RETENTION_MODE_ENFORCE}); err != nil {
		t.Fatal(err)
	}
	runOnce() // ENFORCE
	entries := a.byAction(retentionSweepAction)
	if len(entries) != 1 || src.removals != 1 {
		t.Fatalf("an ENFORCE sweep wrote %d entries and removed %d times, want one of each", len(entries), src.removals)
	}
	var d retentionSweepAuditDetail
	if err := json.Unmarshal([]byte(entries[0].Detail), &d); err != nil {
		t.Fatalf("detail: %v", err)
	}
	want := []retentionSweepAuditStore{{Class: "RETENTION_CLASS_PROMPTS", Store: "agent_tasks", WindowDays: 30, Eligible: 4, Held: 1}}
	if fmt.Sprint(d.Stores) != fmt.Sprint(want) {
		t.Errorf("stores = %+v, want %+v", d.Stores, want)
	}
	if entries[0].Username != retentionSweeperActor {
		t.Errorf("entry by %q, want the sweeper actor %q", entries[0].Username, retentionSweeperActor)
	}
}

func TestRetentionServer_ASweepWithADownAuditStoreRemovesNothing(t *testing.T) {
	store := retention.NewMemoryStore()
	if _, err := store.SetMode(context.Background(), pb.RetentionMode_RETENTION_MODE_ENFORCE, "ops", nil); err != nil {
		t.Fatal(err)
	}
	src := &removingSource{countingSource: countingSource{count: retention.Count{Older: 2, Eligible: 2}}}
	reporter := retention.NewReporter(retention.NewSweeper(store, []retention.Source{src}, nil))
	s, a := newRetentionTestServer()
	s.SetReporter(reporter)
	a.err = errors.New("audit store down")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { reporter.Run(ctx, time.Hour); close(done) }()
	deadline := time.After(5 * time.Second)
	for len(a.byAction(retentionSweepAction)) == 0 { // the sweep reached its audit write
		select {
		case <-deadline:
			t.Fatal("the enforced sweep never tried to write its audit entry")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done
	if src.removals != 0 {
		t.Errorf("removals = %d after a failed audit write, want none", src.removals)
	}
}
