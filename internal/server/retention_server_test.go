package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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
// release each write one entry naming the admin who made it.
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
	if _, err := s.ReleaseLegalHold(ctx, &pb.ReleaseLegalHoldRequest{OrgId: "org-a"}); err != nil {
		t.Fatalf("ReleaseLegalHold: %v", err)
	}
	entry := func(action string) string {
		t.Helper()
		got := a.byAction(action)
		if len(got) != 1 || got[0].Username != "ops" {
			t.Fatalf("%s entries = %+v, want one by ops", action, got)
		}
		return got[0].Detail
	}
	var pol retentionPolicyAuditDetail
	if err := json.Unmarshal([]byte(entry(retentionPolicySetAction)), &pol); err != nil {
		t.Fatalf("policy detail: %v", err)
	}
	wantPol := retentionPolicyAuditDetail{PreviousRevision: 0, Revision: 1,
		Windows: []retentionAuditWindow{{Class: "RETENTION_CLASS_PROMPTS", Days: 7}}}
	if fmt.Sprint(pol) != fmt.Sprint(wantPol) {
		t.Errorf("policy detail = %+v, want %+v", pol, wantPol)
	}
	for _, action := range []string{retentionHoldSetAction, retentionHoldReleaseAction} {
		var hold retentionHoldAuditDetail
		if err := json.Unmarshal([]byte(entry(action)), &hold); err != nil {
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
