package server

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/guardrailpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

const (
	gpModeLog   = pb.GuardrailBaselineMode_GUARDRAIL_BASELINE_MODE_LOG
	gpModeBlock = pb.GuardrailBaselineMode_GUARDRAIL_BASELINE_MODE_BLOCK
)

func gpSetMode(ctx context.Context, s *GuardrailPolicyServer, mode pb.GuardrailBaselineMode) (*pb.SetGuardrailBaselineModeResponse, error) {
	return s.SetGuardrailBaselineMode(ctx, &pb.SetGuardrailBaselineModeRequest{Mode: mode})
}

// TestSetBaselineMode_AdminOnly (#2738): only an admin may switch the
// baseline mode; a refused call changes nothing and writes no audit entry.
func TestSetBaselineMode_AdminOnly(t *testing.T) {
	cases := []struct {
		name string
		ctx  context.Context
		mode pb.GuardrailBaselineMode
		want codes.Code
	}{
		{"admin", gpAdminCtx(), gpModeBlock, codes.OK},
		{"non-admin", gpUserCtx(), gpModeBlock, codes.PermissionDenied},
		{"unauthenticated", context.Background(), gpModeBlock, codes.Unauthenticated},
		{"unspecified mode", gpAdminCtx(), pb.GuardrailBaselineMode_GUARDRAIL_BASELINE_MODE_UNSPECIFIED, codes.InvalidArgument},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, audit := newGPServer()
			changed := 0
			s.SetOnChange(func() { changed++ })
			_, err := gpSetMode(tc.ctx, s, tc.mode)
			if got := status.Code(err); got != tc.want {
				t.Fatalf("SetGuardrailBaselineMode as %s = %v (%v), want %v", tc.name, got, err, tc.want)
			}
			st, err := s.GetGuardrailStatus(gpUserCtx(), &pb.GetGuardrailStatusRequest{})
			if err != nil {
				t.Fatalf("GetGuardrailStatus: %v", err)
			}
			ok := tc.want == codes.OK
			wantMode, wantRev, wantEntries, wantChanged := gpModeLog, int64(0), 0, 0
			if ok {
				wantMode, wantRev, wantEntries, wantChanged = gpModeBlock, 1, 1, 1
			}
			if st.GetBaseline().GetMode() != wantMode || st.GetBaseline().GetRevision() != wantRev {
				t.Fatalf("baseline after a %s set = %v, want %v at revision %d", tc.name, st.GetBaseline(), wantMode, wantRev)
			}
			if n := len(audit.byAction(guardrailBaselineSetAction)); n != wantEntries {
				t.Fatalf("audit entries = %d, want %d", n, wantEntries)
			}
			if changed != wantChanged {
				t.Fatalf("onChange ran %d times, want %d (the gateway must re-read on a switch)", changed, wantChanged)
			}
			// Setting the mode never configures a policy: the baseline stays on.
			if st.GetResponsePolicy() != pb.GuardrailEffectivePolicy_GUARDRAIL_EFFECTIVE_POLICY_BASELINE {
				t.Fatalf("response policy after a %s set = %v, want BASELINE", tc.name, st.GetResponsePolicy())
			}
		})
	}
}

// TestSetBaselineMode_AuditEntryNamesCaller (#2738): every switch writes one
// guardrail.baseline.set entry attributed to the caller, with the previous
// and new mode and revision.
func TestSetBaselineMode_AuditEntryNamesCaller(t *testing.T) {
	s, audit := newGPServer()
	first, err := gpSetMode(gpAdminCtx(), s, gpModeBlock)
	if err != nil {
		t.Fatalf("set BLOCK: %v", err)
	}
	if first.GetBaseline().GetMode() != gpModeBlock || first.GetBaseline().GetRevision() != 1 || first.GetBaseline().GetUpdatedBy() != "ops" {
		t.Fatalf("response = %v, want BLOCK at revision 1 by ops", first.GetBaseline())
	}
	if _, err := gpSetMode(gpAdminCtx(), s, gpModeLog); err != nil {
		t.Fatalf("set LOG: %v", err)
	}
	entries := audit.byAction(guardrailBaselineSetAction)
	if len(entries) != 2 {
		t.Fatalf("audit entries = %d, want 2", len(entries))
	}
	want := []guardrailBaselineAuditDetail{
		{PreviousMode: "GUARDRAIL_BASELINE_MODE_LOG", PreviousRevision: 0, Mode: "GUARDRAIL_BASELINE_MODE_BLOCK", Revision: 1},
		{PreviousMode: "GUARDRAIL_BASELINE_MODE_BLOCK", PreviousRevision: 1, Mode: "GUARDRAIL_BASELINE_MODE_LOG", Revision: 2},
	}
	for i, e := range entries {
		if e.Username != "ops" || e.ResourceType != "guardrail_baseline" || e.ResourceID != "cluster" {
			t.Fatalf("entry %d = user %q type %q id %q, want ops / guardrail_baseline / cluster", i, e.Username, e.ResourceType, e.ResourceID)
		}
		var d guardrailBaselineAuditDetail
		if err := json.Unmarshal([]byte(e.Detail), &d); err != nil {
			t.Fatalf("detail is not the typed JSON: %v (%s)", err, e.Detail)
		}
		if d != want[i] {
			t.Fatalf("entry %d detail = %+v, want %+v", i, d, want[i])
		}
	}
}

// TestSetBaselineMode_AuditFailureFailsTheSet (#2738, decision A on #2727):
// a switch whose audit entry cannot be written is refused and leaves the
// stored mode as it was, so the change and its audit never diverge.
func TestSetBaselineMode_AuditFailureFailsTheSet(t *testing.T) {
	s, audit := newGPServer()
	changed := 0
	s.SetOnChange(func() { changed++ })
	audit.err = errors.New("audit store down")
	if _, err := gpSetMode(gpAdminCtx(), s, gpModeBlock); status.Code(err) != codes.Internal {
		t.Fatalf("set with a failing audit write = %v, want Internal", err)
	}
	st, err := s.GetGuardrailStatus(gpUserCtx(), &pb.GetGuardrailStatusRequest{})
	if err != nil || st.GetBaseline().GetMode() != gpModeLog || st.GetBaseline().GetRevision() != 0 {
		t.Fatalf("status after a failed audit = (%v, %v), want the untouched LOG at revision 0", st, err)
	}
	if changed != 0 {
		t.Fatalf("onChange ran %d times for a refused switch, want 0", changed)
	}

	// The audit store recovers: the same switch now succeeds at revision 1.
	audit.err = nil
	res, err := gpSetMode(gpAdminCtx(), s, gpModeBlock)
	if err != nil || res.GetBaseline().GetRevision() != 1 {
		t.Fatalf("set after recovery = (%v, %v), want revision 1", res, err)
	}
}

// TestSetBaselineMode_NoAuditStoreKeepsCurrentBehaviour pins today's
// behaviour on a daemon with no audit store (no Postgres, REST disabled, or
// an audit store that failed to start): the switch
// succeeds without an entry. Whether that should change is an open question
// on #2727; this test only records the current behaviour.
func TestSetBaselineMode_NoAuditStoreKeepsCurrentBehaviour(t *testing.T) {
	s := NewGuardrailPolicyServer(guardrailpolicy.NewMemoryStore())
	res, err := gpSetMode(gpAdminCtx(), s, gpModeBlock)
	if err != nil || res.GetBaseline().GetMode() != gpModeBlock {
		t.Fatalf("set with no audit store = (%v, %v), want BLOCK stored", res, err)
	}
}

// TestGetGuardrailStatus_ReportsBaselineMode (#2738): the status carries the
// stored mode, LOG by default, also when an admin policy makes it unused;
// an unreadable store is an error, never a default mode.
func TestGetGuardrailStatus_ReportsBaselineMode(t *testing.T) {
	s, _ := newGPServer()
	st, err := s.GetGuardrailStatus(gpUserCtx(), &pb.GetGuardrailStatusRequest{})
	if err != nil || st.GetBaseline().GetMode() != gpModeLog || st.GetBaseline().GetRevision() != 0 {
		t.Fatalf("fresh status = (%v, %v), want baseline LOG at revision 0", st, err)
	}
	if _, err := gpSetMode(gpAdminCtx(), s, gpModeBlock); err != nil {
		t.Fatalf("set BLOCK: %v", err)
	}
	if _, err := s.SetGuardrailPolicy(gpAdminCtx(), gpRequest(0)); err != nil {
		t.Fatalf("Set policy: %v", err)
	}
	st, err = s.GetGuardrailStatus(gpUserCtx(), &pb.GetGuardrailStatusRequest{})
	if err != nil || st.GetResponsePolicy() != pb.GuardrailEffectivePolicy_GUARDRAIL_EFFECTIVE_POLICY_NONE ||
		st.GetBaseline().GetMode() != gpModeBlock || st.GetBaseline().GetRevision() != 1 {
		t.Fatalf("status with a policy = (%v, %v), want NONE with the stored BLOCK mode", st, err)
	}

	s.SetStore(unavailableGuardrailPolicyStore{})
	if _, err := gpSetMode(gpAdminCtx(), s, gpModeLog); status.Code(err) != codes.Internal {
		t.Fatalf("set on an unavailable store = %v, want Internal", err)
	}
}

type failingBaselineModeStore struct{ guardrailpolicy.Store }

func (failingBaselineModeStore) GetBaselineMode(context.Context) (*pb.GuardrailBaselineSetting, error) {
	return nil, errors.New("connection refused")
}

// TestGetGuardrailStatus_BaselineModeReadErrorIsAnError: the policy reads but
// the mode does not; the status is an error, never a guessed LOG.
func TestGetGuardrailStatus_BaselineModeReadErrorIsAnError(t *testing.T) {
	s := NewGuardrailPolicyServer(failingBaselineModeStore{guardrailpolicy.NewMemoryStore()})
	resp, err := s.GetGuardrailStatus(gpUserCtx(), &pb.GetGuardrailStatusRequest{})
	if status.Code(err) != codes.Internal || resp != nil {
		t.Fatalf("status with an unreadable mode = (%v, %v), want Internal and no status", resp, err)
	}
}
