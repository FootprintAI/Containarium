package server

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/footprintai/containarium/internal/audit"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Models storage idempotency only. This is not evidence of a Postgres
// transaction, unique constraint, or hash-chain integration passing.
type authorizationMemoryLogger struct {
	seen map[string]bool
	rows []audit.BatchEntry
}

func (f *authorizationMemoryLogger) LogBatch(_ context.Context, entries []audit.BatchEntry) ([]audit.BatchOutcome, error) {
	if f.seen == nil {
		f.seen = make(map[string]bool)
	}
	outcomes := make([]audit.BatchOutcome, len(entries))
	for i, entry := range entries {
		if f.seen[entry.DedupeKey] {
			outcomes[i] = audit.BatchDuplicate
		} else {
			f.seen[entry.DedupeKey] = true
			f.rows = append(f.rows, entry)
			outcomes[i] = audit.BatchInserted
		}
	}
	return outcomes, nil
}

func TestIngest_AuthorizationReasonsAndReplay(t *testing.T) {
	for number, name := range pb.SSHDenyReason_name {
		t.Run(name, func(t *testing.T) {
			denied := openRec("authorization-session")
			denied.Phase = pb.SSHSessionPhase_SSH_SESSION_PHASE_DENIED
			denied.UserId = "user-test"
			denied.AuthzDecision = pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY
			denied.DenyReason = pb.SSHDenyReason(number)
			denied.Enforced = false // audit-only: a later OPEN is a separate row.
			opened := openRec(denied.SessionId)
			opened.UserId, opened.AuthzDecision, opened.DenyReason = denied.UserId, denied.AuthzDecision, denied.DenyReason
			logger := &authorizationMemoryLogger{}
			server := NewAuditServer(logger)
			req := &pb.IngestSSHSessionRecordsRequest{Records: []*pb.SSHSessionRecord{denied, opened}}
			resp, err := server.IngestSSHSessionRecords(ingestCtx(), req)
			if err != nil {
				t.Fatal(err)
			}
			if resp.Inserted != 2 || resp.Duplicates != 0 || len(logger.rows) != 2 {
				t.Fatalf("first batch: %v rows=%d", resp, len(logger.rows))
			}
			for i, row := range logger.rows {
				wantAction := "ssh_session_denied"
				if i == 1 {
					wantAction = "ssh_session_open"
				}
				if row.Entry.Action != wantAction {
					t.Errorf("action=%q want %q", row.Entry.Action, wantAction)
				}
				var detail struct {
					UserID        string              `json:"user_id"`
					AuthzDecision pb.SSHAuthzDecision `json:"authz_decision"`
					DenyReason    pb.SSHDenyReason    `json:"deny_reason"`
					Enforced      bool                `json:"enforced"`
				}
				if err := json.Unmarshal([]byte(row.Entry.Detail), &detail); err != nil {
					t.Fatal(err)
				}
				if detail.UserID != denied.UserId || detail.AuthzDecision != denied.AuthzDecision || detail.DenyReason != denied.DenyReason || detail.Enforced {
					t.Errorf("authorization detail lost: %+v", detail)
				}
			}
			resp, err = server.IngestSSHSessionRecords(ingestCtx(), req)
			if err != nil || resp.Inserted != 0 || resp.Duplicates != 2 || len(logger.rows) != 2 {
				t.Fatalf("replay: %v rows=%d err=%v", resp, len(logger.rows), err)
			}
			for _, outcome := range resp.Outcomes {
				if outcome != pb.IngestOutcome_INGEST_OUTCOME_DUPLICATE {
					t.Errorf("replay outcome=%v", outcome)
				}
			}
		})
	}
}

func TestIngest_EnforcedDenialPreservesUnknownUser(t *testing.T) {
	p := openRec("unknown-user-session")
	p.Phase = pb.SSHSessionPhase_SSH_SESSION_PHASE_DENIED
	p.AuthzDecision = pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY
	p.DenyReason = pb.SSHDenyReason_SSH_DENY_REASON_UNKNOWN_KEY
	p.Enforced = true
	logger := &authorizationMemoryLogger{}
	_, err := NewAuditServer(logger).IngestSSHSessionRecords(ingestCtx(), &pb.IngestSSHSessionRecordsRequest{Records: []*pb.SSHSessionRecord{p}})
	if err != nil {
		t.Fatal(err)
	}
	if len(logger.rows) != 1 {
		t.Fatalf("rows=%d want 1", len(logger.rows))
	}
	var detail struct {
		UserID        string              `json:"user_id"`
		AuthzDecision pb.SSHAuthzDecision `json:"authz_decision"`
		DenyReason    pb.SSHDenyReason    `json:"deny_reason"`
		Enforced      bool                `json:"enforced"`
	}
	if err := json.Unmarshal([]byte(logger.rows[0].Entry.Detail), &detail); err != nil {
		t.Fatal(err)
	}
	if detail.UserID != "" || !detail.Enforced || detail.AuthzDecision != p.AuthzDecision || detail.DenyReason != p.DenyReason {
		t.Fatalf("unknown user must not fall back to target login: %+v", detail)
	}
}
