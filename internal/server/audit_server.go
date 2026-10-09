package server

import (
	"context"
	"encoding/json"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/sentinel/sshsession"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// maxIngestBatch caps one IngestSSHSessionRecords call. The batch holds the
// audit chain's advisory lock for its whole transaction, so the cap bounds
// how long other appenders can be made to wait.
const maxIngestBatch = 500

// Audit actions written for sentinel SSH session records (#2415). Named to
// match the existing in-box collector's "ssh_login".
const (
	auditActionSSHSessionOpen  = "ssh_session_open"
	auditActionSSHSessionClose = "ssh_session_close"
	auditResourceSSHSession    = "ssh_session"
)

// batchLogger is the slice of *audit.Store the ingest handler needs,
// narrowed so the handler is testable without Postgres.
type batchLogger interface {
	LogBatch(ctx context.Context, entries []audit.BatchEntry) ([]audit.BatchOutcome, error)
}

// AuditServer implements AuditService (#2415).
type AuditServer struct {
	pb.UnimplementedAuditServiceServer
	store batchLogger
}

// NewAuditServer returns the AuditService backed by store. A nil store (the
// daemon has no Postgres) makes every RPC return Unavailable.
func NewAuditServer(store batchLogger) *AuditServer {
	return &AuditServer{store: store}
}

// SSHSessionDetail is the typed JSON stored in an ssh_session row's detail
// column. A named struct, not a map, so the shape is a contract the
// auditor-facing docs and tests can name.
type SSHSessionDetail struct {
	Target           string `json:"target,omitempty"`
	AuthMethod       string `json:"auth_method,omitempty"`
	ClientPort       int    `json:"client_port,omitempty"`
	KeyID            string `json:"key_id,omitempty"`
	Serial           uint64 `json:"serial,omitempty"`
	CAKeyFingerprint string `json:"ca_key_fingerprint,omitempty"`
	KeyFingerprint   string `json:"key_fingerprint,omitempty"`
	CloseReason      string `json:"close_reason,omitempty"`
	SentinelID       string `json:"sentinel_id,omitempty"`
}

// IngestSSHSessionRecords appends the sentinel's SSH session records to this
// backend's audit chain. See the RPC's proto comment for the contract.
func (s *AuditServer) IngestSSHSessionRecords(ctx context.Context, req *pb.IngestSSHSessionRecordsRequest) (*pb.IngestSSHSessionRecordsResponse, error) {
	// Explicit, not RequireScope: a token with no scopes claim must not be
	// able to write into the tamper-evident chain.
	if err := auth.RequireExplicitScope(ctx, auth.ScopeAuditIngest); err != nil {
		return nil, err
	}
	if s.store == nil {
		return nil, status.Error(codes.Unavailable, "audit store is not available on this daemon")
	}

	n := len(req.GetRecords())
	if n == 0 {
		return nil, status.Error(codes.InvalidArgument, "records must contain at least one record")
	}
	if n > maxIngestBatch {
		return nil, status.Errorf(codes.InvalidArgument, "records has %d entries, max %d", n, maxIngestBatch)
	}

	// Validate everything before the first write: an invalid record rejects
	// the batch, it is never skipped (a skipped audit record is a hole).
	jti, _ := auth.JTIFromContext(ctx)
	entries := make([]audit.BatchEntry, n)
	for i, p := range req.GetRecords() {
		rec, err := sshsession.FromProto(p)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "records[%d]: %v", i, err)
		}
		be, err := sshSessionBatchEntry(rec, req.GetSentinelId(), jti)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "records[%d]: %v", i, err)
		}
		entries[i] = be
	}

	outcomes, err := s.store.LogBatch(ctx, entries)
	if err != nil {
		// Nothing was committed (LogBatch is one transaction), so the caller
		// retries the identical batch.
		return nil, status.Errorf(codes.Unavailable, "audit store write failed: %v", err)
	}
	if len(outcomes) != n {
		return nil, status.Errorf(codes.Internal, "audit store returned %d outcomes for %d records", len(outcomes), n)
	}

	resp := &pb.IngestSSHSessionRecordsResponse{Outcomes: make([]pb.IngestOutcome, n)}
	for i, o := range outcomes {
		switch o {
		case audit.BatchInserted:
			resp.Outcomes[i] = pb.IngestOutcome_INGEST_OUTCOME_INSERTED
			resp.Inserted++
		case audit.BatchDuplicate:
			resp.Outcomes[i] = pb.IngestOutcome_INGEST_OUTCOME_DUPLICATE
			resp.Duplicates++
		default:
			return nil, status.Errorf(codes.Internal, "audit store returned unknown outcome %d", o)
		}
	}
	return resp, nil
}

// sshSessionBatchEntry maps one validated Record to its audit row.
func sshSessionBatchEntry(rec sshsession.Record, sentinelID, jti string) (audit.BatchEntry, error) {
	action := auditActionSSHSessionOpen
	if rec.Phase == sshsession.SessionPhaseClose {
		action = auditActionSSHSessionClose
	}
	detail, err := json.Marshal(SSHSessionDetail{
		Target:           rec.Target,
		AuthMethod:       string(rec.AuthMethod),
		ClientPort:       rec.ClientPort,
		KeyID:            rec.KeyID,
		Serial:           rec.Serial,
		CAKeyFingerprint: rec.CAFingerprint,
		KeyFingerprint:   rec.KeyFingerprint,
		CloseReason:      string(rec.CloseReason),
		SentinelID:       sentinelID,
	})
	if err != nil {
		return audit.BatchEntry{}, fmt.Errorf("marshal detail: %w", err)
	}
	return audit.BatchEntry{
		Entry: audit.AuditEntry{
			Timestamp:    rec.OccurredAt,
			Username:     rec.Login,
			Action:       action,
			ResourceType: auditResourceSSHSession,
			ResourceID:   rec.SessionID,
			Detail:       audit.SanitizeDetail(string(detail)),
			SourceIP:     rec.ClientIP,
			TokenID:      jti,
		},
		DedupeKey: sshSessionDedupeKey(rec),
	}, nil
}

// sshSessionDedupeKey is the row's idempotency identity: one row per
// (session, phase). A synthesized orphan close gets its own suffix so it
// never occupies the identity of the session's genuine close.
func sshSessionDedupeKey(rec sshsession.Record) string {
	key := fmt.Sprintf("sshsession:%s:%s", rec.SessionID, rec.Phase)
	if rec.CloseReason == sshsession.CloseReasonUnknownOrphan {
		key += ":orphan"
	}
	return key
}
