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
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #2415 — AuditService.IngestSSHSessionRecords handler.

type fakeBatchLogger struct {
	got     []audit.BatchEntry
	calls   int
	outcome func(i int) audit.BatchOutcome
	err     error
}

func (f *fakeBatchLogger) LogBatch(_ context.Context, es []audit.BatchEntry) ([]audit.BatchOutcome, error) {
	f.calls++
	f.got = es
	if f.err != nil {
		return nil, f.err
	}
	out := make([]audit.BatchOutcome, len(es))
	for i := range es {
		out[i] = audit.BatchInserted
		if f.outcome != nil {
			out[i] = f.outcome(i)
		}
	}
	return out, nil
}

func ingestCtx() context.Context {
	ctx := auth.ContextWithTestSubjectScopes(context.Background(), "sentinel-shipper",
		[]string{"service"}, []string{auth.ScopeAuditIngest})
	return context.WithValue(ctx, auth.ContextKeyJTI, "jti-abc")
}

func openRec(id string) *pb.SSHSessionRecord {
	return &pb.SSHSessionRecord{
		SessionId:  id,
		Phase:      pb.SSHSessionPhase_SSH_SESSION_PHASE_OPEN,
		OccurredAt: timestamppb.New(time.Date(2026, 10, 9, 1, 2, 3, 0, time.UTC)),
		ClientIp:   "203.0.113.9",
		ClientPort: 40222,
		Login:      "alice",
		Target:     "10.0.0.5:22",
		AuthMethod: pb.SSHAuthMethod_SSH_AUTH_METHOD_CERTIFICATE,
		Credential: &pb.SSHSessionCredential{KeyId: "kid", Serial: 7, CaKeyFingerprint: "SHA256:ca"},
	}
}

func closeRec(id string) *pb.SSHSessionRecord {
	r := openRec(id)
	r.Phase = pb.SSHSessionPhase_SSH_SESSION_PHASE_CLOSE
	r.CloseReason = pb.SSHCloseReason_SSH_CLOSE_REASON_NORMAL
	return r
}

func TestIngest_ScopeGate(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
		want codes.Code
	}{
		{"no subject", context.Background(), codes.Unauthenticated},
		{"unscoped token", auth.ContextWithTestSubject(context.Background(), "admin", "admin"), codes.PermissionDenied},
		{"wrong scope", auth.ContextWithTestSubjectScopes(context.Background(), "a", []string{"admin"}, []string{auth.ScopeAuditRead}), codes.PermissionDenied},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeBatchLogger{}
			s := NewAuditServer(f)
			_, err := s.IngestSSHSessionRecords(tc.ctx, &pb.IngestSSHSessionRecordsRequest{Records: []*pb.SSHSessionRecord{openRec("s1")}})
			if status.Code(err) != tc.want {
				t.Fatalf("code = %v (%v), want %v", status.Code(err), err, tc.want)
			}
			if f.calls != 0 {
				t.Fatal("store must not be touched when the scope check fails")
			}
		})
	}
}

func TestIngest_ValidationRejectsWholeBatchBeforeAnyWrite(t *testing.T) {
	many := make([]*pb.SSHSessionRecord, 501)
	for i := range many {
		many[i] = openRec(fmt.Sprintf("s%d", i))
	}
	bad := func(mut func(*pb.SSHSessionRecord)) []*pb.SSHSessionRecord {
		r := openRec("bad")
		mut(r)
		return []*pb.SSHSessionRecord{openRec("ok"), r}
	}
	tests := []struct {
		name    string
		records []*pb.SSHSessionRecord
		wantIdx string // substring naming the offending index
	}{
		{"empty batch", nil, ""},
		{"too many", many, ""},
		{"nil entry", []*pb.SSHSessionRecord{openRec("a"), nil}, "records[1]"},
		{"empty session id", bad(func(r *pb.SSHSessionRecord) { r.SessionId = "" }), "records[1]"},
		{"unspecified phase", bad(func(r *pb.SSHSessionRecord) { r.Phase = pb.SSHSessionPhase_SSH_SESSION_PHASE_UNSPECIFIED }), "records[1]"},
		{"missing occurred_at", bad(func(r *pb.SSHSessionRecord) { r.OccurredAt = nil }), "records[1]"},
		{"close_reason on open", bad(func(r *pb.SSHSessionRecord) { r.CloseReason = pb.SSHCloseReason_SSH_CLOSE_REASON_ERROR }), "records[1]"},
		{"unknown enum number", bad(func(r *pb.SSHSessionRecord) { r.AuthMethod = pb.SSHAuthMethod(42) }), "records[1]"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeBatchLogger{}
			_, err := NewAuditServer(f).IngestSSHSessionRecords(ingestCtx(), &pb.IngestSSHSessionRecordsRequest{Records: tc.records})
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("code = %v (%v), want InvalidArgument", status.Code(err), err)
			}
			if tc.wantIdx != "" && !strings.Contains(err.Error(), tc.wantIdx) {
				t.Fatalf("error %q must name %s", err, tc.wantIdx)
			}
			if f.calls != 0 {
				t.Fatal("nothing may be written when any record is invalid")
			}
		})
	}
}

func TestIngest_OutcomesAndCounts(t *testing.T) {
	f := &fakeBatchLogger{outcome: func(i int) audit.BatchOutcome {
		if i%2 == 1 {
			return audit.BatchDuplicate
		}
		return audit.BatchInserted
	}}
	resp, err := NewAuditServer(f).IngestSSHSessionRecords(ingestCtx(), &pb.IngestSSHSessionRecordsRequest{
		Records: []*pb.SSHSessionRecord{openRec("a"), openRec("b"), closeRec("c"), closeRec("d")},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []pb.IngestOutcome{
		pb.IngestOutcome_INGEST_OUTCOME_INSERTED, pb.IngestOutcome_INGEST_OUTCOME_DUPLICATE,
		pb.IngestOutcome_INGEST_OUTCOME_INSERTED, pb.IngestOutcome_INGEST_OUTCOME_DUPLICATE,
	}
	if len(resp.Outcomes) != len(want) {
		t.Fatalf("outcomes len = %d, want %d", len(resp.Outcomes), len(want))
	}
	for i := range want {
		if resp.Outcomes[i] != want[i] {
			t.Fatalf("outcomes[%d] = %v, want %v", i, resp.Outcomes[i], want[i])
		}
	}
	if resp.Inserted != 2 || resp.Duplicates != 2 {
		t.Fatalf("inserted/duplicates = %d/%d, want 2/2", resp.Inserted, resp.Duplicates)
	}
}

func TestIngest_StoreErrorIsUnavailable(t *testing.T) {
	f := &fakeBatchLogger{err: errors.New("pg down")}
	_, err := NewAuditServer(f).IngestSSHSessionRecords(ingestCtx(), &pb.IngestSSHSessionRecordsRequest{Records: []*pb.SSHSessionRecord{openRec("a")}})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", status.Code(err))
	}
}

func TestIngest_NoStoreIsUnavailable(t *testing.T) {
	_, err := NewAuditServer(nil).IngestSSHSessionRecords(ingestCtx(), &pb.IngestSSHSessionRecordsRequest{Records: []*pb.SSHSessionRecord{openRec("a")}})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", status.Code(err))
	}
}

func TestIngest_RowMapping(t *testing.T) {
	f := &fakeBatchLogger{}
	_, err := NewAuditServer(f).IngestSSHSessionRecords(ingestCtx(), &pb.IngestSSHSessionRecordsRequest{
		SentinelId: "sentinel-1",
		Records:    []*pb.SSHSessionRecord{openRec("sess-9"), closeRec("sess-9")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.got) != 2 {
		t.Fatalf("got %d entries", len(f.got))
	}

	o, c := f.got[0], f.got[1]
	if o.Entry.Action != "ssh_session_open" || c.Entry.Action != "ssh_session_close" {
		t.Fatalf("actions = %q / %q", o.Entry.Action, c.Entry.Action)
	}
	if o.DedupeKey != "sshsession:sess-9:open" || c.DedupeKey != "sshsession:sess-9:close" {
		t.Fatalf("dedupe keys = %q / %q", o.DedupeKey, c.DedupeKey)
	}
	e := o.Entry
	if e.Username != "alice" || e.ResourceType != "ssh_session" || e.ResourceID != "sess-9" ||
		e.SourceIP != "203.0.113.9" || e.TokenID != "jti-abc" {
		t.Fatalf("entry fields wrong: %+v", e)
	}
	if !e.Timestamp.Equal(time.Date(2026, 10, 9, 1, 2, 3, 0, time.UTC)) {
		t.Fatalf("timestamp = %v, want the record's occurred_at", e.Timestamp)
	}
	if e.Actor != "" || e.DelegationChain != "" || e.OrgID != "" || e.RunID != "" {
		t.Fatalf("attribution fields must stay empty: %+v", e)
	}

	var d SSHSessionDetail
	if err := json.Unmarshal([]byte(e.Detail), &d); err != nil {
		t.Fatalf("detail is not the typed JSON struct: %v (%q)", err, e.Detail)
	}
	want := SSHSessionDetail{
		Target: "10.0.0.5:22", AuthMethod: "certificate", ClientPort: 40222,
		KeyID: "kid", Serial: 7, CAKeyFingerprint: "SHA256:ca", SentinelID: "sentinel-1",
	}
	if d != want {
		t.Fatalf("detail = %+v, want %+v", d, want)
	}
	var cd SSHSessionDetail
	_ = json.Unmarshal([]byte(c.Entry.Detail), &cd)
	if cd.CloseReason != "normal" {
		t.Fatalf("close detail close_reason = %q, want normal", cd.CloseReason)
	}
}
