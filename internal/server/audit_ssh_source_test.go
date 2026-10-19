package server

import (
	"encoding/json"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/footprintai/containarium/internal/sentinel/sshsession"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Failed-authentication and ban records (#2419) land as their own audit
// actions, with the counts and ban expiry in the typed detail and the source IP
// in the row's source_ip column, and without any session identity.
func TestIngestSSHSourceRecords(t *testing.T) {
	at := time.Date(2026, 10, 19, 1, 2, 3, 0, time.UTC)
	until := at.Add(5 * time.Minute)
	tests := []struct {
		name       string
		rec        *pb.SSHSessionRecord
		wantAction string
		wantDetail SSHSessionDetail
		wantIP     string
	}{
		{
			name: "auth failures in a window",
			rec: &pb.SSHSessionRecord{SessionId: "f1", Phase: pb.SSHSessionPhase_SSH_SESSION_PHASE_AUTH_FAILED,
				OccurredAt: timestamppb.New(at), ClientIp: "203.0.113.9", FailureCount: 7, BanListener: pb.SSHBanListener_SSH_BAN_LISTENER_MAIN},
			wantAction: "ssh_auth_failed", wantIP: "203.0.113.9",
			wantDetail: SSHSessionDetail{SentinelID: "sentinel-1", FailureCount: 7, BanListener: pb.SSHBanListener_SSH_BAN_LISTENER_MAIN},
		},
		{
			name: "a ban",
			rec: &pb.SSHSessionRecord{SessionId: "b1", Phase: pb.SSHSessionPhase_SSH_SESSION_PHASE_BANNED,
				OccurredAt: timestamppb.New(at), ClientIp: "203.0.113.9", FailureCount: 100, BannedUntil: timestamppb.New(until),
				BanListener: pb.SSHBanListener_SSH_BAN_LISTENER_ANONYMOUS},
			wantAction: "ssh_banned", wantIP: "203.0.113.9",
			wantDetail: SSHSessionDetail{SentinelID: "sentinel-1", FailureCount: 100, BannedUntil: "2026-10-19T01:07:03Z", BanListener: pb.SSHBanListener_SSH_BAN_LISTENER_ANONYMOUS},
		},
		{
			name: "overflow record",
			rec: &pb.SSHSessionRecord{SessionId: "o1", Phase: pb.SSHSessionPhase_SSH_SESSION_PHASE_AUTH_FAILED,
				OccurredAt: timestamppb.New(at), SuppressedCount: 4200, BanListener: pb.SSHBanListener_SSH_BAN_LISTENER_MAIN},
			wantAction: "ssh_auth_failed", wantIP: "",
			wantDetail: SSHSessionDetail{SentinelID: "sentinel-1", SuppressedCount: 4200, BanListener: pb.SSHBanListener_SSH_BAN_LISTENER_MAIN},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &fakeBatchLogger{}
			resp, err := NewAuditServer(store).IngestSSHSessionRecords(ingestCtx(), &pb.IngestSSHSessionRecordsRequest{
				Records: []*pb.SSHSessionRecord{tt.rec}, SentinelId: "sentinel-1"})
			if err != nil || resp.GetInserted() != 1 {
				t.Fatalf("ingest: resp %v err %v", resp, err)
			}
			rec, err := sshsession.FromProto(tt.rec)
			if err != nil {
				t.Fatal(err)
			}
			row, err := sshSessionBatchEntry(rec, "sentinel-1", "jti")
			if err != nil {
				t.Fatal(err)
			}
			if row.Entry.Action != tt.wantAction || row.Entry.SourceIP != tt.wantIP || row.Entry.Username != "" {
				t.Fatalf("row action/ip/username = %q/%q/%q, want %q/%q/\"\"", row.Entry.Action, row.Entry.SourceIP, row.Entry.Username, tt.wantAction, tt.wantIP)
			}
			var got SSHSessionDetail
			if err := json.Unmarshal([]byte(row.Entry.Detail), &got); err != nil {
				t.Fatal(err)
			}
			if got != tt.wantDetail {
				t.Fatalf("detail = %+v, want %+v", got, tt.wantDetail)
			}
			if row.DedupeKey != "sshsession:"+tt.rec.GetSessionId()+":"+string(rec.Phase) {
				t.Errorf("dedupe key = %q", row.DedupeKey)
			}
		})
	}
}

// An invalid source record rejects the whole batch (a skipped audit record is a
// hole), exactly as for the other phases.
func TestIngestSSHSourceRecords_InvalidRejectsBatch(t *testing.T) {
	bad := &pb.SSHSessionRecord{SessionId: "x", Phase: pb.SSHSessionPhase_SSH_SESSION_PHASE_BANNED,
		OccurredAt: timestamppb.Now(), ClientIp: "203.0.113.9", FailureCount: 5, BanListener: pb.SSHBanListener_SSH_BAN_LISTENER_MAIN} // no banned_until
	store := &fakeBatchLogger{}
	if _, err := NewAuditServer(store).IngestSSHSessionRecords(ingestCtx(), &pb.IngestSSHSessionRecordsRequest{Records: []*pb.SSHSessionRecord{openRec("good"), bad}}); err == nil {
		t.Fatal("a banned record without banned_until was accepted")
	}
	if len(store.got) != 0 {
		t.Fatalf("nothing may be written when a record is invalid; %d written", len(store.got))
	}
}
