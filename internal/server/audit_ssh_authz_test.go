package server

import (
	"encoding/json"
	"testing"

	"github.com/footprintai/containarium/internal/sentinel/sshsession"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestIngestSSHAuthorizationAttribution(t *testing.T) {
	for n := int32(0); n <= 7; n++ {
		t.Run(pb.SSHDenyReason(n).String(), func(t *testing.T) {
			record := openRec("authz-session")
			record.UserId = "person"
			record.AuthzDecision = pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW
			if n != 0 {
				record.AuthzDecision = pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY
				record.DenyReason = pb.SSHDenyReason(n)
			}
			store := &fakeBatchLogger{}
			_, err := NewAuditServer(store).IngestSSHSessionRecords(ingestCtx(), &pb.IngestSSHSessionRecordsRequest{Records: []*pb.SSHSessionRecord{record}})
			if err != nil {
				t.Fatal(err)
			}
			// Drive the exact row mapper used by ingestion, including audit-only DENY.
			rec, err := sshsession.FromProto(record)
			if err != nil {
				t.Fatal(err)
			}
			row, err := sshSessionBatchEntry(rec, "sentinel", "jti")
			if err != nil {
				t.Fatal(err)
			}
			var detail SSHSessionDetail
			if err := json.Unmarshal([]byte(row.Entry.Detail), &detail); err != nil {
				t.Fatal(err)
			}
			if row.Entry.Action != "ssh_session_open" || detail.UserID != "person" || detail.AuthzDecision != rec.AuthzDecision || detail.DenyReason != rec.DenyReason || detail.Enforced {
				t.Fatalf("audit row lost attribution: %+v", row)
			}
		})
	}
}
