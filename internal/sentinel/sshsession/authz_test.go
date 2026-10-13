package sshsession

import (
	"strconv"
	"testing"

	"github.com/footprintai/containarium/internal/sentinel/sshauthz"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/tg123/sshpiper/libplugin"
)

func TestPluginPreservesAuthzOnOpenCloseAndShutdown(t *testing.T) {
	for _, tc := range []struct {
		name     string
		decision pb.SSHAuthzDecision
		reason   pb.SSHDenyReason
	}{
		{"allow", pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW, pb.SSHDenyReason_SSH_DENY_REASON_UNSPECIFIED},
		{"deny", pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY, pb.SSHDenyReason_SSH_DENY_REASON_UNKNOWN_KEY},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := &libplugin.ConnMeta{UserName: "alice", UniqId: "session-a", Metadata: map[string]string{
				sshauthz.MetaUserID: "user-a", sshauthz.MetaDecision: strconv.Itoa(int(tc.decision)), sshauthz.MetaDenyReason: strconv.Itoa(int(tc.reason)), sshauthz.MetaEnforced: "true",
			}}
			recorder := &fakeRecorder{}
			plugin := &Plugin{Recorder: recorder}
			plugin.Config().PipeStartCallback(conn)
			plugin.Config().PipeErrorCallback(conn, nil)
			conn.UniqId = "session-b"
			plugin.Config().PipeStartCallback(conn)
			plugin.Shutdown()
			if len(recorder.recs) != 4 {
				t.Fatalf("records=%d", len(recorder.recs))
			}
			for _, r := range recorder.recs {
				if r.UserID != "user-a" || r.AuthzDecision != tc.decision || r.DenyReason != tc.reason || r.Enforced {
					t.Fatalf("metadata lost or enforced: %+v", r)
				}
			}
		})
	}
}
