package sshsession

import (
	"encoding/json"
	"reflect"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/tg123/sshpiper/libplugin"
)

func TestAuthorizationMetadataOnOpenCloseAndShutdown(t *testing.T) {
	recorder := &fakeRecorder{}
	p := &Plugin{Recorder: recorder}
	conn := &libplugin.ConnMeta{UserName: "alice", UniqId: "s1", FromAddr: "203.0.113.1:1234", Metadata: map[string]string{MetaUserID: "person", MetaAuthzDecision: "DENY", MetaDenyReason: "UNKNOWN_KEY"}}
	p.Config().PipeStartCallback(conn)
	p.Config().PipeErrorCallback(conn, nil)
	conn.UniqId = "s2"
	p.Config().PipeStartCallback(conn)
	p.Shutdown()
	if len(recorder.recs) != 4 {
		t.Fatalf("records: %v", recorder.recs)
	}
	for _, rec := range recorder.recs {
		if rec.UserID != "person" || rec.AuthzDecision != pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY || rec.DenyReason != pb.SSHDenyReason_SSH_DENY_REASON_UNKNOWN_KEY || rec.Enforced {
			t.Fatalf("lost metadata: %+v", rec)
		}
		raw, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		var back Record
		if err := json.Unmarshal(raw, &back); err != nil || !reflect.DeepEqual(back, rec) {
			t.Fatalf("JSONL roundtrip: %v %v", back, err)
		}
		back, err = FromProto(ToProto(rec))
		if err != nil || !reflect.DeepEqual(back, rec) {
			t.Fatalf("proto roundtrip: %v %v", back, err)
		}
	}
}

func TestAuthorizationProtoEveryReasonAndValidation(t *testing.T) {
	for n := int32(1); n <= 7; n++ {
		r := baseRecord()
		r.UserID = "person"
		r.AuthzDecision = pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY
		r.DenyReason = pb.SSHDenyReason(n)
		back, err := FromProto(ToProto(r))
		if err != nil || !reflect.DeepEqual(back, r) {
			t.Fatalf("reason %d: %v %v", n, back, err)
		}
	}
	r := baseRecord()
	r.AuthzDecision = pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW
	r.UserID = "person"
	if back, err := FromProto(ToProto(r)); err != nil || !reflect.DeepEqual(back, r) {
		t.Fatalf("allow: %v %v", back, err)
	}
	for _, mut := range []func(*Record){
		func(r *Record) { r.AuthzDecision = DecisionToProto("INVALID") },
		func(r *Record) {
			r.AuthzDecision = pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY
			r.DenyReason = ReasonToProto("INVALID")
		},
	} {
		bad := r
		mut(&bad)
		if _, err := FromProto(ToProto(bad)); err == nil {
			t.Fatalf("accepted bad record: %+v", bad)
		}
	}
}

func TestEnforcedMetadataOnOpenAndClose(t *testing.T) {
	recorder := &fakeRecorder{}
	p := &Plugin{Recorder: recorder}
	conn := &libplugin.ConnMeta{UserName: "alice", UniqId: "s1", FromAddr: "203.0.113.1:1234", Metadata: map[string]string{MetaUserID: "person", MetaAuthzDecision: "ALLOW", MetaEnforced: "true"}}
	p.Config().PipeStartCallback(conn)
	p.Config().PipeErrorCallback(conn, nil)
	if len(recorder.recs) != 2 {
		t.Fatalf("records: %v", recorder.recs)
	}
	for _, rec := range recorder.recs {
		if !rec.Enforced || rec.AuthzDecision != pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW {
			t.Fatalf("enforced allow lost: %+v", rec)
		}
	}
}
