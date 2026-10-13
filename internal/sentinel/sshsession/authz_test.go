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
		if rec.UserID != "person" || rec.AuthzDecision != AuthzDeny || rec.DenyReason != DenyUnknownKey || rec.Enforced {
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
		r.AuthzDecision = AuthzDeny
		r.DenyReason = ReasonFromProto(pb.SSHDenyReason(n))
		back, err := FromProto(ToProto(r))
		if err != nil || !reflect.DeepEqual(back, r) {
			t.Fatalf("reason %d: %v %v", n, back, err)
		}
	}
	r := baseRecord()
	r.AuthzDecision = AuthzAllow
	r.UserID = "person"
	if back, err := FromProto(ToProto(r)); err != nil || !reflect.DeepEqual(back, r) {
		t.Fatalf("allow: %v %v", back, err)
	}
	for _, mut := range []func(*Record){
		func(r *Record) { r.AuthzDecision = "INVALID" },
		func(r *Record) { r.AuthzDecision = AuthzDeny; r.DenyReason = "INVALID" },
		func(r *Record) { r.AuthzDecision = AuthzAllow; r.DenyReason = DenyUnknownKey },
		func(r *Record) { r.AuthzDecision = AuthzDeny; r.DenyReason = "" },
	} {
		bad := r
		mut(&bad)
		if _, err := FromProto(ToProto(bad)); err == nil {
			t.Fatalf("accepted bad record: %+v", bad)
		}
	}
}
