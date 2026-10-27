package sshsession

import (
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/protobuf/proto"
)

// Uses the real enum contract introduced by #2516 (PR #2534).
func TestAuthorization_ProtoRoundTrip(t *testing.T) {
	for number, name := range pb.SSHDenyReason_name {
		t.Run(name, func(t *testing.T) {
			p := ToProto(baseRecord())
			p.Phase = pb.SSHSessionPhase_SSH_SESSION_PHASE_DENIED
			p.UserId = "user-test"
			p.AuthzDecision = pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY
			p.DenyReason = pb.SSHDenyReason(number)
			p.Enforced = true
			r, err := FromProto(p)
			if err != nil {
				t.Fatal(err)
			}
			if got := ToProto(r); !proto.Equal(got, p) {
				t.Fatalf("authorization fields lost:\n got %v\nwant %v", got, p)
			}
		})
	}
	for number, name := range pb.SSHAuthzDecision_name {
		t.Run("open/"+name, func(t *testing.T) {
			p := ToProto(baseRecord())
			p.UserId = "user-test"
			p.AuthzDecision = pb.SSHAuthzDecision(number)
			p.Enforced = false // audit-only may OPEN after a DENY.
			r, err := FromProto(p)
			if err != nil || !proto.Equal(ToProto(r), p) {
				t.Fatalf("open authorization round-trip: record=%+v err=%v", r, err)
			}
		})
	}
}

func TestAuthorization_RejectsUnknownEnumsAndDeniedCloseReason(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*pb.SSHSessionRecord)
	}{
		{"unknown decision", func(p *pb.SSHSessionRecord) { p.AuthzDecision = pb.SSHAuthzDecision(999) }},
		{"unknown deny reason", func(p *pb.SSHSessionRecord) { p.DenyReason = pb.SSHDenyReason(999) }},
		{"close reason on denied", func(p *pb.SSHSessionRecord) {
			p.Phase = pb.SSHSessionPhase_SSH_SESSION_PHASE_DENIED
			p.CloseReason = pb.SSHCloseReason_SSH_CLOSE_REASON_NORMAL
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := ToProto(baseRecord())
			tc.mut(p)
			if _, err := FromProto(p); err == nil {
				t.Fatal("invalid record was accepted")
			}
		})
	}
}
