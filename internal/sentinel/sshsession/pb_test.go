package sshsession

import (
	"reflect"
	"strings"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

var allPhases = []SessionPhase{SessionPhaseOpen, SessionPhaseClose}
var allAuthMethods = []AuthMethod{AuthMethodCertificate, AuthMethodPublicKey, AuthMethodUnknown}
var allCloseReasons = []CloseReason{
	CloseReasonNormal, CloseReasonUpstreamGone, CloseReasonProxyShutdown,
	CloseReasonError, CloseReasonUnknownOrphan,
}

func baseRecord() Record {
	return Record{
		SessionID:  "sess-1",
		Phase:      SessionPhaseOpen,
		OccurredAt: time.Date(2026, 10, 9, 1, 2, 3, 456000000, time.UTC),
		ClientIP:   "203.0.113.9",
		ClientPort: 40222,
		Login:      "alice",
		Target:     "10.0.0.5:22",
		AuthMethod: AuthMethodCertificate,
		Credential: Credential{KeyID: "kid", Serial: 7, CAFingerprint: "SHA256:ca"},
	}
}

func TestToFromProto_RoundTripEveryEnumValue(t *testing.T) {
	for _, ph := range allPhases {
		for _, am := range allAuthMethods {
			r := baseRecord()
			r.Phase, r.AuthMethod = ph, am
			if ph == SessionPhaseClose {
				r.CloseReason = CloseReasonNormal
			}
			got, err := FromProto(ToProto(r))
			if err != nil {
				t.Fatalf("%s/%s: %v", ph, am, err)
			}
			if !reflect.DeepEqual(got, r) {
				t.Fatalf("%s/%s round trip:\n got %+v\nwant %+v", ph, am, got, r)
			}
		}
	}
	for _, cr := range allCloseReasons {
		r := baseRecord()
		r.Phase, r.CloseReason = SessionPhaseClose, cr
		got, err := FromProto(ToProto(r))
		if err != nil || !reflect.DeepEqual(got, r) {
			t.Fatalf("close_reason %s: got %+v err %v", cr, got, err)
		}
	}
}

func TestToFromProto_RawKeyCredentialAndNoCredential(t *testing.T) {
	r := baseRecord()
	r.AuthMethod = AuthMethodPublicKey
	r.Credential = Credential{KeyFingerprint: "SHA256:key"}
	if got, err := FromProto(ToProto(r)); err != nil || !reflect.DeepEqual(got, r) {
		t.Fatalf("raw key: %+v %v", got, err)
	}
	r.AuthMethod, r.Credential = AuthMethodUnknown, Credential{}
	if got, err := FromProto(ToProto(r)); err != nil || !reflect.DeepEqual(got, r) {
		t.Fatalf("no credential: %+v %v", got, err)
	}
}

func TestFromProto_Rejects(t *testing.T) {
	good := ToProto(baseRecord())
	tests := []struct {
		name string
		mut  func(*pb.SSHSessionRecord)
	}{
		{"unspecified phase", func(p *pb.SSHSessionRecord) { p.Phase = pb.SSHSessionPhase_SSH_SESSION_PHASE_UNSPECIFIED }},
		{"unknown phase number", func(p *pb.SSHSessionRecord) { p.Phase = pb.SSHSessionPhase(99) }},
		{"empty session id", func(p *pb.SSHSessionRecord) { p.SessionId = "" }},
		{"missing occurred_at", func(p *pb.SSHSessionRecord) { p.OccurredAt = nil }},
		{"unknown auth method number", func(p *pb.SSHSessionRecord) { p.AuthMethod = pb.SSHAuthMethod(99) }},
		{"unknown close reason number", func(p *pb.SSHSessionRecord) {
			p.Phase = pb.SSHSessionPhase_SSH_SESSION_PHASE_CLOSE
			p.CloseReason = pb.SSHCloseReason(99)
		}},
		{"close_reason on an open", func(p *pb.SSHSessionRecord) { p.CloseReason = pb.SSHCloseReason_SSH_CLOSE_REASON_NORMAL }},
		{"close without close_reason", func(p *pb.SSHSessionRecord) {
			p.Phase = pb.SSHSessionPhase_SSH_SESSION_PHASE_CLOSE
			p.CloseReason = pb.SSHCloseReason_SSH_CLOSE_REASON_UNSPECIFIED
		}},
		{"nil record", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var p *pb.SSHSessionRecord
			if tc.mut != nil {
				p = proto_clone(good)
				tc.mut(p)
			}
			if _, err := FromProto(p); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// Fails when someone adds a Go enum constant and forgets the proto (or the
// reverse): the Go sets above must cover every proto value except
// UNSPECIFIED, one to one.
func TestEnumSetsMatchProto(t *testing.T) {
	check := func(name string, goN int, protoNames map[int32]string) {
		if want := len(protoNames) - 1; goN != want { // minus UNSPECIFIED
			t.Errorf("%s: %d Go constants vs %d proto values (excluding UNSPECIFIED)", name, goN, want)
		}
	}
	// SSH_SESSION_PHASE_DENIED is on the wire contract (#2516) but the
	// sentinel's Record does not carry it until #2519; until then
	// TestFromProto_RejectsDeniedPhase pins that ingest refuses it.
	check("phase", len(allPhases)+1, pb.SSHSessionPhase_name)
	check("auth method", len(allAuthMethods), pb.SSHAuthMethod_name)
	check("close reason", len(allCloseReasons), pb.SSHCloseReason_name)
}

// A DENIED record must be refused, not stored as an open row, until the
// sentinel's Record carries the phase (#2519).
func TestFromProto_RejectsDeniedPhase(t *testing.T) {
	p := ToProto(baseRecord())
	p.Phase = pb.SSHSessionPhase_SSH_SESSION_PHASE_DENIED
	if _, err := FromProto(p); err == nil || !strings.Contains(err.Error(), "invalid phase") {
		t.Fatalf("FromProto(DENIED) err = %v, want invalid phase", err)
	}
}
