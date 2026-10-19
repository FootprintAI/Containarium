package sshsession

import (
	"reflect"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

var allPhases = []SessionPhase{SessionPhaseOpen, SessionPhaseClose, SessionPhaseDenied, SessionPhaseAuthFailed, SessionPhaseBanned}
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
			if ph == SessionPhaseAuthFailed || ph == SessionPhaseBanned {
				// Source-IP records carry no session identity (#2419).
				if am != AuthMethodCertificate {
					continue
				}
				r = sourceRecord(ph)
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
	check("phase", len(allPhases), pb.SSHSessionPhase_name)
	check("auth method", len(allAuthMethods), pb.SSHAuthMethod_name)
	check("close reason", len(allCloseReasons), pb.SSHCloseReason_name)
}

// #2519 completes #2516's wire contract: DENIED must retain its own phase,
// rather than being rejected or silently mapped to an OPEN record.
func TestFromProto_AcceptsDeniedPhase(t *testing.T) {
	p := ToProto(baseRecord())
	p.Phase = pb.SSHSessionPhase_SSH_SESSION_PHASE_DENIED
	r, err := FromProto(p)
	if err != nil {
		t.Fatalf("FromProto(DENIED): %v", err)
	}
	if r.Phase != SessionPhaseDenied || ToProto(r).GetPhase() != p.Phase {
		t.Fatalf("DENIED phase changed during round-trip: %+v", r)
	}
}

func sourceRecord(ph SessionPhase) Record {
	r := Record{
		SessionID:    "src-1",
		Phase:        ph,
		OccurredAt:   time.Date(2026, 10, 9, 1, 2, 3, 0, time.UTC),
		ClientIP:     "203.0.113.9",
		FailureCount: 12,
		BanListener:  pb.SSHBanListener_SSH_BAN_LISTENER_MAIN,
	}
	if ph == SessionPhaseBanned {
		until := r.OccurredAt.Add(5 * time.Minute)
		r.BannedUntil = &until
	}
	return r
}

// The source-IP phases (#2419) round-trip with their own fields intact, and
// the overflow shape (no client IP, only a suppressed count) is accepted.
func TestSourceRecords_RoundTripAndOverflow(t *testing.T) {
	for _, ph := range []SessionPhase{SessionPhaseAuthFailed, SessionPhaseBanned} {
		r := sourceRecord(ph)
		got, err := FromProto(ToProto(r))
		if err != nil || !reflect.DeepEqual(got, r) {
			t.Fatalf("%s: got %+v err %v, want %+v", ph, got, err, r)
		}
	}
	overflow := Record{SessionID: "ovf-1", Phase: SessionPhaseAuthFailed, OccurredAt: time.Unix(1, 0).UTC(),
		SuppressedCount: 900, BanListener: pb.SSHBanListener_SSH_BAN_LISTENER_ANONYMOUS}
	if got, err := FromProto(ToProto(overflow)); err != nil || !reflect.DeepEqual(got, overflow) {
		t.Fatalf("overflow: got %+v err %v", got, err)
	}
}

func TestSourceRecords_Rejects(t *testing.T) {
	mut := func(ph SessionPhase, f func(*Record)) *pb.SSHSessionRecord {
		r := sourceRecord(ph)
		f(&r)
		return ToProto(r)
	}
	tests := []struct {
		name string
		p    *pb.SSHSessionRecord
	}{
		{"auth_failed without a listener", mut(SessionPhaseAuthFailed, func(r *Record) { r.BanListener = 0 })},
		{"auth_failed without a count", mut(SessionPhaseAuthFailed, func(r *Record) { r.FailureCount = 0 })},
		{"auth_failed with banned_until", mut(SessionPhaseAuthFailed, func(r *Record) { t := r.OccurredAt; r.BannedUntil = &t })},
		{"auth_failed with a login", mut(SessionPhaseAuthFailed, func(r *Record) { r.Login = "alice" })},
		{"auth_failed with a credential", mut(SessionPhaseAuthFailed, func(r *Record) { r.KeyFingerprint = "SHA256:x" })},
		{"auth_failed overflow with a failure count", mut(SessionPhaseAuthFailed, func(r *Record) { r.ClientIP = ""; r.SuppressedCount = 5 })},
		{"auth_failed with both counts", mut(SessionPhaseAuthFailed, func(r *Record) { r.SuppressedCount = 5 })},
		{"banned without banned_until", mut(SessionPhaseBanned, func(r *Record) { r.BannedUntil = nil })},
		{"banned without an ip", mut(SessionPhaseBanned, func(r *Record) { r.ClientIP = "" })},
		{"banned with a suppressed count", mut(SessionPhaseBanned, func(r *Record) { r.SuppressedCount = 1 })},
		{"open with failure fields", func() *pb.SSHSessionRecord { p := ToProto(baseRecord()); p.FailureCount = 3; return p }()},
		{"open with a ban listener", func() *pb.SSHSessionRecord {
			p := ToProto(baseRecord())
			p.BanListener = pb.SSHBanListener_SSH_BAN_LISTENER_MAIN
			return p
		}()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := FromProto(tt.p); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
