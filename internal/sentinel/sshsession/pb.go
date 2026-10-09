package sshsession

import (
	"fmt"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Conversions between the sentinel's on-disk Record (JSONL) and the
// AuditService wire type (#2415). Table-driven in both directions so a new
// Go constant without a proto value (or the reverse) is caught by
// TestEnumSetsMatchProto rather than at ingest time.

var phaseToPB = map[SessionPhase]pb.SSHSessionPhase{
	SessionPhaseOpen:  pb.SSHSessionPhase_SSH_SESSION_PHASE_OPEN,
	SessionPhaseClose: pb.SSHSessionPhase_SSH_SESSION_PHASE_CLOSE,
}

var authMethodToPB = map[AuthMethod]pb.SSHAuthMethod{
	AuthMethodCertificate: pb.SSHAuthMethod_SSH_AUTH_METHOD_CERTIFICATE,
	AuthMethodPublicKey:   pb.SSHAuthMethod_SSH_AUTH_METHOD_PUBLICKEY,
	AuthMethodUnknown:     pb.SSHAuthMethod_SSH_AUTH_METHOD_UNKNOWN,
}

var closeReasonToPB = map[CloseReason]pb.SSHCloseReason{
	CloseReasonNormal:        pb.SSHCloseReason_SSH_CLOSE_REASON_NORMAL,
	CloseReasonUpstreamGone:  pb.SSHCloseReason_SSH_CLOSE_REASON_UPSTREAM_GONE,
	CloseReasonProxyShutdown: pb.SSHCloseReason_SSH_CLOSE_REASON_PROXY_SHUTDOWN,
	CloseReasonError:         pb.SSHCloseReason_SSH_CLOSE_REASON_ERROR,
	CloseReasonUnknownOrphan: pb.SSHCloseReason_SSH_CLOSE_REASON_UNKNOWN_ORPHAN,
}

func invert[K comparable, V comparable](m map[K]V) map[V]K {
	out := make(map[V]K, len(m))
	for k, v := range m {
		out[v] = k
	}
	return out
}

var (
	phaseFromPB       = invert(phaseToPB)
	authMethodFromPB  = invert(authMethodToPB)
	closeReasonFromPB = invert(closeReasonToPB)
)

// ToProto converts a Record read from the sink into its wire form. A value
// with no proto counterpart (a hand-edited file) maps to the UNSPECIFIED
// enum value, which the server rejects — the shipper validates with
// FromProto before sending, so that never reaches the wire.
func ToProto(r Record) *pb.SSHSessionRecord {
	out := &pb.SSHSessionRecord{
		SessionId:   r.SessionID,
		Phase:       phaseToPB[r.Phase],
		OccurredAt:  timestamppb.New(r.OccurredAt),
		ClientIp:    r.ClientIP,
		ClientPort:  int32(r.ClientPort), // #nosec G115 -- a TCP port fits int32
		Login:       r.Login,
		Target:      r.Target,
		AuthMethod:  authMethodToPB[r.AuthMethod],
		CloseReason: closeReasonToPB[r.CloseReason],
	}
	if r.Credential != (Credential{}) {
		out.Credential = &pb.SSHSessionCredential{
			KeyId:            r.KeyID,
			Serial:           r.Serial,
			CaKeyFingerprint: r.CAFingerprint,
			KeyFingerprint:   r.KeyFingerprint,
		}
	}
	return out
}

// FromProto converts a wire record back into a Record, enforcing the same
// invariants the server enforces on ingest: a known phase, a session id, an
// occurred_at, known enum numbers, close_reason present exactly when the
// phase is close. An absent auth_method stays empty (the plugin omits it on
// old records); an UNSPECIFIED/unknown close_reason on a close is an error.
func FromProto(p *pb.SSHSessionRecord) (Record, error) {
	if p == nil {
		return Record{}, fmt.Errorf("nil record")
	}
	if p.GetSessionId() == "" {
		return Record{}, fmt.Errorf("empty session_id")
	}
	phase, ok := phaseFromPB[p.GetPhase()]
	if !ok {
		return Record{}, fmt.Errorf("session %q: invalid phase %v", p.GetSessionId(), p.GetPhase())
	}
	if p.GetOccurredAt() == nil {
		return Record{}, fmt.Errorf("session %q: missing occurred_at", p.GetSessionId())
	}
	r := Record{
		SessionID:  p.GetSessionId(),
		Phase:      phase,
		OccurredAt: p.GetOccurredAt().AsTime(),
		ClientIP:   p.GetClientIp(),
		ClientPort: int(p.GetClientPort()),
		Login:      p.GetLogin(),
		Target:     p.GetTarget(),
	}
	if am := p.GetAuthMethod(); am != pb.SSHAuthMethod_SSH_AUTH_METHOD_UNSPECIFIED {
		v, ok := authMethodFromPB[am]
		if !ok {
			return Record{}, fmt.Errorf("session %q: invalid auth_method %v", r.SessionID, am)
		}
		r.AuthMethod = v
	}
	if c := p.GetCredential(); c != nil {
		r.Credential = Credential{
			KeyID:          c.GetKeyId(),
			Serial:         c.GetSerial(),
			CAFingerprint:  c.GetCaKeyFingerprint(),
			KeyFingerprint: c.GetKeyFingerprint(),
		}
	}
	cr := p.GetCloseReason()
	switch {
	case phase == SessionPhaseOpen && cr != pb.SSHCloseReason_SSH_CLOSE_REASON_UNSPECIFIED:
		return Record{}, fmt.Errorf("session %q: close_reason set on an open record", r.SessionID)
	case phase == SessionPhaseClose:
		v, ok := closeReasonFromPB[cr]
		if !ok {
			return Record{}, fmt.Errorf("session %q: close record needs a valid close_reason, got %v", r.SessionID, cr)
		}
		r.CloseReason = v
	}
	return r, nil
}
