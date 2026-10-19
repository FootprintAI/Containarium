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
	SessionPhaseOpen:   pb.SSHSessionPhase_SSH_SESSION_PHASE_OPEN,
	SessionPhaseClose:  pb.SSHSessionPhase_SSH_SESSION_PHASE_CLOSE,
	SessionPhaseDenied: pb.SSHSessionPhase_SSH_SESSION_PHASE_DENIED,

	SessionPhaseAuthFailed: pb.SSHSessionPhase_SSH_SESSION_PHASE_AUTH_FAILED,
	SessionPhaseBanned:     pb.SSHSessionPhase_SSH_SESSION_PHASE_BANNED,
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
		SessionId:     r.SessionID,
		Phase:         phaseToPB[r.Phase],
		OccurredAt:    timestamppb.New(r.OccurredAt),
		ClientIp:      r.ClientIP,
		ClientPort:    int32(r.ClientPort), // #nosec G115 -- a TCP port fits int32
		Login:         r.Login,
		Target:        r.Target,
		AuthMethod:    authMethodToPB[r.AuthMethod],
		CloseReason:   closeReasonToPB[r.CloseReason],
		UserId:        r.UserID,
		AuthzDecision: r.AuthzDecision,
		DenyReason:    r.DenyReason,
		Enforced:      r.Enforced,

		FailureCount:    r.FailureCount,
		BanListener:     r.BanListener,
		SuppressedCount: r.SuppressedCount,
	}
	if r.BannedUntil != nil {
		out.BannedUntil = timestamppb.New(*r.BannedUntil)
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
	if _, ok := pb.SSHAuthzDecision_name[int32(p.GetAuthzDecision())]; !ok {
		return Record{}, fmt.Errorf("session %q: invalid authz_decision %v", p.GetSessionId(), p.GetAuthzDecision())
	}
	if _, ok := pb.SSHDenyReason_name[int32(p.GetDenyReason())]; !ok {
		return Record{}, fmt.Errorf("session %q: invalid deny_reason %v", p.GetSessionId(), p.GetDenyReason())
	}
	r := Record{
		SessionID:     p.GetSessionId(),
		Phase:         phase,
		OccurredAt:    p.GetOccurredAt().AsTime(),
		ClientIP:      p.GetClientIp(),
		ClientPort:    int(p.GetClientPort()),
		Login:         p.GetLogin(),
		Target:        p.GetTarget(),
		UserID:        p.GetUserId(),
		AuthzDecision: p.GetAuthzDecision(),
		DenyReason:    p.GetDenyReason(),
		Enforced:      p.GetEnforced(),

		FailureCount:    p.GetFailureCount(),
		BanListener:     p.GetBanListener(),
		SuppressedCount: p.GetSuppressedCount(),
	}
	if t := p.GetBannedUntil(); t != nil {
		u := t.AsTime()
		r.BannedUntil = &u
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
	case phase != SessionPhaseClose && cr != pb.SSHCloseReason_SSH_CLOSE_REASON_UNSPECIFIED:
		return Record{}, fmt.Errorf("session %q: close_reason set on a %s record", r.SessionID, phase)
	case phase == SessionPhaseClose:
		v, ok := closeReasonFromPB[cr]
		if !ok {
			return Record{}, fmt.Errorf("session %q: close record needs a valid close_reason, got %v", r.SessionID, cr)
		}
		r.CloseReason = v
	}
	if err := validateSourceRecord(r); err != nil {
		return Record{}, err
	}
	return r, nil
}

// validateSourceRecord checks the fields specific to the source-IP phases
// (#2419) and rejects them on any other phase, so a malformed or hand-edited
// record is refused whole rather than stored with meaningless fields.
func validateSourceRecord(r Record) error {
	sourcePhase := r.Phase == SessionPhaseAuthFailed || r.Phase == SessionPhaseBanned
	hasSourceFields := r.FailureCount != 0 || r.SuppressedCount != 0 || r.BannedUntil != nil || r.BanListener != pb.SSHBanListener_SSH_BAN_LISTENER_UNSPECIFIED
	if !sourcePhase {
		if hasSourceFields {
			return fmt.Errorf("session %q: failure/ban fields set on a %s record", r.SessionID, r.Phase)
		}
		return nil
	}
	if _, ok := pb.SSHBanListener_name[int32(r.BanListener)]; !ok || r.BanListener == pb.SSHBanListener_SSH_BAN_LISTENER_UNSPECIFIED {
		return fmt.Errorf("session %q: %s record needs a valid ban_listener, got %v", r.SessionID, r.Phase, r.BanListener)
	}
	switch r.Phase {
	case SessionPhaseBanned:
		if r.ClientIP == "" || r.FailureCount == 0 || r.BannedUntil == nil {
			return fmt.Errorf("session %q: banned record needs client_ip, failure_count and banned_until", r.SessionID)
		}
		if r.SuppressedCount != 0 {
			return fmt.Errorf("session %q: suppressed_count set on a banned record", r.SessionID)
		}
	case SessionPhaseAuthFailed:
		if r.BannedUntil != nil {
			return fmt.Errorf("session %q: banned_until set on an auth_failed record", r.SessionID)
		}
		if r.ClientIP == "" {
			// The overflow record: only the suppressed count means anything.
			if r.SuppressedCount == 0 || r.FailureCount != 0 {
				return fmt.Errorf("session %q: auth_failed record without client_ip must carry only suppressed_count", r.SessionID)
			}
		} else if r.FailureCount == 0 || r.SuppressedCount != 0 {
			return fmt.Errorf("session %q: auth_failed record needs failure_count and no suppressed_count", r.SessionID)
		}
	}
	if r.Login != "" || r.Target != "" || r.Credential != (Credential{}) || r.AuthMethod != "" {
		return fmt.Errorf("session %q: %s record must not carry login, target or credential (no session existed)", r.SessionID, r.Phase)
	}
	return nil
}
