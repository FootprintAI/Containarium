package sshsession

import (
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"strings"
)

// Shared metadata keys survive sshpiperd's NextPlugin transition and are read
// by the session observer on both pipe start and close.
const (
	MetaUserID        = "containarium.ssh_authz.user_id"
	MetaAuthzDecision = "containarium.ssh_authz.decision"
	MetaDenyReason    = "containarium.ssh_authz.deny_reason"
	// MetaEnforced is "true" for every session ssh-authz-plugin admitted in
	// enforce mode, including one it routed without a daemon decision (a
	// certificate); empty in audit-only mode.
	MetaEnforced = "containarium.ssh_authz.enforced"
	// MetaTarget is the upstream host:port the enforcing ssh-authz-plugin
	// routed the connection to. Both the open and the close record carry it,
	// so a config.yaml re-rendered mid-session cannot split a session across
	// two targets. Empty when yaml routed: the record builder then resolves
	// the login from config.yaml.
	MetaTarget = "containarium.ssh_session.target"
)

type AuthzDecision string

const (
	AuthzAllow AuthzDecision = "ALLOW"
	AuthzDeny  AuthzDecision = "DENY"
)

type DenyReason string

const (
	DenyUnknownKey          DenyReason = "UNKNOWN_KEY"
	DenyUserInactive        DenyReason = "USER_INACTIVE"
	DenyNoAccess            DenyReason = "NO_ACCESS"
	DenyKeyExpired          DenyReason = "KEY_EXPIRED"
	DenyApprovalPending     DenyReason = "APPROVAL_PENDING"
	DenyApprovalDenied      DenyReason = "APPROVAL_DENIED"
	DenyUpstreamUnavailable DenyReason = "UPSTREAM_UNAVAILABLE"
)

func DecisionFromProto(v pb.SSHAuthzDecision) AuthzDecision {
	if v == pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_UNSPECIFIED {
		return ""
	}
	return AuthzDecision(strings.TrimPrefix(v.String(), "SSH_AUTHZ_DECISION_"))
}

func ReasonFromProto(v pb.SSHDenyReason) DenyReason {
	if v == pb.SSHDenyReason_SSH_DENY_REASON_UNSPECIFIED {
		return ""
	}
	return DenyReason(strings.TrimPrefix(v.String(), "SSH_DENY_REASON_"))
}

func DecisionToProto(v AuthzDecision) pb.SSHAuthzDecision {
	if v == "" {
		return pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_UNSPECIFIED
	}
	n, ok := pb.SSHAuthzDecision_value["SSH_AUTHZ_DECISION_"+string(v)]
	if !ok || n == 0 {
		return pb.SSHAuthzDecision(-1)
	}
	return pb.SSHAuthzDecision(n)
}

func ReasonToProto(v DenyReason) pb.SSHDenyReason {
	if v == "" {
		return pb.SSHDenyReason_SSH_DENY_REASON_UNSPECIFIED
	}
	n, ok := pb.SSHDenyReason_value["SSH_DENY_REASON_"+string(v)]
	if !ok || n == 0 {
		return pb.SSHDenyReason(-1)
	}
	return pb.SSHDenyReason(n)
}
