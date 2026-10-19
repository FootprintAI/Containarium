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
	// MetaEnforced is "true" when ssh-authz-plugin ran in enforce mode for
	// this credential; empty in audit-only mode or when no check ran.
	MetaEnforced = "containarium.ssh_authz.enforced"
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
