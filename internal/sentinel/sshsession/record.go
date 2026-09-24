// Package sshsession implements containarium#1980: a structured session
// lifecycle record for SSH connections accepted by the sentinel's
// sshpiperd. sshpiperd is the only place a client's key or certificate is
// verified (containers run no sshd of their own), but today an accepted
// connection produces no record at all — only the failtoban plugin's
// auth-failure line exists. This package plugs into sshpiperd's own
// plugin chain (see plugin.go) to emit an "open" record when a pipe is
// established and a "close" record when it ends, correlated by
// session_id, without touching the failure-path logging failtoban's
// fail2ban regex depends on.
package sshsession

import "time"

// SessionPhase distinguishes the two records emitted per accepted SSH
// session. Typed per this repo's strong-typing convention (CLAUDE.md) —
// not a bare string with a comment listing the allowed values.
type SessionPhase string

const (
	SessionPhaseOpen  SessionPhase = "open"
	SessionPhaseClose SessionPhase = "close"
)

// AuthMethod is how the client's credential was presented.
type AuthMethod string

const (
	AuthMethodCertificate AuthMethod = "certificate"
	AuthMethodPublicKey   AuthMethod = "publickey"
	// AuthMethodUnknown is recorded when the offered key could not be
	// parsed at all (see ExtractCredential) — it is never used to block
	// a connection, only to mark that this record's credential fields
	// could not be populated.
	AuthMethodUnknown AuthMethod = "unknown"
)

// CloseReason classifies why a "close" record was emitted.
type CloseReason string

const (
	// CloseReasonNormal covers both a nil WaitWithHook error and an
	// explicit client-initiated disconnect (observed in practice as SSH
	// disconnect reason 11, "disconnected by user").
	CloseReasonNormal CloseReason = "normal"
	// CloseReasonUpstreamGone covers the upstream/backend connection
	// dropping out from under the pipe.
	CloseReasonUpstreamGone CloseReason = "upstream_gone"
	// CloseReasonProxyShutdown is emitted by Plugin.Shutdown for any
	// session that was still open when the plugin process itself was
	// asked to stop (sshpiperd restarting or exiting) — see plugin.go.
	// Without this, a session killed by a proxy restart would leave
	// only an "open" record, indistinguishable from a session still
	// legitimately running.
	CloseReasonProxyShutdown CloseReason = "proxy_shutdown"
	// CloseReasonError is the catch-all for a close whose cause didn't
	// match a more specific classification. Still distinguishable from
	// CloseReasonNormal, which is the property acceptance criterion 5
	// actually requires.
	CloseReasonError CloseReason = "error"
)

// Credential is the non-secret handle that identifies the credential used
// to authenticate a session. For a certificate: KeyID + Serial +
// CAFingerprint (the certificate's own key_id/serial, per
// containarium#1980, plus the CA public key's fingerprint since under
// TrustedUserCAKeys the login name alone identifies only the target
// account, not the person). For a raw public key: KeyFingerprint only.
//
// Every field here is a derived identifier (a SHA256 fingerprint, an
// operator-assigned key_id string, an integer serial) — never raw key
// material, a signature, or anything else that could be replayed.
type Credential struct {
	KeyID          string `json:"key_id,omitempty"`
	Serial         uint64 `json:"serial,omitempty"`
	CAFingerprint  string `json:"ca_key_fingerprint,omitempty"`
	KeyFingerprint string `json:"key_fingerprint,omitempty"`
}

// Record is one session lifecycle event. Exactly one SessionPhaseOpen and
// exactly one SessionPhaseClose record are emitted per accepted SSH
// connection (barring CloseReasonProxyShutdown's own best-effort
// flush — see plugin.go), correlated by SessionID.
//
// This is connection metadata only: it never carries a private key,
// token, or session content (see Credential's doc comment).
type Record struct {
	SessionID  string       `json:"session_id"`
	Phase      SessionPhase `json:"phase"`
	OccurredAt time.Time    `json:"occurred_at"`

	// ClientIP/ClientPort are always the real DOWNSTREAM (client-facing)
	// address. sshpiperd's plugin API hands PipeStart/PipeError only the
	// downstream ConnMetadata — see plugin.go's buildRecord — so an
	// upstream/proxy-local address cannot land here by construction.
	ClientIP   string `json:"client_ip"`
	ClientPort int    `json:"client_port,omitempty"`

	// Login is the SSH username presented. Under TrustedUserCAKeys this
	// identifies the target account, not necessarily the person — see
	// Credential for what actually distinguishes the person.
	Login string `json:"login"`

	// Target is the backend/container endpoint (host:port) the sentinel's
	// sshpiper config routes Login to at the time this record was built —
	// see target.go. Empty if it could not be resolved (e.g. config.yaml
	// unreadable at record time).
	Target string `json:"target,omitempty"`

	AuthMethod AuthMethod `json:"auth_method,omitempty"`
	Credential

	// CloseReason is set only on a SessionPhaseClose record.
	CloseReason CloseReason `json:"close_reason,omitempty"`
}
