package sshauthz

import (
	"context"
	"errors"
	"net"
	"strconv"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/tg123/sshpiper/libplugin"
	"golang.org/x/crypto/ssh"
)

const (
	MetaUserID     = "containarium.authz.user_id"
	MetaDecision   = "containarium.authz.decision"
	MetaDenyReason = "containarium.authz.deny_reason"
	MetaEnforced   = "containarium.authz.enforced"
)

// Plugin is audit-only: every callback, including denials and internal errors,
// returns NextPluginAuth with nil error. It never accepts or rejects a login.
// sshpiperd advances its chain after the first offered key and does not reset
// it for later key offers on the same connection (see sshsession.Plugin).
type Plugin struct {
	Authorizer Authorizer
	Resolver   BackendResolver
	Cache      Cache
	Timeout    time.Duration
	SentinelID string
	Logf       func(string, ...any)
}

func (p *Plugin) Config() libplugin.SshPiperPluginConfig {
	return libplugin.SshPiperPluginConfig{PublicKeyCallback: p.publicKeyCallback}
}

func deferAuth(meta map[string]string) (*libplugin.Upstream, error) {
	return &libplugin.Upstream{Auth: libplugin.CreateNextPluginAuth(meta)}, nil
}

func (p *Plugin) publicKeyCallback(conn libplugin.ConnMetadata, wire []byte) (*libplugin.Upstream, error) {
	// Always overwrite previous audit metadata. A malformed credential or an
	// unknown route must not inherit a previous offered key's identity.
	meta := map[string]string{MetaUserID: "", MetaDecision: "", MetaDenyReason: "", MetaEnforced: "false"}
	key, err := ssh.ParsePublicKey(wire)
	if err != nil {
		return deferAuth(meta)
	}
	if _, cert := key.(*ssh.Certificate); cert {
		return deferAuth(meta)
	}
	if p.Resolver == nil {
		return deferAuth(meta)
	}
	backend, known := p.Resolver.BackendForLogin(conn.User())
	if !known {
		return deferAuth(meta)
	}
	cacheKey := CacheKey{Backend: backend, Login: conn.User(), Fingerprint: ssh.FingerprintSHA256(key)}
	decision := pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW
	reason := pb.SSHDenyReason_SSH_DENY_REASON_UNSPECIFIED
	userID := ""
	cached := false
	if p.Cache != nil {
		userID, cached = p.Cache.Fresh(cacheKey)
	}
	if !cached {
		timeout := p.Timeout
		if timeout <= 0 {
			timeout = DefaultTimeout
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		ip := conn.RemoteAddr()
		if host, _, err := net.SplitHostPort(ip); err == nil {
			ip = host
		}
		request := &pb.AuthorizeSSHRequest{Login: conn.User(), ClientIp: ip, SentinelId: p.SentinelID, Credential: &pb.SSHCredential{Kind: &pb.SSHCredential_PublicKey{PublicKey: &pb.SSHPublicKeyCredential{FingerprintSha256: cacheKey.Fingerprint, KeyType: keyType(key.Type())}}}}
		var response *pb.AuthorizeSSHResponse
		var callErr error
		if p.Authorizer == nil {
			callErr = errors.New("SSH authorizer not configured")
		} else {
			response, callErr = p.Authorizer.Authorize(ctx, backend, request)
		}
		decision, reason = pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY, pb.SSHDenyReason_SSH_DENY_REASON_UPSTREAM_UNAVAILABLE
		if callErr != nil {
			if errors.Is(callErr, ErrUpstreamUnavailable) && p.Cache != nil {
				if uid, ok := p.Cache.Grace(cacheKey); ok {
					userID = uid
					decision = pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW
					reason = pb.SSHDenyReason_SSH_DENY_REASON_UNSPECIFIED
				}
			}
			if !errors.Is(callErr, ErrUpstreamUnavailable) && p.Cache != nil {
				p.Cache.Invalidate(cacheKey)
			}
			if p.Logf != nil {
				p.Logf("ssh-authz backend=%q login=%q error=%q audit-only", backend, conn.User(), callErr.Error())
			}
		} else if response != nil {
			userID = response.GetUserId()
			// Treat unspecified/unknown enums, contradictory ALLOW+reason and bad
			// TTLs as protocol failures; they must never create a positive entry.
			_, knownReason := pb.SSHDenyReason_name[int32(response.GetDenyReason())]
			switch {
			case response.GetDecision() == pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY && knownReason:
				reason = response.GetDenyReason()
				if p.Cache != nil {
					p.Cache.Invalidate(cacheKey)
				}
			case response.GetDecision() == pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW && response.GetDenyReason() == pb.SSHDenyReason_SSH_DENY_REASON_UNSPECIFIED:
				ttl := DefaultTTL
				valid := true
				if response.CacheTtl != nil {
					valid = response.CacheTtl.CheckValid() == nil
					ttl = response.CacheTtl.AsDuration()
					valid = valid && ttl >= 0
				}
				if valid {
					decision = pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW
					reason = pb.SSHDenyReason_SSH_DENY_REASON_UNSPECIFIED
					if p.Cache != nil {
						p.Cache.Put(cacheKey, userID, ttl)
					}
				} else if p.Cache != nil {
					p.Cache.Invalidate(cacheKey)
				}
			default:
				if p.Cache != nil {
					p.Cache.Invalidate(cacheKey)
				}
			}
		} else if p.Cache != nil {
			p.Cache.Invalidate(cacheKey)
		}
	}
	meta[MetaUserID] = userID
	meta[MetaDecision] = strconv.FormatInt(int64(decision), 10)
	meta[MetaDenyReason] = strconv.FormatInt(int64(reason), 10)
	if p.Logf != nil {
		p.Logf("ssh-authz backend=%q login=%q decision=%s deny_reason=%s user_id=%q enforced=false", backend, conn.User(), decision, reason, userID)
	}
	return deferAuth(meta)
}

func keyType(kind string) pb.SSHKeyType {
	switch kind {
	case ssh.KeyAlgoED25519:
		return pb.SSHKeyType_SSH_KEY_TYPE_ED25519
	case ssh.KeyAlgoRSA:
		return pb.SSHKeyType_SSH_KEY_TYPE_RSA
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		return pb.SSHKeyType_SSH_KEY_TYPE_ECDSA
	case ssh.KeyAlgoSKED25519:
		return pb.SSHKeyType_SSH_KEY_TYPE_SK_ED25519
	case ssh.KeyAlgoSKECDSA256:
		return pb.SSHKeyType_SSH_KEY_TYPE_SK_ECDSA
	default:
		return pb.SSHKeyType_SSH_KEY_TYPE_UNSPECIFIED
	}
}
