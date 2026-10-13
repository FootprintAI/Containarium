package sshauthz

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/footprintai/containarium/internal/sentinel/sshsession"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/tg123/sshpiper/libplugin"
	"golang.org/x/crypto/ssh"
)

const (
	DefaultGrace   = 5 * time.Minute
	DefaultTimeout = 3 * time.Second
)

type Authorizer interface {
	Authorize(context.Context, string, *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error)
}

// BackendResolver must use the same login selection rule as KeyStore.Apply.
// Errors differ from unknown logins so a broken local bridge is audited.
type BackendResolver interface {
	ResolveBackend(context.Context, string) (backend string, known bool, err error)
}

type Config struct {
	Authorizer Authorizer
	Resolver   BackendResolver
	Cache      *Cache
	Timeout    time.Duration
	SentinelID string
	Logf       func(string, ...any)
}

type Plugin struct{ cfg Config }

func New(cfg Config) (*Plugin, error) {
	if cfg.Authorizer == nil || cfg.Resolver == nil {
		return nil, errors.New("ssh authz: authorizer and backend resolver required")
	}
	if cfg.Timeout < 0 {
		return nil, errors.New("ssh authz: timeout must be positive")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.Cache == nil {
		cfg.Cache = NewCache(DefaultGrace, 0, nil)
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	return &Plugin{cfg: cfg}, nil
}

func (p *Plugin) PluginConfig() libplugin.SshPiperPluginConfig {
	return libplugin.SshPiperPluginConfig{PublicKeyCallback: p.publicKeyCallback}
}

func deferWith(meta map[string]string) (*libplugin.Upstream, error) {
	return &libplugin.Upstream{Auth: &libplugin.Upstream_NextPlugin{NextPlugin: &libplugin.UpstreamNextPluginAuth{Meta: meta}}}, nil
}

func (p *Plugin) publicKeyCallback(conn libplugin.ConnMetadata, wire []byte) (*libplugin.Upstream, error) {
	// Clear these on skipped credentials as well; metadata from another offer
	// must never claim a decision for this credential.
	meta := map[string]string{sshsession.MetaUserID: "", sshsession.MetaAuthzDecision: "", sshsession.MetaDenyReason: ""}
	key, err := ssh.ParsePublicKey(wire)
	if err != nil {
		return deferWith(meta)
	}
	if _, cert := key.(*ssh.Certificate); cert {
		return deferWith(meta)
	}
	ctx, cancel := context.WithTimeout(context.Background(), p.cfg.Timeout)
	defer cancel()
	backend, known, err := p.cfg.Resolver.ResolveBackend(ctx, conn.User())
	if err != nil {
		return p.stash(meta, conn.User(), "", unavailable())
	}
	if !known {
		return deferWith(meta)
	}
	fp := ssh.FingerprintSHA256(key)
	ck := CacheKey{Backend: backend, Login: conn.User(), Fingerprint: fp}
	if user, ok := p.cfg.Cache.Get(ck, false); ok {
		return p.stash(meta, conn.User(), backend, allowed(user))
	}
	ip := conn.RemoteAddr()
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}
	res, err := p.cfg.Authorizer.Authorize(ctx, backend, &pb.AuthorizeSSHRequest{
		Login: conn.User(), ClientIp: ip, SentinelId: p.cfg.SentinelID,
		Credential: &pb.SSHCredential{Kind: &pb.SSHCredential_PublicKey{PublicKey: &pb.SSHPublicKeyCredential{
			FingerprintSha256: fp, KeyType: keyType(key),
		}}},
	})
	// The managed daemon may report a cloud outage as a typed denial. It is
	// subject to the same bounded grace as transport errors and HTTP 5xx.
	outage := err != nil && isOutage(err)
	if err == nil && res != nil && res.GetDecision() == pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY && res.GetDenyReason() == pb.SSHDenyReason_SSH_DENY_REASON_UPSTREAM_UNAVAILABLE {
		outage = true
	}
	if outage {
		if user, ok := p.cfg.Cache.Get(ck, true); ok {
			return p.stash(meta, conn.User(), backend, allowed(user))
		}
		denied := unavailable()
		if err == nil && res != nil {
			denied.UserId = res.GetUserId()
		}
		return p.stash(meta, conn.User(), backend, denied)
	}
	if err != nil || validateResponse(res) != nil {
		p.cfg.Cache.Delete(ck)
		return p.stash(meta, conn.User(), backend, unavailable())
	}
	if res.GetDecision() == pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW {
		p.cfg.Cache.Put(ck, res.GetUserId(), res.GetCacheTtl().AsDuration())
	} else {
		p.cfg.Cache.Delete(ck)
	}
	return p.stash(meta, conn.User(), backend, res)
}

func allowed(user string) *pb.AuthorizeSSHResponse {
	return &pb.AuthorizeSSHResponse{Decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW, UserId: user}
}
func unavailable() *pb.AuthorizeSSHResponse {
	return &pb.AuthorizeSSHResponse{Decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY, DenyReason: pb.SSHDenyReason_SSH_DENY_REASON_UPSTREAM_UNAVAILABLE}
}

func validateResponse(res *pb.AuthorizeSSHResponse) error {
	if res == nil {
		return errors.New("empty authorization response")
	}
	switch res.GetDecision() {
	case pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW:
		if res.GetDenyReason() != pb.SSHDenyReason_SSH_DENY_REASON_UNSPECIFIED {
			return errors.New("allow with deny reason")
		}
		if ttl := res.GetCacheTtl(); ttl != nil {
			if err := ttl.CheckValid(); err != nil {
				return err
			}
			if ttl.AsDuration() < 0 {
				return errors.New("negative cache TTL")
			}
		}
	case pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY:
		if _, ok := pb.SSHDenyReason_name[int32(res.GetDenyReason())]; !ok || res.GetDenyReason() == pb.SSHDenyReason_SSH_DENY_REASON_UNSPECIFIED {
			return errors.New("invalid deny reason")
		}
	default:
		return fmt.Errorf("invalid decision: %v", res.GetDecision())
	}
	return nil
}

func (p *Plugin) stash(meta map[string]string, login, backend string, res *pb.AuthorizeSSHResponse) (*libplugin.Upstream, error) {
	meta[sshsession.MetaUserID] = res.GetUserId()
	meta[sshsession.MetaAuthzDecision] = string(sshsession.DecisionFromProto(res.GetDecision()))
	meta[sshsession.MetaDenyReason] = string(sshsession.ReasonFromProto(res.GetDenyReason()))
	p.cfg.Logf("[ssh-authz] login=%q backend=%q decision=%s reason=%s user_id=%q enforced=false", login, backend, meta[sshsession.MetaAuthzDecision], meta[sshsession.MetaDenyReason], res.GetUserId())
	return deferWith(meta)
}

func keyType(key ssh.PublicKey) pb.SSHKeyType {
	switch key.Type() {
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
