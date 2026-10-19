package sshauthz

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/footprintai/containarium/internal/hostport"
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
	// Enforce turns a DENY into an error from PublicKeyCallback: sshpiperd
	// keeps the chain on this plugin, so neither ssh-session-plugin nor yaml
	// is consulted for that key. Every other offer is routed by Router and
	// never deferred (see pass). False is audit-only: every decision defers.
	Enforce bool
	// Router is required in enforce mode.
	Router *Router
	// Recorder receives the SessionPhaseDenied record of an enforced denial
	// and, in enforce mode, the open and close records of routed sessions.
	// No other plugin sees those credentials. Nil drops the records.
	Recorder sshsession.Recorder
	Target   *sshsession.TargetResolver // routed target on session records
	Now      func() time.Time           // nil uses time.Now().UTC()
}

type Plugin struct {
	cfg     Config
	session *sshsession.Plugin

	mu      sync.Mutex
	pending map[string]pendingConn       // routed, pipe not started yet
	open    map[string]map[string]string // pipe started, not closed yet
}

func New(cfg Config) (*Plugin, error) {
	if cfg.Authorizer == nil || cfg.Resolver == nil {
		return nil, errors.New("ssh authz: authorizer and backend resolver required")
	}
	if cfg.Enforce && cfg.Router == nil {
		return nil, errors.New("ssh authz: enforce mode requires a router")
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
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	session := &sshsession.Plugin{Recorder: cfg.Recorder, Target: cfg.Target, Now: cfg.Now, SkipUnobserved: true}
	return &Plugin{cfg: cfg, session: session, pending: map[string]pendingConn{}, open: map[string]map[string]string{}}, nil
}

func (p *Plugin) PluginConfig() libplugin.SshPiperPluginConfig {
	cfg := libplugin.SshPiperPluginConfig{PublicKeyCallback: p.publicKeyCallback}
	if p.cfg.Enforce {
		cfg.PipeStartCallback, cfg.PipeErrorCallback = p.pipeStart, p.pipeError
	}
	return cfg
}

func deferWith(meta map[string]string) (*libplugin.Upstream, error) {
	return &libplugin.Upstream{Auth: &libplugin.Upstream_NextPlugin{NextPlugin: &libplugin.UpstreamNextPluginAuth{Meta: meta}}}, nil
}

func (p *Plugin) publicKeyCallback(conn libplugin.ConnMetadata, wire []byte) (*libplugin.Upstream, error) {
	// Clear these on skipped credentials as well; metadata from another offer
	// must never claim a decision for this credential.
	meta := map[string]string{sshsession.MetaUserID: "", sshsession.MetaAuthzDecision: "", sshsession.MetaDenyReason: "", sshsession.MetaEnforced: ""}
	key, err := ssh.ParsePublicKey(wire)
	if err != nil {
		return p.pass(conn, wire, meta)
	}
	if _, cert := key.(*ssh.Certificate); cert {
		return p.pass(conn, wire, meta)
	}
	fp := ssh.FingerprintSHA256(key)
	ctx, cancel := context.WithTimeout(context.Background(), p.cfg.Timeout)
	defer cancel()
	backend, known, err := p.cfg.Resolver.ResolveBackend(ctx, conn.User())
	if err != nil {
		return p.stash(meta, conn, wire, "", fp, unavailable())
	}
	if !known {
		return p.pass(conn, wire, meta)
	}
	ck := CacheKey{Backend: backend, Login: conn.User(), Fingerprint: fp}
	if user, ok := p.cfg.Cache.Get(ck, false); ok {
		return p.stash(meta, conn, wire, backend, fp, allowed(user))
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
			return p.stash(meta, conn, wire, backend, fp, allowed(user))
		}
		denied := unavailable()
		if err == nil && res != nil {
			denied.UserId = res.GetUserId()
		}
		return p.stash(meta, conn, wire, backend, fp, denied)
	}
	if err != nil || validateResponse(res) != nil {
		p.cfg.Cache.Delete(ck)
		return p.stash(meta, conn, wire, backend, fp, unavailable())
	}
	if res.GetDecision() == pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW {
		p.cfg.Cache.Put(ck, res.GetUserId(), res.GetCacheTtl().AsDuration())
	} else {
		p.cfg.Cache.Delete(ck)
	}
	return p.stash(meta, conn, wire, backend, fp, res)
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

func (p *Plugin) stash(meta map[string]string, conn libplugin.ConnMetadata, wire []byte, backend, fp string, res *pb.AuthorizeSSHResponse) (*libplugin.Upstream, error) {
	meta[sshsession.MetaUserID] = res.GetUserId()
	meta[sshsession.MetaAuthzDecision] = string(sshsession.DecisionFromProto(res.GetDecision()))
	meta[sshsession.MetaDenyReason] = string(sshsession.ReasonFromProto(res.GetDenyReason()))
	if p.cfg.Enforce {
		meta[sshsession.MetaEnforced] = "true"
	}
	p.cfg.Logf("[ssh-authz] login=%q backend=%q decision=%s reason=%s user_id=%q enforced=%v", conn.User(), backend, meta[sshsession.MetaAuthzDecision], meta[sshsession.MetaDenyReason], res.GetUserId(), p.cfg.Enforce)
	if !p.cfg.Enforce || res.GetDecision() == pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW {
		return p.pass(conn, wire, meta)
	}
	p.recordDenied(conn, fp, res)
	return nil, fmt.Errorf("ssh authz: login %q denied: %s", conn.User(), meta[sshsession.MetaDenyReason])
}

// recordDenied writes the ssh_session_denied record for an enforced denial.
// Like ssh-session-plugin, a sink failure never changes the auth outcome.
func (p *Plugin) recordDenied(conn libplugin.ConnMetadata, fp string, res *pb.AuthorizeSSHResponse) {
	if p.cfg.Recorder == nil {
		return
	}
	ip, port := hostport.Split(conn.RemoteAddr(), 0)
	rec := sshsession.Record{
		SessionID:     conn.UniqueID(),
		Phase:         sshsession.SessionPhaseDenied,
		OccurredAt:    p.cfg.Now(),
		ClientIP:      ip,
		ClientPort:    port,
		Login:         conn.User(),
		AuthMethod:    sshsession.AuthMethodPublicKey,
		Credential:    sshsession.Credential{KeyFingerprint: fp},
		UserID:        res.GetUserId(),
		AuthzDecision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY,
		DenyReason:    res.GetDenyReason(),
		Enforced:      true,
	}
	if err := p.cfg.Recorder.Record(rec); err != nil {
		p.cfg.Logf("[ssh-authz] login=%q: write denied record: %v", conn.User(), err)
	}
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
