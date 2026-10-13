package sshauthz

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/tg123/sshpiper/libplugin"
	"golang.org/x/crypto/ssh"
)

// Metadata keys written to ConnMeta.Metadata by this plugin and read by the
// ssh-session-plugin to populate SSHSessionRecord's authz fields.
const (
	MetaUserID    = "containarium.ssh_authz.user_id"
	MetaDecision  = "containarium.ssh_authz.decision"
	MetaDenyReason = "containarium.ssh_authz.deny_reason"
	MetaEnforced  = "containarium.ssh_authz.enforced"
)

// BackendResolver maps an SSH login to the backend's HTTP base URL.
// The implementation wraps the KeyStore and the backend IP/port map;
// the interface exists so tests can inject a stub without the full
// sentinel runtime.
type BackendResolver interface {
	// ResolveLogin returns the HTTP base URL (e.g. "http://10.0.0.2:8080")
	// for the backend that the given SSH login is routed to.
	// ok is false when no backend is registered for this login.
	ResolveLogin(login string) (backendURL string, ok bool)
}

// Config is everything the sshauthz plugin needs. All fields except
// Resolver and Authorizer have defaults.
type Config struct {
	// Resolver maps login → backend HTTP base URL. Required.
	Resolver BackendResolver
	// Authorizer calls the backend's /v1/ssh/authorize. Required.
	Authorizer Authorizer
	// Cache is the positive-results cache. nil creates a default in-memory
	// cache with the real clock.
	Cache *Cache
	// Grace is how long a cached positive is honoured after it expires when
	// the backend is unreachable (transport error or 5xx). Default: 5m.
	Grace time.Duration
	// Timeout bounds a single Authorize call. Default: 3s.
	Timeout time.Duration
	// Logf receives one diagnostic line per decision. nil = log.Printf.
	Logf func(format string, args ...any)
}

// Plugin is the sshpiperd plugin that performs SSH live authorization.
// It is always audit-only: PublicKeyCallback always defers (returns
// UpstreamNextPluginAuth) so the routing plugin's decision is never
// overridden. The decision and reason are stashed in ConnMeta.Metadata
// for the ssh-session-plugin to record.
type Plugin struct {
	cfg Config
}

// New validates cfg and applies defaults.
func New(cfg Config) (*Plugin, error) {
	if cfg.Resolver == nil {
		return nil, fmt.Errorf("sshauthz: Resolver is required")
	}
	if cfg.Authorizer == nil {
		return nil, fmt.Errorf("sshauthz: Authorizer is required")
	}
	if cfg.Cache == nil {
		cfg.Cache = NewCache(nil)
	}
	if cfg.Grace <= 0 {
		cfg.Grace = 5 * time.Minute
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 3 * time.Second
	}
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	return &Plugin{cfg: cfg}, nil
}

// PluginConfig returns the callbacks sshpiperd drives.
func (p *Plugin) PluginConfig() libplugin.SshPiperPluginConfig {
	return libplugin.SshPiperPluginConfig{
		PublicKeyCallback: p.publicKeyCallback,
	}
}

// publicKeyCallback is the core: on every public-key auth attempt it runs
// the decision logic and stashes the outcome as ConnMeta metadata. It always
// defers to the next plugin — it is audit-only in this issue.
func (p *Plugin) publicKeyCallback(conn libplugin.ConnMetadata, key []byte) (*libplugin.Upstream, error) {
	meta := make(map[string]string)
	// enforced is always false in audit-only mode (this issue).
	meta[MetaEnforced] = "false"

	login := conn.User()
	clientAddr := conn.RemoteAddr()

	// 1. Certificate offered → skip authz (cert auth carries its own
	//    identity assertion via the CA trust chain; the enforce path for
	//    certs is a separate issue). Still defer so the routing plugin sees
	//    the credential and can act on it.
	pub, err := ssh.ParsePublicKey(key)
	if err != nil {
		// Unparseable key — log and defer; the routing plugin will reject it.
		p.cfg.Logf("[ssh-authz] %s: unparseable key from %s, deferring: %v", login, clientAddr, err)
		return p.defer_(meta), nil
	}

	if _, isCert := pub.(*ssh.Certificate); isCert {
		p.cfg.Logf("[ssh-authz] %s from %s: certificate auth, skipping authz check", login, clientAddr)
		return p.defer_(meta), nil
	}

	fingerprint := ssh.FingerprintSHA256(pub)

	// 2. Resolve login → backend URL. Unknown login → defer without authz.
	backendURL, ok := p.cfg.Resolver.ResolveLogin(login)
	if !ok {
		p.cfg.Logf("[ssh-authz] %s from %s: no backend for login, deferring (routing plugin will handle)", login, clientAddr)
		return p.defer_(meta), nil
	}

	// 3. Cache hit → stash and defer.
	if userID, _, hit := p.cfg.Cache.Get(backendURL, login, fingerprint); hit {
		p.cfg.Logf("[ssh-authz] %s from %s: cache hit (user_id=%s)", login, clientAddr, userID)
		meta[MetaUserID] = userID
		meta[MetaDecision] = DecisionAllow.String()
		return p.defer_(meta), nil
	}

	// 4. Call the backend.
	ctx, cancel := context.WithTimeout(context.Background(), p.cfg.Timeout)
	defer cancel()

	res, authzErr := p.cfg.Authorizer.Authorize(ctx, backendURL, login, fingerprint, clientAddr)

	if authzErr != nil {
		// Transport error or 5xx — check the grace cache.
		if userID, graceOK := p.cfg.Cache.GraceGet(backendURL, login, fingerprint, p.cfg.Grace); graceOK {
			p.cfg.Logf("[ssh-authz] %s from %s: upstream error (%v), grace cache hit (user_id=%s)", login, clientAddr, authzErr, userID)
			meta[MetaUserID] = userID
			meta[MetaDecision] = DecisionAllow.String()
			return p.defer_(meta), nil
		}
		// Grace cache miss — treat as DENY UPSTREAM_UNAVAILABLE.
		p.cfg.Logf("[ssh-authz] %s from %s: upstream error (%v), no grace cache, audit-deny UPSTREAM_UNAVAILABLE", login, clientAddr, authzErr)
		meta[MetaDecision] = DecisionDeny.String()
		meta[MetaDenyReason] = DenyReasonUpstreamUnavailable.String()
		return p.defer_(meta), nil
	}

	// 5. Dispatch on decision.
	switch res.Decision {
	case DecisionAllow:
		p.cfg.Cache.Put(backendURL, login, fingerprint, res.UserID, res.CacheTTL)
		p.cfg.Logf("[ssh-authz] %s from %s: ALLOW (user_id=%s, cache_ttl=%s)", login, clientAddr, res.UserID, res.CacheTTL)
		meta[MetaUserID] = res.UserID
		meta[MetaDecision] = DecisionAllow.String()

	case DecisionApprovalPending:
		// Treated as DENY in this issue; keyboard-interactive is umbrella B.
		p.cfg.Logf("[ssh-authz] %s from %s: APPROVAL_PENDING, treating as deny (audit-only)", login, clientAddr)
		meta[MetaDecision] = DecisionDeny.String()
		meta[MetaDenyReason] = DenyReasonApprovalDenied.String()

	default: // DecisionDeny and DecisionUnspecified.
		p.cfg.Logf("[ssh-authz] %s from %s: DENY %s (audit-only, deferring)", login, clientAddr, res.DenyReason)
		meta[MetaDecision] = DecisionDeny.String()
		meta[MetaDenyReason] = res.DenyReason.String()
	}

	return p.defer_(meta), nil
}

// defer_ wraps meta in an UpstreamNextPluginAuth so sshpiperd advances
// to the next plugin in the chain, merging meta into the connection's
// shared metadata map.
func (p *Plugin) defer_(meta map[string]string) *libplugin.Upstream {
	return &libplugin.Upstream{
		Auth: &libplugin.Upstream_NextPlugin{
			NextPlugin: &libplugin.UpstreamNextPluginAuth{Meta: meta},
		},
	}
}
