package sshauthz

import (
	"fmt"
	"time"

	"github.com/footprintai/containarium/internal/sentinel/sshsession"
	"github.com/tg123/sshpiper/libplugin"
)

// Bounds on decisions kept for connections whose pipe has not started, such
// as a connection that was routed on a publickey query and then dropped.
const (
	maxPending = 10000
	pendingTTL = 10 * time.Minute
)

type pendingConn struct {
	meta map[string]string
	at   time.Time
}

// pass handles an offer this plugin does not refuse. Audit-only mode defers it
// with the decision metadata. Enforce mode routes it as the yaml plugin would
// and returns the upstream itself: sshpiperd's chain only moves forward within
// a connection, so a deferral would let yaml alone judge every later offer on
// that connection (#2629). sshpiperd copies no metadata when a plugin returns
// an upstream, so the decision and credential are kept here, by connection,
// for this plugin's own session records. The SSH server re-runs this callback
// for the key that finally signs unless it was the last key checked, so the
// last routed offer is the one that authenticated.
func (p *Plugin) pass(conn libplugin.ConnMetadata, wire []byte, meta map[string]string) (*libplugin.Upstream, error) {
	if !p.cfg.Enforce {
		return deferWith(meta)
	}
	up, err := p.cfg.Router.Route(conn, wire)
	if err != nil {
		p.cfg.Logf("[ssh-authz] login=%q: not routed: %v", conn.User(), err)
		return nil, fmt.Errorf("ssh authz: login %q not routed: %w", conn.User(), err)
	}
	for k, v := range sshsession.CredentialMeta(wire) {
		meta[k] = v
	}
	p.remember(conn.UniqueID(), meta)
	return up, nil
}

func (p *Plugin) remember(id string, meta map[string]string) {
	now := p.cfg.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.pending[id]; !ok && len(p.pending) >= maxPending {
		oldest := ""
		for k, v := range p.pending {
			if now.Sub(v.at) >= pendingTTL {
				delete(p.pending, k)
			} else if oldest == "" || v.at.Before(p.pending[oldest].at) {
				oldest = k
			}
		}
		if len(p.pending) >= maxPending {
			delete(p.pending, oldest)
		}
	}
	p.pending[id] = pendingConn{meta: meta, at: now}
}

// stashedConn hands ssh-session-plugin's record builder the metadata this
// plugin kept for the connection.
type stashedConn struct {
	libplugin.ConnMetadata
	meta map[string]string
}

func (c stashedConn) GetMeta(key string) string { return c.meta[key] }

func (p *Plugin) pipeStart(conn libplugin.ConnMetadata) {
	p.mu.Lock()
	pc, ok := p.pending[conn.UniqueID()]
	if ok {
		delete(p.pending, conn.UniqueID())
		p.open[conn.UniqueID()] = pc.meta
	}
	p.mu.Unlock()
	if !ok {
		// ssh-session-plugin skips this connection too, so the session has no
		// open or close record. Make the gap visible; name no credential.
		p.cfg.Logf("[ssh-authz] session=%q login=%q: no pending decision (evicted from the bounded stash); no session records written", conn.UniqueID(), conn.User())
		return
	}
	p.session.Config().PipeStartCallback(stashedConn{conn, pc.meta})
}

func (p *Plugin) pipeError(conn libplugin.ConnMetadata, err error) {
	p.mu.Lock()
	meta, ok := p.open[conn.UniqueID()]
	delete(p.open, conn.UniqueID())
	p.mu.Unlock()
	if ok {
		p.session.Config().PipeErrorCallback(stashedConn{conn, meta}, err)
	}
}

// Shutdown writes a proxy_shutdown close record for every session this plugin
// opened and never closed. Call it once before the process exits.
func (p *Plugin) Shutdown() { p.session.Shutdown() }
