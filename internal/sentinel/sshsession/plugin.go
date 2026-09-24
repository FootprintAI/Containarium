package sshsession

import (
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/footprintai/containarium/internal/hostport"
	"github.com/tg123/sshpiper/libplugin"
)

// Metadata keys stashed on the shared per-connection ConnMeta.Metadata map
// by publicKeyCallback (via UpstreamNextPluginAuth) and read back by
// PipeStart/PipeErrorCallback — see Plugin's doc comment for why the same
// map is visible to both.
const (
	metaAuthMethod     = "containarium.ssh_session.auth_method"
	metaKeyID          = "containarium.ssh_session.key_id"
	metaSerial         = "containarium.ssh_session.serial"
	metaCAFingerprint  = "containarium.ssh_session.ca_key_fingerprint"
	metaKeyFingerprint = "containarium.ssh_session.key_fingerprint"
)

// clock lets tests fix time.Now.
type clock func() time.Time

// Plugin builds the sshpiperd plugin callbacks that observe a session's
// accept and close and hand a Record to a Recorder.
//
// It MUST be chained as the FIRST plugin in the sshpiperd invocation,
// ahead of the routing plugin ("yaml"): sshpiperd's ChainPlugins
// dispatches PublicKeyAuth only to the "current" plugin in the chain, so
// to see the offered credential at all, Plugin has to be asked first.
// publicKeyCallback never itself accepts or rejects a key — it always
// defers to the next plugin via UpstreamNextPluginAuth after stashing the
// credential handle into the shared per-connection metadata map — so it
// cannot change what sshpiper's routing plugin would otherwise have
// decided, and a key it fails to parse still reaches the routing plugin
// unchanged (see publicKeyCallback and containarium#1980 acceptance
// criterion 9: never touch the auth-failure path).
//
// PipeStartCallback and PipeErrorCallback are broadcast by sshpiperd's
// ChainPlugins to every plugin in the chain regardless of which one made
// the routing decision, so Plugin still observes open/close for every
// connection yaml alone authenticates.
//
// Known limitation: sshpiperd's chain position only advances forward
// within one connection (it never resets to the first plugin for a
// second key offer on the same connection). If a single connection
// offers more than one candidate key/certificate, only the FIRST offered
// credential is captured — a later offer that is what actually
// authenticates bypasses publicKeyCallback entirely once the chain has
// moved on to yaml. A typical Containarium client (ssh -i /
// CertificateFile with one identity) only ever offers one, so this does
// not affect the common path; it is called out here as a deliberate,
// documented scope boundary rather than a silent gap.
type Plugin struct {
	Recorder Recorder
	Target   *TargetResolver
	Now      clock // nil uses time.Now().UTC()

	mu       sync.Mutex
	open     map[string]Record // sessionID -> last emitted open record, for Shutdown
	shutdown bool              // true once Shutdown has run — see pipeStartCallback
}

func (p *Plugin) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now().UTC()
}

// Config builds the libplugin.SshPiperPluginConfig for this Plugin's
// callbacks. Pass it to libplugin.NewFromStdio in main().
func (p *Plugin) Config() libplugin.SshPiperPluginConfig {
	return libplugin.SshPiperPluginConfig{
		PublicKeyCallback: p.publicKeyCallback,
		PipeStartCallback: p.pipeStartCallback,
		PipeErrorCallback: p.pipeErrorCallback,
	}
}

// publicKeyCallback observes the offered credential and always defers —
// see Plugin's doc comment.
func (p *Plugin) publicKeyCallback(conn libplugin.ConnMetadata, key []byte) (*libplugin.Upstream, error) {
	meta := map[string]string{}

	authMethod, cred, err := ExtractCredential(key)
	// Always record an auth_method, even on a parse failure: ExtractCredential
	// returns AuthMethodUnknown in that case, and "unknown" is itself the
	// useful signal (a malformed/unsupported credential probe) — leaving
	// meta[metaAuthMethod] unset here used to make buildRecord's AuthMethod
	// read back as "" (omitted from JSON via omitempty) for exactly the
	// sessions where this mattered most (containarium#1980 PR review
	// finding 2). Auth still proceeds unchanged either way (see below).
	meta[metaAuthMethod] = string(authMethod)
	if err == nil {
		if cred.KeyID != "" {
			meta[metaKeyID] = cred.KeyID
		}
		if cred.Serial != 0 {
			meta[metaSerial] = strconv.FormatUint(cred.Serial, 10)
		}
		if cred.CAFingerprint != "" {
			meta[metaCAFingerprint] = cred.CAFingerprint
		}
		if cred.KeyFingerprint != "" {
			meta[metaKeyFingerprint] = cred.KeyFingerprint
		}
	}

	return &libplugin.Upstream{
		Auth: &libplugin.Upstream_NextPlugin{
			NextPlugin: &libplugin.UpstreamNextPluginAuth{Meta: meta},
		},
	}, nil
}

func (p *Plugin) pipeStartCallback(conn libplugin.ConnMetadata) {
	rec := p.buildRecord(conn, SessionPhaseOpen)

	p.mu.Lock()
	shuttingDown := p.shutdown
	if !shuttingDown {
		if p.open == nil {
			p.open = make(map[string]Record)
		}
		p.open[rec.SessionID] = rec
	}
	p.mu.Unlock()

	p.record(rec)

	if shuttingDown {
		// This session's open callback lost the race with Shutdown (it
		// observed p.shutdown already set) — Shutdown's own iteration
		// over p.open, taken atomically under the same lock before it
		// was nil'd, could never have seen this session, since it wasn't
		// registered yet. Emit its close record right here instead of
		// leaving a dangling open record with no matching close (see
		// containarium#1980 PR review finding 1 and Shutdown's doc
		// comment on why that ambiguity must never happen).
		closeRec := rec
		closeRec.Phase = SessionPhaseClose
		closeRec.OccurredAt = p.now()
		closeRec.CloseReason = CloseReasonProxyShutdown
		p.record(closeRec)
	}
}

func (p *Plugin) pipeErrorCallback(conn libplugin.ConnMetadata, pipeErr error) {
	rec := p.buildRecord(conn, SessionPhaseClose)
	rec.CloseReason = classifyCloseReason(pipeErr, conn.RemoteAddr())

	p.mu.Lock()
	delete(p.open, rec.SessionID)
	p.mu.Unlock()

	p.record(rec)
}

// Shutdown emits a CloseReasonProxyShutdown record for every session that
// was opened but never closed — call it once, right before the plugin
// process exits (e.g. because sshpiperd itself is stopping and closed
// this plugin's stdio). Without this, a session killed by a proxy
// restart would leave only an "open" record in the sink, which on its
// own is indistinguishable from a session still legitimately running —
// see containarium#1980 acceptance criterion 5.
//
// Shutdown is the authoritative terminal state: once it has run, it sets
// p.shutdown under the same lock it uses to snapshot p.open, so a session
// whose pipeStartCallback is concurrently in flight either (a) is already
// in the snapshot Shutdown iterates below, or (b) observes p.shutdown
// already set and closes itself out immediately in pipeStartCallback —
// never (c) a third case where it's registered into a map Shutdown has
// already stopped looking at (containarium#1980 PR review finding 1).
// Safe to call more than once: later calls are no-ops.
func (p *Plugin) Shutdown() {
	p.mu.Lock()
	if p.shutdown {
		p.mu.Unlock()
		return
	}
	p.shutdown = true
	remaining := p.open
	p.open = nil
	p.mu.Unlock()

	for _, openRec := range remaining {
		closeRec := openRec
		closeRec.Phase = SessionPhaseClose
		closeRec.OccurredAt = p.now()
		closeRec.CloseReason = CloseReasonProxyShutdown
		p.record(closeRec)
	}
}

func (p *Plugin) record(rec Record) {
	if p.Recorder == nil {
		return
	}
	// Best-effort: a failure to persist a record must never break the
	// SSH pipe it is trying to observe.
	_ = p.Recorder.Record(rec)
}

func (p *Plugin) buildRecord(conn libplugin.ConnMetadata, phase SessionPhase) Record {
	login := conn.User()
	ip, port := hostport.Split(conn.RemoteAddr(), 0)

	rec := Record{
		SessionID:  conn.UniqueID(),
		Phase:      phase,
		OccurredAt: p.now(),
		ClientIP:   ip,
		ClientPort: port,
		Login:      login,
		AuthMethod: AuthMethod(conn.GetMeta(metaAuthMethod)),
		Credential: Credential{
			KeyID:          conn.GetMeta(metaKeyID),
			CAFingerprint:  conn.GetMeta(metaCAFingerprint),
			KeyFingerprint: conn.GetMeta(metaKeyFingerprint),
		},
	}

	if s := conn.GetMeta(metaSerial); s != "" {
		if v, err := strconv.ParseUint(s, 10, 64); err == nil {
			rec.Serial = v
		}
	}

	if p.Target != nil {
		rec.Target = p.Target.Resolve(login)
	}

	return rec
}

// classifyCloseReason turns the error WaitWithHook returned (surfaced to
// the plugin as PipeErrorCallback's err, unconditionally — see sshpiperd's
// own daemon.go) into one of our typed CloseReasons.
//
// WaitWithHook pipes both directions (upstream->downstream and
// downstream->upstream) into the SAME error channel and returns whichever
// side's read/write fails first, with no label saying which side that
// was (see the vendored tg123/sshpiper/libplugin's PipeErrorCallback
// signature: just a bare `error`). A plain io.EOF or a bare "connection
// reset"/"broken pipe" string is exactly what an ordinary client closing
// its own socket after running a command looks like from here — treating
// that as CloseReasonUpstreamGone would flood any "close_reason ==
// upstream_gone" alert with routine session ends (containarium#1980 PR
// review finding 4).
//
// The one piece of side information that DOES survive is a *net.OpError's
// Addr: Go's net package stamps the remote address of the specific TCP
// socket whose read/write failed, and that's either the session's own
// downstream client address (known — it's downstreamAddr, straight off
// conn.RemoteAddr()) or, by elimination, the upstream/backend's. Only that
// positively-attributed, non-downstream case is classified as
// CloseReasonUpstreamGone; every other close reason string is still
// matched, but never defaults to "upstream" on ambiguous evidence alone.
func classifyCloseReason(err error, downstreamAddr string) CloseReason {
	if err == nil {
		return CloseReasonNormal
	}

	msg := err.Error()
	if strings.Contains(msg, "disconnected by user") {
		return CloseReasonNormal
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Addr != nil {
		if sameHost(opErr.Addr.String(), downstreamAddr) {
			return CloseReasonNormal
		}
		return CloseReasonUpstreamGone
	}

	switch {
	case strings.Contains(msg, "EOF"),
		strings.Contains(msg, "connection reset"),
		strings.Contains(msg, "broken pipe"),
		strings.Contains(msg, "connection lost"):
		// Ambiguous: no address to attribute this to either side, and a
		// normal client-side disconnect commonly presents exactly this
		// way. Do not misattribute it to the backend.
		return CloseReasonNormal
	default:
		return CloseReasonError
	}
}

// sameHost reports whether two "host:port" (or bare host) strings name the
// same host, ignoring the port — used to compare a *net.OpError's Addr
// against the session's known downstream client address without being
// tripped up by incidental formatting differences.
func sameHost(a, b string) bool {
	if a == b {
		return true
	}
	ha, _ := hostport.Split(a, 0)
	hb, _ := hostport.Split(b, 0)
	return ha != "" && ha == hb
}
