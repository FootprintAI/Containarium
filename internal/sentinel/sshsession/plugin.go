package sshsession

import (
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

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

	mu   sync.Mutex
	open map[string]Record // sessionID -> last emitted open record, for Shutdown
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

	if authMethod, cred, err := ExtractCredential(key); err == nil {
		meta[metaAuthMethod] = string(authMethod)
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
	// A parse failure leaves meta empty — auth still proceeds unchanged
	// (see below), and buildRecord's AuthMethod defaults to "" rather
	// than blocking anything.

	return &libplugin.Upstream{
		Auth: &libplugin.Upstream_NextPlugin{
			NextPlugin: &libplugin.UpstreamNextPluginAuth{Meta: meta},
		},
	}, nil
}

func (p *Plugin) pipeStartCallback(conn libplugin.ConnMetadata) {
	rec := p.buildRecord(conn, SessionPhaseOpen)

	p.mu.Lock()
	if p.open == nil {
		p.open = make(map[string]Record)
	}
	p.open[rec.SessionID] = rec
	p.mu.Unlock()

	p.record(rec)
}

func (p *Plugin) pipeErrorCallback(conn libplugin.ConnMetadata, pipeErr error) {
	rec := p.buildRecord(conn, SessionPhaseClose)
	rec.CloseReason = classifyCloseReason(pipeErr)

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
func (p *Plugin) Shutdown() {
	p.mu.Lock()
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
	ip, port := splitHostPort(conn.RemoteAddr())

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

// splitHostPort separates a "host:port" remote address into its parts.
// Falls back to treating the whole string as the host if it isn't in
// host:port form, rather than dropping the address entirely.
func splitHostPort(addr string) (string, int) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 0
	}
	port, _ := strconv.Atoi(portStr)
	return host, port
}

// classifyCloseReason turns the error WaitWithHook returned (surfaced to
// the plugin as PipeErrorCallback's err, unconditionally — see sshpiperd's
// own daemon.go) into one of our typed CloseReasons. This is inherently
// best-effort string matching over an upstream error message that is not
// a stable contract, but unlike the auth-failure line containarium#1980
// explicitly declines to parse, a close_reason misclassifying "unknown"
// as CloseReasonError rather than CloseReasonNormal is a minor precision
// loss, not a missing fact: the record itself is never lost.
func classifyCloseReason(err error) CloseReason {
	if err == nil {
		return CloseReasonNormal
	}

	msg := err.Error()
	switch {
	case strings.Contains(msg, "disconnected by user"):
		return CloseReasonNormal
	case strings.Contains(msg, "EOF"),
		strings.Contains(msg, "connection reset"),
		strings.Contains(msg, "broken pipe"),
		strings.Contains(msg, "connection lost"):
		return CloseReasonUpstreamGone
	default:
		return CloseReasonError
	}
}
