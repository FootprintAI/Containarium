package sshsession

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/tg123/sshpiper/libplugin"
	"golang.org/x/crypto/ssh"
)

// fakeRecorder collects every Record handed to it, in order.
type fakeRecorder struct {
	recs []Record
}

func (f *fakeRecorder) Record(rec Record) error {
	f.recs = append(f.recs, rec)
	return nil
}

// deferredMeta drives a publicKeyCallback result the same way sshpiperd's
// own ChainPlugins.onNextPlugin does: copy the returned NextPluginAuth's
// Meta into the ConnMeta that will be passed to the later PipeStart/
// PipeError calls. See internal/sentinel/sshsession/plugin.go's doc
// comment for why this same map is what makes credential propagation
// from auth-time to pipe-start-time work.
func deferredMeta(t *testing.T, upstream *libplugin.Upstream) map[string]string {
	t.Helper()
	next := upstream.GetNextPlugin()
	if next == nil {
		t.Fatalf("publicKeyCallback did not defer via NextPluginAuth: %+v", upstream)
	}
	return next.Meta
}

func TestPlugin_CertificateSession_OpenAndClose(t *testing.T) {
	// Acceptance criterion 1: an accepted certificate-auth SSH connection
	// emits one open and one close record, correlated by session_id.
	// Acceptance criterion 2: the record names the certificate's key_id
	// AND serial.
	ca := newTestCA(t)
	cert, _ := newTestUserCert(t, ca, "alice", 42)

	rec := &fakeRecorder{}
	p := &Plugin{Recorder: rec}

	conn := &libplugin.ConnMeta{
		UserName: "boxuser",
		FromAddr: "203.0.113.7:52341",
		UniqId:   "session-abc",
		Metadata: map[string]string{},
	}

	upstream, err := p.Config().PublicKeyCallback(conn, cert.Marshal())
	if err != nil {
		t.Fatalf("PublicKeyCallback: %v", err)
	}
	for k, v := range deferredMeta(t, upstream) {
		conn.Metadata[k] = v
	}

	cfg := p.Config()
	cfg.PipeStartCallback(conn)
	cfg.PipeErrorCallback(conn, nil)

	if len(rec.recs) != 2 {
		t.Fatalf("got %d records, want 2 (open + close): %+v", len(rec.recs), rec.recs)
	}

	open, closeRec := rec.recs[0], rec.recs[1]

	if open.Phase != SessionPhaseOpen {
		t.Errorf("first record phase = %q, want open", open.Phase)
	}
	if closeRec.Phase != SessionPhaseClose {
		t.Errorf("second record phase = %q, want close", closeRec.Phase)
	}
	if open.SessionID != "session-abc" || closeRec.SessionID != "session-abc" {
		t.Errorf("session ids not correlated: open=%q close=%q", open.SessionID, closeRec.SessionID)
	}
	if open.SessionID != closeRec.SessionID {
		t.Errorf("open/close session ids differ")
	}

	if open.AuthMethod != AuthMethodCertificate {
		t.Errorf("auth method = %q, want certificate", open.AuthMethod)
	}
	if open.KeyID != "alice" {
		t.Errorf("key id = %q, want alice", open.KeyID)
	}
	if open.Serial != 42 {
		t.Errorf("serial = %d, want 42", open.Serial)
	}
	if open.CAFingerprint == "" {
		t.Error("ca fingerprint should be populated for a certificate session")
	}

	if closeRec.CloseReason != CloseReasonNormal {
		t.Errorf("close reason = %q, want normal (nil pipe error)", closeRec.CloseReason)
	}
}

func TestPlugin_RawPublicKeySession_RecordsFingerprint(t *testing.T) {
	// Acceptance criterion 3: a raw-public-key connection records the key
	// fingerprint.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("build public key: %v", err)
	}

	rec := &fakeRecorder{}
	p := &Plugin{Recorder: rec}
	conn := &libplugin.ConnMeta{
		UserName: "boxuser",
		FromAddr: "203.0.113.8:9000",
		UniqId:   "session-raw",
		Metadata: map[string]string{},
	}

	upstream, err := p.Config().PublicKeyCallback(conn, pub.Marshal())
	if err != nil {
		t.Fatalf("PublicKeyCallback: %v", err)
	}
	for k, v := range deferredMeta(t, upstream) {
		conn.Metadata[k] = v
	}

	p.Config().PipeStartCallback(conn)

	if len(rec.recs) != 1 {
		t.Fatalf("got %d records, want 1", len(rec.recs))
	}
	got := rec.recs[0]
	if got.AuthMethod != AuthMethodPublicKey {
		t.Errorf("auth method = %q, want publickey", got.AuthMethod)
	}
	want := ssh.FingerprintSHA256(pub)
	if got.KeyFingerprint != want {
		t.Errorf("key fingerprint = %q, want %q", got.KeyFingerprint, want)
	}
	if got.KeyID != "" || got.Serial != 0 {
		t.Errorf("raw key record should carry no cert fields, got %+v", got)
	}
}

func TestPlugin_ClientIPIsAlwaysDownstream(t *testing.T) {
	// Acceptance criterion 4: the recorded client_ip is the real
	// downstream address; an upstream/proxy-local address must never
	// appear there. Plugin only ever sees libplugin.ConnMetadata, which
	// sshpiperd populates from the DOWNSTREAM side for PipeStart/
	// PipeError (see plugin.go's doc comment) -- this test pins that
	// whatever RemoteAddr() reports lands verbatim in ClientIP, so a
	// regression that swapped in some other address would be caught.
	const downstreamAddr = "203.0.113.42:4242"
	const upstreamLocalAddr = "127.0.0.1:20022" // must NEVER appear as client_ip

	rec := &fakeRecorder{}
	p := &Plugin{Recorder: rec}
	conn := &libplugin.ConnMeta{
		UserName: "boxuser",
		FromAddr: downstreamAddr,
		UniqId:   "session-ip",
	}

	p.Config().PipeStartCallback(conn)
	p.Config().PipeErrorCallback(conn, nil)

	for _, got := range rec.recs {
		if got.ClientIP != "203.0.113.42" {
			t.Errorf("client_ip = %q, want 203.0.113.42 (the downstream address)", got.ClientIP)
		}
		if got.ClientIP == "127.0.0.1" {
			t.Fatalf("client_ip leaked the upstream-local address %q", upstreamLocalAddr)
		}
		if got.ClientPort != 4242 {
			t.Errorf("client_port = %d, want 4242", got.ClientPort)
		}
	}
}

func TestPlugin_PublicKeyCallback_NeverBlocksOnParseFailure(t *testing.T) {
	// Acceptance criterion 9 (by extension): observing a credential must
	// never turn into a reason to reject or delay authentication that
	// sshpiper's own routing plugin would otherwise have allowed.
	p := &Plugin{}
	conn := &libplugin.ConnMeta{UserName: "boxuser", FromAddr: "203.0.113.1:1", UniqId: "s"}

	upstream, err := p.Config().PublicKeyCallback(conn, []byte("not a key"))
	if err != nil {
		t.Fatalf("PublicKeyCallback returned an error for an unparsable key: %v", err)
	}
	if upstream.GetNextPlugin() == nil {
		t.Fatal("PublicKeyCallback must always defer via NextPluginAuth, even on parse failure")
	}
}

func TestPlugin_PublicKeyCallback_NeverLeaksRawKeyBytes(t *testing.T) {
	// Acceptance criterion 8: no private key, token, or session content
	// in any record -- including the metadata this plugin stashes for
	// itself in-flight, which is exactly the kind of internal state a
	// careless implementation could leak raw bytes through.
	ca := newTestCA(t)
	cert, _ := newTestUserCert(t, ca, "alice", 42)
	raw := cert.Marshal()

	p := &Plugin{}
	conn := &libplugin.ConnMeta{UserName: "boxuser", FromAddr: "203.0.113.1:1", UniqId: "s"}

	upstream, err := p.Config().PublicKeyCallback(conn, raw)
	if err != nil {
		t.Fatalf("PublicKeyCallback: %v", err)
	}

	for k, v := range deferredMeta(t, upstream) {
		if bytes.Contains([]byte(v), raw) {
			t.Fatalf("metadata key %q leaks the raw certificate bytes", k)
		}
	}
}

func TestPlugin_Shutdown_ClosesOutOpenSessionsOnly(t *testing.T) {
	// Acceptance criterion 5: an abnormally-ended session (proxy
	// restarted mid-session) either emits a close with a reason, or is
	// distinguishable from a session still open. Shutdown is what
	// supplies that close when the plugin process itself is stopping.
	rec := &fakeRecorder{}
	fixedNow := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	p := &Plugin{Recorder: rec, Now: func() time.Time { return fixedNow }}

	stillOpen := &libplugin.ConnMeta{UserName: "boxuser", FromAddr: "203.0.113.1:1", UniqId: "open-session"}
	alreadyClosed := &libplugin.ConnMeta{UserName: "boxuser", FromAddr: "203.0.113.2:2", UniqId: "closed-session"}

	cfg := p.Config()
	cfg.PipeStartCallback(stillOpen)
	cfg.PipeStartCallback(alreadyClosed)
	cfg.PipeErrorCallback(alreadyClosed, errors.New("ssh: disconnect, reason 11: disconnected by user"))

	rec.recs = nil // discard the two opens + one normal close above
	p.Shutdown()

	if len(rec.recs) != 1 {
		t.Fatalf("Shutdown emitted %d records, want exactly 1 (only the still-open session): %+v", len(rec.recs), rec.recs)
	}
	got := rec.recs[0]
	if got.SessionID != "open-session" {
		t.Errorf("Shutdown closed out session %q, want open-session", got.SessionID)
	}
	if got.Phase != SessionPhaseClose {
		t.Errorf("phase = %q, want close", got.Phase)
	}
	if got.CloseReason != CloseReasonProxyShutdown {
		t.Errorf("close reason = %q, want proxy_shutdown", got.CloseReason)
	}

	// A second Shutdown call must not re-emit anything already flushed.
	rec.recs = nil
	p.Shutdown()
	if len(rec.recs) != 0 {
		t.Errorf("second Shutdown emitted %d records, want 0", len(rec.recs))
	}
}

func TestClassifyCloseReason(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want CloseReason
	}{
		{"nil", nil, CloseReasonNormal},
		{"disconnected by user", errors.New("ssh: disconnect, reason 11: disconnected by user"), CloseReasonNormal},
		{"EOF", errors.New("EOF"), CloseReasonUpstreamGone},
		{"connection reset", errors.New("read tcp: connection reset by peer"), CloseReasonUpstreamGone},
		{"unrecognized", errors.New("something unexpected"), CloseReasonError},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classifyCloseReason(c.err); got != c.want {
				t.Errorf("classifyCloseReason(%v) = %q, want %q", c.err, got, c.want)
			}
		})
	}
}
