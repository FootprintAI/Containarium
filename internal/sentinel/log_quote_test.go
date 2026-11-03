package sentinel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// #3456: a tunnelled backend's spot ID comes from its handshake, and the
// sentinel's backend ID for it is "tunnel-" + that spot ID. Both are logged
// with %q, so a newline cannot start a forged log line and an ESC byte cannot
// reach the operator's terminal.

// logQuoteHostile carries a newline followed by a forged log prefix, and an
// ANSI clear-screen sequence.
const logQuoteHostile = "evil\n[forged] admin login ok\x1b[2J"

// logQuoteEscaped is how logQuoteHostile reads once %q has escaped it.
const logQuoteEscaped = `evil\n[forged] admin login ok\x1b[2J`

// captureSyncLog points the standard logger at a syncBuffer for the test.
func captureSyncLog(t *testing.T) *syncBuffer {
	t.Helper()
	var buf syncBuffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

// assertLogQuoted fails unless the hostile value was logged, and logged only
// in escaped form: no raw control byte, no line that starts with the forged
// prefix.
func assertLogQuoted(t *testing.T, out string) {
	t.Helper()
	if strings.ContainsAny(out, "\x1b\r") {
		t.Fatalf("raw control byte in log output: %q", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "[forged]") {
			t.Fatalf("hostile value forged a log line: %q", out)
		}
	}
	if !strings.Contains(out, logQuoteEscaped) {
		t.Fatalf("hostile value not logged in escaped form; got %q", out)
	}
}

func TestLogQuote_TunnelProxyListenerNamesSpot(t *testing.T) {
	stubLoopbackAliases(t)
	registry := NewTunnelRegistry()
	ts := NewTunnelServer("127.0.0.1:0", NewTokenPolicy(), registry, 0)
	closeProxiesOnCleanup(t, ts)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	session, closeSession := newSessionPair(t)
	defer closeSession()

	buf := captureSyncLog(t)
	ts.startProxies(ctx, logQuoteHostile, 1, "127.0.0.1", 0, []int{freeLoopbackPort(t)}, session)
	requireListeners(t, ts, logQuoteHostile)
	assertLogQuoted(t, buf.String())
}

func TestLogQuote_FailoverNamesTunnelBackend(t *testing.T) {
	r := newFailbackRig(t, 4)
	r.peer.ID = "tunnel-" + logQuoteHostile

	buf := captureSyncLog(t)
	r.set("10.0.0.1", false)
	r.tick(2)
	require.Equal(t, r.peer.ID, r.primaryID(), "the unhealthy primary fails over to the tunnel backend")
	r.set("10.0.0.1", true)
	r.tick(6)
	require.Equal(t, "gcp", r.primaryID(), "and fails back once the preferred primary is healthy again")
	assertLogQuoted(t, buf.String())
}

// A registering primary supplies its own pool, hostname, base domains and IP
// in the request body; the handler only checks that they are non-empty.
func TestLogQuote_PrimaryRegistrationFields(t *testing.T) {
	for _, field := range []string{"pool", "hostname", "ip"} {
		t.Run(field, func(t *testing.T) {
			body := map[string]any{"pool": "prod", "hostname": "app.example.com", "ip": "10.0.0.1", "port": 443}
			body[field] = logQuoteHostile
			raw, err := json.Marshal(body)
			require.NoError(t, err)
			m := &Manager{primaries: NewPrimaryRegistry()}
			buf := captureSyncLog(t)
			rec := httptest.NewRecorder()
			m.PrimariesHandler()(rec, httptest.NewRequest(http.MethodPost, "/sentinel/primaries", bytes.NewReader(raw)))
			require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
			assertLogQuoted(t, buf.String())
			// #3476: the port is its own key=value, not glued to the quoted IP.
			require.Regexp(t, `ip="[^"\n]*" port=443`, buf.String())
		})
	}
}

// #3476: a tunnelled backend's ID is "tunnel-" + a self-reported spot ID.
func TestLogQuote_BackendStatusLine(t *testing.T) {
	p := &fakeRecoveryProvider{status: StatusProvisioning}
	m, b := newMaintenanceManager(t, p, Config{})
	b.ID = "tunnel-" + logQuoteHostile
	buf := captureSyncLog(t)
	m.diagnoseAndRecover(context.Background(), b)
	// Only the status line is asserted: the "is provisioning..." line that
	// follows it still prints the ID raw and is not part of #3476.
	require.Contains(t, buf.String(), `[sentinel] backend "tunnel-`+logQuoteEscaped+`" status: provisioning`)
}

// #3476: the alert webhook line carries the backend ID.
func TestLogQuote_AlertWebhookBackend(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	buf := captureSyncLog(t)
	postAlertPayload(srv.URL, alertPayload{Event: "preempted", Backend: "tunnel-" + logQuoteHostile})
	require.Eventually(t, func() bool { return strings.Contains(buf.String(), "delivered") },
		5*time.Second, 10*time.Millisecond, "webhook delivery line never logged")
	assertLogQuoted(t, buf.String())
}

// #3476: probe error text embeds what the primary registered (and what the
// dial returns); the UNREACHABLE line must quote it.
func TestLogQuote_PrimaryUnreachableError(t *testing.T) {
	m := &Manager{primaries: NewPrimaryRegistry()}
	m.reachabilityDial = func(string, int) (net.Conn, error) {
		return nil, errors.New(logQuoteHostile)
	}
	m.primaries.Register(Primary{
		Pool: "prod", Hostname: "prod.example.com", IP: "127.0.0.2", Port: 443,
		BackendID: "tunnel-spot-1",
	})
	buf := captureSyncLog(t)
	m.checkTunnelPrimaries(context.Background())
	require.Contains(t, buf.String(), "UNREACHABLE")
	assertLogQuoted(t, buf.String())
}
