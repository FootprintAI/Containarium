package sentinel

import (
	"context"
	"log"
	"os"
	"strings"
	"testing"

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
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
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
