package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// #3456: route domains and SNI names reach these log lines from tenant
// input. They are logged with %q, so a newline cannot start a forged log line
// and an ESC byte cannot reach the operator's terminal.

// logQuoteHostile carries a newline followed by a forged log prefix, and an
// ANSI clear-screen sequence.
const logQuoteHostile = "evil\n[forged] admin login ok\x1b[2J"

// logQuoteEscaped is how logQuoteHostile reads once %q has escaped it.
const logQuoteEscaped = `evil\n[forged] admin login ok\x1b[2J`

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

// failingCaddy is a Caddy admin API that fails every request.
func failingCaddy(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "caddy unavailable", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestLogQuote_UpdateRouteRemoveFailure(t *testing.T) {
	buf := captureLog(t)
	p := NewProxyManager(failingCaddy(t), "example.com")
	_ = p.UpdateRoute(logQuoteHostile+".example.com", "10.0.3.9", 8080)
	assertLogQuoted(t, buf.String())
}

func TestLogQuote_AddL4RouteRemoveFailure(t *testing.T) {
	buf := captureLog(t)
	m := NewL4ProxyManager(failingCaddy(t))
	_ = m.AddL4Route(logQuoteHostile+".example.com", "10.0.3.9", 8443)
	assertLogQuoted(t, buf.String())
}
