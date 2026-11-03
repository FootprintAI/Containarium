package zap

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// #3456: scan target URLs are built from tenant route domains. They are
// logged with %q, so a newline cannot start a forged log line and an ESC byte
// cannot reach the operator's terminal.

// logQuoteHostile carries a newline followed by a forged log prefix, and an
// ANSI clear-screen sequence.
const logQuoteHostile = "evil\n[forged] admin login ok\x1b[2J"

// logQuoteEscaped is how logQuoteHostile reads once %q has escaped it.
const logQuoteEscaped = `evil\n[forged] admin login ok\x1b[2J`

// captureStdLog points the standard logger at a buffer for the test. Tests
// using it must not run in parallel.
func captureStdLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	})
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

func TestLogQuote_ScanURLTarget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "zap unavailable", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	buf := captureStdLog(t)
	s := NewScanner()
	s.apiBase = srv.URL
	if _, err := s.ScanURL(context.Background(), "https://"+logQuoteHostile+".example.com/"); err == nil {
		t.Fatal("want an error from a failing ZAP API")
	}
	assertLogQuoted(t, buf.String())
}
