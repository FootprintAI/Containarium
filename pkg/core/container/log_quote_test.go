package container

import (
	"bytes"
	"errors"
	"log"
	"strings"
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// #3456: box names and usernames reach these log lines from tenant input.
// They are logged with %q, so a newline cannot start a forged log line and an
// ESC byte cannot reach the operator's terminal.

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

// failingExecBackend fails every Exec, so each best-effort step logs.
type failingExecBackend struct {
	incus.Backend
}

func (failingExecBackend) Exec(string, []string) error { return errors.New("exec failed") }

func TestLogQuote_PodmanRestartDurability(t *testing.T) {
	buf := captureStdLog(t)
	m := NewWithBackend(failingExecBackend{})
	m.enablePodmanRestartDurability(logQuoteHostile+"-container", logQuoteHostile)
	if got := strings.Count(buf.String(), "\n"); got != 3 {
		t.Fatalf("want 3 log lines (one per failed step), got %d: %q", got, buf.String())
	}
	assertLogQuoted(t, buf.String())
}

func TestLogQuote_OTelMissingCollector(t *testing.T) {
	buf := captureStdLog(t)
	if env := otelEnvVars(CreateOptions{Monitoring: true}, logQuoteHostile); env != nil {
		t.Fatalf("no collector endpoint: want no env vars, got %v", env)
	}
	assertLogQuoted(t, buf.String())
}
