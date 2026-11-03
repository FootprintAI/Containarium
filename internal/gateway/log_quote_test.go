package gateway

import (
	"bytes"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
)

// #3456: the box name, login user and label keys and values in these log
// lines come from the request. They are logged with %q, so a newline cannot
// start a forged log line and an ESC byte cannot reach the operator's
// terminal.

// logQuoteHostile carries a newline followed by a forged log prefix, and an
// ANSI clear-screen sequence.
const logQuoteHostile = "evil\n[forged] admin login ok\x1b[2J"

// logQuoteEscaped is how logQuoteHostile reads once %q has escaped it.
const logQuoteEscaped = `evil\n[forged] admin login ok\x1b[2J`

// logQuoteHostilePath is logQuoteHostile percent-encoded for a URL path.
const logQuoteHostilePath = "evil%0A%5Bforged%5D%20admin%20login%20ok%1B%5B2J"

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

// labelFailBackend reports every container as present and fails every label
// write, so the label handlers reach their error log lines.
type labelFailBackend struct {
	incus.Backend
}

func (labelFailBackend) GetContainer(name string) (*incus.ContainerInfo, error) {
	return &incus.ContainerInfo{Name: name}, nil
}
func (labelFailBackend) AddLabel(string, string, string) error {
	return errors.New("label write failed")
}
func (labelFailBackend) RemoveLabel(string, string) error { return errors.New("label write failed") }

func TestLogQuote_SetLabelFailure(t *testing.T) {
	h := &LabelHandler{manager: container.NewWithBackend(labelFailBackend{})}
	for _, tc := range []struct {
		name, path, body string
	}{
		{"hostile box", "/v1/containers/" + logQuoteHostilePath + "/labels", `{"labels":{"team":"a"}}`},
		{"hostile key", "/v1/containers/alice/labels", `{"labels":{"evil\n[forged] admin login ok\u001b[2J":"a"}}`},
		{"hostile value", "/v1/containers/alice/labels", `{"labels":{"team":"evil\n[forged] admin login ok\u001b[2J"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := captureStdLog(t)
			rec := httptest.NewRecorder()
			h.HandleSetLabels(rec, httptest.NewRequest(http.MethodPut, tc.path, strings.NewReader(tc.body)))
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500 (body %s)", rec.Code, rec.Body.String())
			}
			assertLogQuoted(t, buf.String())
		})
	}
}

func TestLogQuote_RemoveLabelFailure(t *testing.T) {
	h := &LabelHandler{manager: container.NewWithBackend(labelFailBackend{})}
	for _, tc := range []struct{ name, path string }{
		{"hostile box", "/v1/containers/" + logQuoteHostilePath + "/labels/team"},
		{"hostile key", "/v1/containers/alice/labels/" + logQuoteHostilePath},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := captureStdLog(t)
			rec := httptest.NewRecorder()
			h.HandleRemoveLabel(rec, httptest.NewRequest(http.MethodDelete, tc.path, nil))
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500 (body %s)", rec.Code, rec.Body.String())
			}
			assertLogQuoted(t, buf.String())
		})
	}
}

func TestLogQuote_TerminalRunUserLookupFailure(t *testing.T) {
	boom := errors.New("incus unavailable")
	for _, tc := range []struct {
		name string
		th   *TerminalHandler
	}{
		{"tool-access read fails", &TerminalHandler{
			recordedToolAccess: func(string) (string, error) { return "", boom },
		}},
		{"run user check fails", &TerminalHandler{
			recordedToolAccess: func(string) (string, error) { return "full_sudo", nil },
			runUserExists:      func(string) (bool, error) { return false, boom },
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := captureStdLog(t)
			if _, refusal := tc.th.resolveTerminalUser(logQuoteHostile+"-container", "alice", true); refusal == nil {
				t.Fatal("want a refusal when the lookup fails")
			}
			assertLogQuoted(t, buf.String())
		})
	}
}
