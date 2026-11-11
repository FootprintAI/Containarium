package cloud

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) })
	return &buf
}

func TestWarnIfPlaintextControlPlane_NonLoopbackHTTPWarns(t *testing.T) {
	buf := captureLog(t)
	warnIfPlaintextControlPlane("http://203.0.113.7:8080")
	if out := buf.String(); !strings.Contains(out, "plaintext") || !strings.Contains(out, "https://") {
		t.Errorf("expected plaintext control-plane warning, got %q", out)
	}
}

func TestWarnIfPlaintextControlPlane_NoWarning(t *testing.T) {
	for _, cp := range []string{
		"http://localhost:8080",
		"http://127.0.0.1:8080",
		"http://[::1]:8080",
		"https://cloud.example.com",
		"cloud.example.com:443", // gRPC, not REST
	} {
		buf := captureLog(t)
		warnIfPlaintextControlPlane(cp)
		if buf.Len() != 0 {
			t.Errorf("control plane %q: unexpected warning %q", cp, buf.String())
		}
	}
}
