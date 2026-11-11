package client

import (
	"bytes"
	"strings"
	"testing"
)

// captureWarn redirects the plaintext-fallback warning sink for one test.
func captureWarn(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := plaintextWarnWriter
	plaintextWarnWriter = &buf
	t.Cleanup(func() { plaintextWarnWriter = prev })
	return &buf
}

func TestNewHTTPClient_SchemelessNonLoopbackWarns(t *testing.T) {
	t.Setenv(EnvAllowPlaintextFallback, "")
	buf := captureWarn(t)

	c, err := NewHTTPClient("203.0.113.7:8080", "tok")
	if err != nil {
		t.Fatal(err)
	}
	// Default is unchanged: still falls back to http://.
	if c.baseURL != "http://203.0.113.7:8080" {
		t.Errorf("baseURL = %q, want http fallback preserved", c.baseURL)
	}
	out := buf.String()
	if !strings.Contains(out, "plaintext") || !strings.Contains(out, EnvAllowPlaintextFallback) {
		t.Errorf("expected plaintext warning naming the opt-in, got %q", out)
	}
}

func TestNewHTTPClient_SchemelessNonLoopbackOptInSilent(t *testing.T) {
	t.Setenv(EnvAllowPlaintextFallback, "1")
	buf := captureWarn(t)

	if _, err := NewHTTPClient("203.0.113.7:8080", "tok"); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Errorf("opt-in must silence the warning, got %q", buf.String())
	}
}

func TestNewHTTPClient_NoWarning(t *testing.T) {
	t.Setenv(EnvAllowPlaintextFallback, "")
	for _, ep := range []string{
		"localhost:8080",
		"127.0.0.1:8080",
		"[::1]:8080",
		"https://example.com",
		"http://203.0.113.7:8080", // explicit http is the operator's stated choice
	} {
		buf := captureWarn(t)
		if _, err := NewHTTPClient(ep, "tok"); err != nil {
			t.Fatal(err)
		}
		if buf.Len() != 0 {
			t.Errorf("endpoint %q: unexpected warning %q", ep, buf.String())
		}
	}
}
