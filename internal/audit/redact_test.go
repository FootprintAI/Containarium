package audit

import (
	"strings"
	"testing"
)

// Phase 4.4 — Redact / SanitizeDetail tests (audit C-MED-5).

func TestRedact_LeavesSafeStringsAlone(t *testing.T) {
	safe := []string{
		"",
		"duration=123ms",
		"action=create container=alice",
		"hello world",
	}
	for _, s := range safe {
		if got := Redact(s); got != s {
			t.Errorf("Redact(%q) changed safe string to %q", s, got)
		}
	}
}

func TestRedact_ScrubsJWT(t *testing.T) {
	// Sample JWT-shaped string with three base64 segments.
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSIsImV4cCI6OTk5OX0.signature_here_longer"
	got := Redact("token=" + jwt)
	if strings.Contains(got, jwt) {
		t.Fatalf("JWT not redacted: %q", got)
	}
	if !strings.Contains(got, "REDACTED-JWT") {
		t.Fatalf("expected redaction marker: %q", got)
	}
}

func TestRedact_ScrubsJWTWithBearerPrefix(t *testing.T) {
	in := "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSIsImV4cCI6OTk5OX0.signature_here"
	got := Redact(in)
	if strings.Contains(got, "eyJhbGciOiJIUzI1NiJ9") {
		t.Fatalf("JWT body leaked: %q", got)
	}
}

func TestRedact_ScrubsPasswordVariants(t *testing.T) {
	cases := []string{
		"password=hunter2",
		"PASSWORD=hunter2",
		"password = hunter2",
		"password: hunter2",
		"passwd=hunter2",
		"pass=hunter2",
		"secret=abcdef",
		"api_key=foo",
		"api-key=foo",
		"access_token=foo",
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			got := Redact(in)
			if strings.Contains(got, "hunter2") || strings.Contains(got, "abcdef") || strings.Contains(got, "foo") {
				t.Fatalf("secret leaked through redaction: %q", got)
			}
		})
	}
}

func TestRedact_ScrubsAWSAccessKey(t *testing.T) {
	in := "aws_access_key_id AKIAIOSFODNN7EXAMPLE"
	got := Redact(in)
	if strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("AWS access key leaked: %q", got)
	}
}

func TestRedact_ScrubsPrivateKey(t *testing.T) {
	in := "log line includes -----BEGIN RSA PRIVATE KEY----- and other content"
	got := Redact(in)
	if strings.Contains(got, "-----BEGIN") {
		t.Fatalf("private key marker leaked: %q", got)
	}
}

func TestHasSensitive_DetectsRedactable(t *testing.T) {
	sensitive := []string{
		"Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.signature_here_longer",
		"password=foo",
		"AKIAIOSFODNN7EXAMPLE",
	}
	for _, s := range sensitive {
		if !HasSensitive(s) {
			t.Errorf("HasSensitive failed to flag %q", s)
		}
	}
}

func TestSanitizeDetail_TruncatesOversized(t *testing.T) {
	in := strings.Repeat("x", MaxDetailLength+1000)
	out := SanitizeDetail(in)
	if len(out) > MaxDetailLength+len(" [truncated]") {
		t.Fatalf("output not truncated: len=%d", len(out))
	}
	if !strings.HasSuffix(out, "[truncated]") {
		t.Fatalf("expected truncation marker: %q", out[len(out)-50:])
	}
}

func TestSanitizeDetail_TrimsWhitespace(t *testing.T) {
	got := SanitizeDetail("  duration=5s  ")
	if got != "duration=5s" {
		t.Fatalf("got %q, want trimmed", got)
	}
}
