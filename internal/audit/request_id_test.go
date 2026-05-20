package audit

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
)

// Phase 4.6 — request correlation IDs.

func TestExtractOrGenerateRequestID_HonorsInbound(t *testing.T) {
	r := httptest.NewRequest("GET", "/v1/x", nil)
	r.Header.Set(RequestIDHeader, "trace-12345-abcdef")
	if got := extractOrGenerateRequestID(r); got != "trace-12345-abcdef" {
		t.Fatalf("got %q, want trace-12345-abcdef", got)
	}
}

func TestExtractOrGenerateRequestID_RejectsMalformedInbound(t *testing.T) {
	cases := []string{
		"has spaces",
		"has;semicolons",
		"\nnewline",
		strings.Repeat("a", 129), // over 128 chars
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/v1/x", nil)
			r.Header.Set(RequestIDHeader, in)
			got := extractOrGenerateRequestID(r)
			if got == in {
				t.Fatalf("malformed inbound %q should have been replaced", in)
			}
			// Replacement should be a fresh hex string.
			if len(got) != 32 {
				t.Fatalf("generated ID = %q (len %d), want 32-char hex", got, len(got))
			}
		})
	}
}

func TestExtractOrGenerateRequestID_GeneratesWhenAbsent(t *testing.T) {
	r := httptest.NewRequest("GET", "/v1/x", nil)
	got := extractOrGenerateRequestID(r)
	if len(got) != 32 {
		t.Fatalf("generated ID = %q (len %d), want 32-char hex", got, len(got))
	}
	// Make sure two calls produce different IDs.
	r2 := httptest.NewRequest("GET", "/v1/x", nil)
	if extractOrGenerateRequestID(r2) == got {
		t.Fatal("two generated IDs collided — randomness broken")
	}
}

func TestContextWithRequestID_Roundtrip(t *testing.T) {
	ctx := ContextWithRequestID(context.Background(), "abc-123")
	if got := RequestIDFromContext(ctx); got != "abc-123" {
		t.Fatalf("got %q, want abc-123", got)
	}
}

func TestRequestIDFromContext_EmptyOnUnset(t *testing.T) {
	if got := RequestIDFromContext(context.Background()); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}

func TestValidRequestID_Boundaries(t *testing.T) {
	ok := []string{
		"a",
		"trace-abc-123",
		"trace_abc_123",
		"AbCdEf0123456789",
		strings.Repeat("a", 128),
	}
	for _, s := range ok {
		if !validRequestID(s) {
			t.Errorf("%q should be valid", s)
		}
	}
	bad := []string{
		"",
		"has space",
		"has\ttab",
		"has.dot",
		"has/slash",
		strings.Repeat("a", 129),
	}
	for _, s := range bad {
		if validRequestID(s) {
			t.Errorf("%q should be invalid", s)
		}
	}
}
