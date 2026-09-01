package cmd

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRunSecuritySentryStatus_RequiresServer(t *testing.T) {
	oldServer := serverAddr
	serverAddr = ""
	defer func() { serverAddr = oldServer }()

	if err := runSecuritySentryStatus(testCmd(), nil); err == nil {
		t.Fatal("expected an error when --server is unset")
	}
}

// The #1640 CLI test-strategy row: flag→request mapping — status hits the
// exact GetSentryStatus REST path, and the response renders the rule table.
func TestRunSecuritySentryStatus_HitsExpectedPathAndRendersOutput(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"state": "SENTRY_STATE_OK",
			"reason": "",
			"rules": [
				{"rule": "THREAT_RULE_ID_BAD_DESTINATION", "healthy": true},
				{"rule": "THREAT_RULE_ID_DENY_BURST", "healthy": false, "lastError": "panic: boom"}
			]
		}`))
	}))
	defer srv.Close()

	oldServer := serverAddr
	serverAddr = srv.URL
	defer func() { serverAddr = oldServer }()

	cmd := testCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	if err := runSecuritySentryStatus(cmd, nil); err != nil {
		t.Fatalf("runSecuritySentryStatus: %v", err)
	}
	if gotPath != "/v1/security/sentry/status" {
		t.Fatalf("request path = %q, want /v1/security/sentry/status", gotPath)
	}

	out := buf.String()
	for _, want := range []string{"Sentry: OK", "BAD_DESTINATION", "DENY_BURST", "panic: boom"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

// --json routes through the shared printJSON helper (writes to os.Stdout,
// like every other read command's --json flag) rather than cmd.OutOrStdout —
// this only proves the flag takes that code path without erroring; content
// capture belongs to printJSON's own coverage, not duplicated per-command.
func TestRunSecuritySentryStatus_JSONFlag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"state": "SENTRY_STATE_DISABLED", "reason": "CONTAINARIUM_THREAT_SENTRY is not set", "rules": []}`))
	}))
	defer srv.Close()

	oldServer, oldJSON := serverAddr, sentryStatusJSONOut
	serverAddr = srv.URL
	sentryStatusJSONOut = true
	defer func() { serverAddr = oldServer; sentryStatusJSONOut = oldJSON }()

	if err := runSecuritySentryStatus(testCmd(), nil); err != nil {
		t.Fatalf("runSecuritySentryStatus: %v", err)
	}
}
