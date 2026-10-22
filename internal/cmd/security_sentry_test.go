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
			"cpuSampler": "standalone (30s)",
			"execTelemetry": "ok",
			"execEventsLost": "8729",
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
	for _, want := range []string{"Sentry: OK", "cpu-sampler: standalone (30s)", "exec-telemetry: ok", "exec-events-lost: 8729", "BAD_DESTINATION", "DENY_BURST", "panic: boom"} {
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

// exec-telemetry (#2637): an unavailable watcher prints its reason; a zero
// lost count is not printed (noise); a status from an older daemon without
// the field prints no exec line at all.
func TestPrintSentryStatus_ExecTelemetry(t *testing.T) {
	tests := []struct {
		name    string
		env     sentryStatusEnvelope
		want    []string
		notWant []string
	}{
		{name: "unavailable with reason", env: sentryStatusEnvelope{State: "SENTRY_STATE_OK", ExecTelemetry: "unavailable (netbpf: execwatch: load collection: BTF not found)"},
			want: []string{"exec-telemetry: unavailable (netbpf: execwatch: load collection: BTF not found)"}, notWant: []string{"exec-events-lost"}},
		{name: "ok with zero lost", env: sentryStatusEnvelope{State: "SENTRY_STATE_OK", ExecTelemetry: "ok", ExecEventsLost: "0"},
			want: []string{"exec-telemetry: ok"}, notWant: []string{"exec-events-lost"}},
		{name: "ok with losses", env: sentryStatusEnvelope{State: "SENTRY_STATE_OK", ExecTelemetry: "ok", ExecEventsLost: "12"},
			want: []string{"exec-telemetry: ok", "exec-events-lost: 12"}},
		{name: "older daemon without the field", env: sentryStatusEnvelope{State: "SENTRY_STATE_OK"}, notWant: []string{"exec-telemetry", "exec-hashes-dropped"}},
		{name: "hash drops (#2768)", env: sentryStatusEnvelope{State: "SENTRY_STATE_OK", ExecTelemetry: "ok", ExecHashesDropped: "37"},
			want: []string{"exec-hashes-dropped: 37"}},
		{name: "zero hash drops", env: sentryStatusEnvelope{State: "SENTRY_STATE_OK", ExecTelemetry: "ok", ExecHashesDropped: "0"},
			notWant: []string{"exec-hashes-dropped"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			printSentryStatus(&buf, tc.env)
			for _, w := range tc.want {
				if !strings.Contains(buf.String(), w) {
					t.Errorf("missing %q in:\n%s", w, buf.String())
				}
			}
			for _, nw := range tc.notWant {
				if strings.Contains(buf.String(), nw) {
					t.Errorf("unexpected %q in:\n%s", nw, buf.String())
				}
			}
		})
	}
}
