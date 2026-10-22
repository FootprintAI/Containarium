package cmd

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func serveBridgeDNS(t *testing.T, body string) (url string, gotPath *string) {
	t.Helper()
	var p string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &p
}

func withServer(t *testing.T, url string) {
	t.Helper()
	old := serverAddr
	serverAddr = url
	t.Cleanup(func() { serverAddr = old })
}

func TestRunBridgeDNSStatus_RequiresServer(t *testing.T) {
	withServer(t, "")
	err := runBridgeDNSStatus(testCmd(), nil)
	// The specific error, not just any error: an empty URL would fail the HTTP
	// request anyway, with a message that does not tell the operator what to set.
	if err == nil || !strings.Contains(err.Error(), "--server is required") {
		t.Fatalf("err = %v; want the --server is required error", err)
	}
}

// Flag→request mapping: status hits the exact GetBridgeDNSStatus REST path, and
// a degraded response shows the operator what is wrong and both records.
func TestRunBridgeDNSStatus_DegradedShowsWhyAndBothRecords(t *testing.T) {
	url, gotPath := serveBridgeDNS(t, `{
		"state": "BRIDGE_DNS_STATE_DEGRADED",
		"reason": "bridgedns: write incusbr0.raw.dnsmasq: permission denied",
		"bridge": "incusbr0",
		"caddyIp": "10.0.3.5",
		"desired": "address=/example.com/10.0.3.5\nserver=/ssh.example.com/#",
		"current": "address=/example.com/10.0.3.9",
		"lastError": "bridgedns: write incusbr0.raw.dnsmasq: permission denied",
		"driftCount": 3,
		"lastPass": "2026-09-30T12:00:00Z",
		"lastApplied": "2026-09-30T11:00:00Z"
	}`)
	withServer(t, url)
	cmd := testCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	if err := runBridgeDNSStatus(cmd, nil); err != nil {
		t.Fatalf("runBridgeDNSStatus: %v", err)
	}
	if *gotPath != "/v1/system/bridge-dns" {
		t.Fatalf("request path = %q, want /v1/system/bridge-dns", *gotPath)
	}
	out := buf.String()
	for _, want := range []string{
		"Bridge DNS: DEGRADED", "Reason:", "permission denied", "Bridge:", "incusbr0", "core-caddy: 10.0.3.5",
		"Current:", "address=/example.com/10.0.3.9", "Desired:", "address=/example.com/10.0.3.5", "server=/ssh.example.com/#",
		"Drift passes: 3", "Last pass:", "2026-09-30T12:00:00Z", "Last applied:", "2026-09-30T11:00:00Z",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

// In sync there is one record to show and nothing to explain.
func TestRunBridgeDNSStatus_InSyncShowsOneRecordAndNoReason(t *testing.T) {
	url, _ := serveBridgeDNS(t, `{
		"state": "BRIDGE_DNS_STATE_IN_SYNC", "bridge": "incusbr0", "caddyIp": "10.0.3.5",
		"desired": "address=/example.com/10.0.3.5", "current": "address=/example.com/10.0.3.5",
		"driftCount": 0, "lastPass": "2026-09-30T12:00:00Z"
	}`)
	withServer(t, url)
	cmd := testCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	if err := runBridgeDNSStatus(cmd, nil); err != nil {
		t.Fatalf("runBridgeDNSStatus: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"Bridge DNS: IN_SYNC", "Record:", "address=/example.com/10.0.3.5", "core-caddy: 10.0.3.5"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	for _, unwanted := range []string{"Reason:", "Desired:", "Current:", "Last error:", "Last applied:"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("in-sync output should not contain %q:\n%s", unwanted, out)
		}
	}
}

func TestRunBridgeDNSStatus_NotManagedExplainsAndShowsNoRecord(t *testing.T) {
	url, _ := serveBridgeDNS(t, `{"state": "BRIDGE_DNS_STATE_NOT_MANAGED", "reason": "this daemon does not manage core-caddy"}`)
	withServer(t, url)
	cmd := testCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	if err := runBridgeDNSStatus(cmd, nil); err != nil {
		t.Fatalf("runBridgeDNSStatus: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Bridge DNS: NOT_MANAGED") || !strings.Contains(out, "this daemon does not manage core-caddy") {
		t.Errorf("output should name the state and reason:\n%s", out)
	}
	for _, unwanted := range []string{"Record:", "Desired:", "Current:", "core-caddy:"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("not-managed output should not contain %q:\n%s", unwanted, out)
		}
	}
}

func TestPrintBridgeDNSStatus_UnspecifiedState(t *testing.T) {
	var buf bytes.Buffer
	printBridgeDNSStatus(&buf, bridgeDNSStatusEnvelope{})
	if !strings.Contains(buf.String(), "Bridge DNS: UNSPECIFIED") {
		t.Errorf("empty state should render UNSPECIFIED:\n%s", buf.String())
	}
}

// --json goes through the shared printJSON helper (stdout); this only proves
// the flag takes that path without error, like the sentry status test.
func TestRunBridgeDNSStatus_JSONFlag(t *testing.T) {
	url, _ := serveBridgeDNS(t, `{"state": "BRIDGE_DNS_STATE_IN_SYNC"}`)
	withServer(t, url)
	old := bridgeDNSStatusJSONOut
	bridgeDNSStatusJSONOut = true
	t.Cleanup(func() { bridgeDNSStatusJSONOut = old })

	if err := runBridgeDNSStatus(testCmd(), nil); err != nil {
		t.Fatalf("runBridgeDNSStatus: %v", err)
	}
}

// #2232: an absent record shows its own state and the opt-in hint; a
// created record says who created it and how to carve names out.
func TestRunBridgeDNSStatus_AbsentAndCreated(t *testing.T) {
	url, _ := serveBridgeDNS(t, `{"state": "BRIDGE_DNS_STATE_ABSENT", "reason": "the bridge has no record and this daemon will not create one; start with --bridge-dns-create to opt in (#2232)", "bridge": "incusbr0", "caddyIp": "10.0.3.5", "desired": "address=/example.com/10.0.3.5", "current": ""}`)
	withServer(t, url)
	cmd := testCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	if err := runBridgeDNSStatus(cmd, nil); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, w := range []string{"Bridge DNS: ABSENT", "--bridge-dns-create", "(unset)", "address=/example.com/10.0.3.5"} {
		if !strings.Contains(out, w) {
			t.Errorf("absent output missing %q:\n%s", w, out)
		}
	}

	url2, _ := serveBridgeDNS(t, `{"state": "BRIDGE_DNS_STATE_IN_SYNC", "bridge": "incusbr0", "caddyIp": "10.0.3.5", "current": "address=/example.com/10.0.3.5", "desired": "address=/example.com/10.0.3.5", "lastApplied": "2026-10-02T07:00:00Z", "lastAction": "created", "createdAt": "2026-10-02T07:00:00Z"}`)
	withServer(t, url2)
	cmd = testCmd()
	buf.Reset()
	cmd.SetOut(&buf)
	if err := runBridgeDNSStatus(cmd, nil); err != nil {
		t.Fatal(err)
	}
	out = buf.String()
	for _, w := range []string{"Last action:  created", "Created by this daemon at 2026-10-02T07:00:00Z", "--dns-passthrough-host"} {
		if !strings.Contains(out, w) {
			t.Errorf("created output missing %q:\n%s", w, out)
		}
	}
}
