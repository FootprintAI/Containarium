package cmd

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRunSecurityFindingsList_RequiresServer(t *testing.T) {
	oldServer := serverAddr
	serverAddr = ""
	defer func() { serverAddr = oldServer }()

	if err := runSecurityFindingsList(testCmd(), nil); err == nil {
		t.Fatal("expected an error when --server is unset")
	}
}

func TestRunSecurityFindingsList_HitsExpectedPathAndRendersOutput(t *testing.T) {
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"findings": [
				{"id": "7", "rule": "THREAT_RULE_ID_BAD_DESTINATION", "severity": "THREAT_SEVERITY_HIGH",
				 "tenantId": "alice", "state": "FINDING_STATE_OPEN", "count": "3",
				 "lastSeen": "2026-08-31T10:00:00Z", "subject": "203.0.113.9"}
			]
		}`))
	}))
	defer srv.Close()

	oldServer := serverAddr
	serverAddr = srv.URL
	defer func() { serverAddr = oldServer }()

	oldSeverity, oldTenant, oldSince, oldState, oldLimit := findingsSeverity, findingsTenant, findingsSince, findingsState, findingsLimit
	findingsSeverity, findingsTenant = "", ""
	findingsSince, findingsState = "", ""
	findingsLimit = 0
	defer func() {
		findingsSeverity, findingsTenant, findingsSince, findingsState, findingsLimit = oldSeverity, oldTenant, oldSince, oldState, oldLimit
	}()

	cmd := testCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	if err := runSecurityFindingsList(cmd, nil); err != nil {
		t.Fatalf("runSecurityFindingsList: %v", err)
	}
	if gotMethod != http.MethodGet || gotPath != "/v1/security/findings" {
		t.Fatalf("request = %s %s, want GET /v1/security/findings", gotMethod, gotPath)
	}
	out := buf.String()
	for _, want := range []string{"BAD_DESTINATION", "HIGH", "OPEN", "alice", "203.0.113.9"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestRunSecurityFindingsList_EncodesFilters(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"findings": []}`))
	}))
	defer srv.Close()

	oldServer := serverAddr
	serverAddr = srv.URL
	defer func() { serverAddr = oldServer }()

	oldSeverity, oldTenant, oldSince, oldState, oldLimit := findingsSeverity, findingsTenant, findingsSince, findingsState, findingsLimit
	findingsSeverity = "high"
	findingsTenant = "bob"
	findingsSince = "2026-08-01T00:00:00Z"
	findingsState = "open"
	findingsLimit = 25
	defer func() {
		findingsSeverity, findingsTenant, findingsSince, findingsState, findingsLimit = oldSeverity, oldTenant, oldSince, oldState, oldLimit
	}()

	cmd := testCmd()
	cmd.SetOut(&bytes.Buffer{})
	if err := runSecurityFindingsList(cmd, nil); err != nil {
		t.Fatalf("runSecurityFindingsList: %v", err)
	}

	for _, want := range []string{
		"severity=THREAT_SEVERITY_HIGH",
		"tenant_id=bob",
		"state=FINDING_STATE_OPEN",
		"limit=25",
	} {
		if !strings.Contains(gotQuery, want) {
			t.Errorf("query = %q, want it to contain %q", gotQuery, want)
		}
	}
}

func TestRunSecurityFindingsResolve_PostsToResolvePath(t *testing.T) {
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"finding": {"id": "7", "state": "FINDING_STATE_RESOLVED"}}`))
	}))
	defer srv.Close()

	oldServer := serverAddr
	serverAddr = srv.URL
	defer func() { serverAddr = oldServer }()

	cmd := testCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	if err := runSecurityFindingsResolve(cmd, []string{"7"}); err != nil {
		t.Fatalf("runSecurityFindingsResolve: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/security/findings/7/resolve" {
		t.Fatalf("request = %s %s, want POST /v1/security/findings/7/resolve", gotMethod, gotPath)
	}
	if !strings.Contains(buf.String(), "Resolved") || !strings.Contains(buf.String(), "RESOLVED") {
		t.Errorf("output = %q, want a confirmation naming the resolved state", buf.String())
	}
}

func TestRunSecurityFindingsResolve_RejectsNonNumericID(t *testing.T) {
	oldServer := serverAddr
	serverAddr = "http://example.invalid"
	defer func() { serverAddr = oldServer }()

	if err := runSecurityFindingsResolve(testCmd(), []string{"not-a-number"}); err == nil {
		t.Fatal("expected an error for a non-numeric id")
	}
}
