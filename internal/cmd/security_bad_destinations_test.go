package cmd

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRunSecurityBadDestinationsList_RequiresServer(t *testing.T) {
	oldServer := serverAddr
	serverAddr = ""
	defer func() { serverAddr = oldServer }()

	if err := runSecurityBadDestinationsList(testCmd(), nil); err == nil {
		t.Fatal("expected an error when --server is unset")
	}
}

func TestRunSecurityBadDestinationsList_HitsExpectedPathAndRendersOutput(t *testing.T) {
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"entries": [
				{"cidr": "198.51.100.7/32", "label": "known miner", "source": "baseline"},
				{"cidr": "192.0.2.55/32", "label": "operator-flagged host", "source": "operator"}
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

	if err := runSecurityBadDestinationsList(cmd, nil); err != nil {
		t.Fatalf("runSecurityBadDestinationsList: %v", err)
	}
	if gotMethod != http.MethodGet || gotPath != "/v1/security/bad-destinations" {
		t.Fatalf("request = %s %s, want GET /v1/security/bad-destinations", gotMethod, gotPath)
	}
	out := buf.String()
	for _, want := range []string{"198.51.100.7/32", "known miner", "baseline", "192.0.2.55/32", "operator"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestRunSecurityBadDestinationsAdd_PostsCidrAndLabel(t *testing.T) {
	var gotPath, gotMethod, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		gotBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"entry": {"cidr": "192.0.2.55/32", "label": "flagged", "source": "operator"}}`))
	}))
	defer srv.Close()

	oldServer := serverAddr
	serverAddr = srv.URL
	defer func() { serverAddr = oldServer }()

	cmd := testCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	if err := runSecurityBadDestinationsAdd(cmd, []string{"192.0.2.55/32", "flagged"}); err != nil {
		t.Fatalf("runSecurityBadDestinationsAdd: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/security/bad-destinations" {
		t.Fatalf("request = %s %s, want POST /v1/security/bad-destinations", gotMethod, gotPath)
	}
	if !strings.Contains(gotBody, "192.0.2.55/32") || !strings.Contains(gotBody, "flagged") {
		t.Errorf("request body = %q, want cidr and label", gotBody)
	}
	if !strings.Contains(buf.String(), "Added") {
		t.Errorf("output = %q, want a confirmation", buf.String())
	}
}

func TestRunSecurityBadDestinationsRemove_DeletesByCIDR(t *testing.T) {
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	oldServer := serverAddr
	serverAddr = srv.URL
	defer func() { serverAddr = oldServer }()

	cmd := testCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	if err := runSecurityBadDestinationsRemove(cmd, []string{"192.0.2.55/32"}); err != nil {
		t.Fatalf("runSecurityBadDestinationsRemove: %v", err)
	}
	if gotMethod != http.MethodDelete || gotPath != "/v1/security/bad-destinations/192.0.2.55/32" {
		t.Fatalf("request = %s %s, want DELETE /v1/security/bad-destinations/192.0.2.55/32", gotMethod, gotPath)
	}
	if !strings.Contains(buf.String(), "Removed") {
		t.Errorf("output = %q, want a confirmation", buf.String())
	}
}
