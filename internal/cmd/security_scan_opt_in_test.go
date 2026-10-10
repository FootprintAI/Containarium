package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestScanOptIn_RequiresServer(t *testing.T) {
	old := serverAddr
	serverAddr = ""
	defer func() { serverAddr = old }()
	if err := runScanOptInSet(testCmd(), "alice-container", true); err == nil {
		t.Fatal("set: expected an error when --server is unset")
	}
	if err := runScanOptInList(testCmd(), nil); err == nil {
		t.Fatal("list: expected an error when --server is unset")
	}
}

func TestScanOptInSet_SendsTypedPutAndReportsDecision(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody scanOptInSetBody
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.EscapedPath()
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		w.Write([]byte(`{"optIn":{"containerName":"alice-container","scanner":"PENTEST_SCANNER_OPENVAS","updatedBy":"alice"}}`))
	}))
	defer srv.Close()
	oldServer, oldReason := serverAddr, scanOptInReason
	serverAddr, scanOptInReason = srv.URL, "owner consent"
	defer func() { serverAddr, scanOptInReason = oldServer, oldReason }()

	cmd := testCmd()
	var out strings.Builder
	cmd.SetOut(&out)
	if err := runScanOptInSet(cmd, "alice-container", false); err != nil {
		t.Fatal(err)
	}
	if gotMethod != "PUT" || gotPath != "/v1/pentest/scan-opt-ins/alice-container" {
		t.Fatalf("got %s %s", gotMethod, gotPath)
	}
	if gotBody.Scanner != pentestScannerOpenVAS || gotBody.OptedIn || gotBody.Reason != "owner consent" {
		t.Fatalf("body = %+v", gotBody)
	}
	if !strings.Contains(out.String(), "refused") {
		t.Fatalf("output %q should report the refusal", out.String())
	}
}

func TestScanOptInList_RendersRows(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Write([]byte(`{"optIns":[{"containerName":"alice-container","scanner":"PENTEST_SCANNER_OPENVAS","optedIn":true,"updatedBy":"alice","reason":"ok"},
			{"containerName":"bob-container","scanner":"PENTEST_SCANNER_OPENVAS","updatedBy":"bob"}]}`))
	}))
	defer srv.Close()
	old := serverAddr
	serverAddr = srv.URL
	defer func() { serverAddr = old }()

	cmd := testCmd()
	var out strings.Builder
	cmd.SetOut(&out)
	if err := runScanOptInList(cmd, []string{"alice-container"}); err != nil {
		t.Fatal(err)
	}
	if gotQuery != "container_name=alice-container" {
		t.Fatalf("query = %q", gotQuery)
	}
	text := out.String()
	for _, want := range []string{"alice-container", "allowed", "bob-container", "refused", "OPENVAS"} {
		if !strings.Contains(text, want) {
			t.Fatalf("output missing %q:\n%s", want, text)
		}
	}
}
