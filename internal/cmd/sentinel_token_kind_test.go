//go:build !windows && !containarium_client

package cmd

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/sentinel"
	"github.com/spf13/cobra"
)

// #2415 — `sentinel register-token|deregister-token --kind audit-ingest`.

const kindTestSecret = "cli-kind-admin-secret-32-bytes-long!!"

func resetKindFlags() {
	sentinelRegisterTokenSentinelURL, sentinelRegisterTokenToken = "", ""
	sentinelRegisterTokenPools, sentinelRegisterTokenSecret = nil, ""
	sentinelRegisterTokenKind, sentinelRegisterTokenBackend = sentinelTokenKindTunnelJoin, ""
	sentinelDeregisterTokenSentinelURL, sentinelDeregisterTokenToken = "", ""
	sentinelDeregisterTokenTokenPrefix, sentinelDeregisterTokenSecret = "", ""
	sentinelDeregisterTokenKind, sentinelDeregisterTokenBackend = sentinelTokenKindTunnelJoin, ""
}

func kindTestCmd() *cobra.Command {
	c := &cobra.Command{}
	c.SetOut(io.Discard)
	c.SetErr(io.Discard)
	c.SetContext(context.Background())
	return c
}

type captured struct {
	method, path string
	body         []byte
}

// capturingSentinel is an HMAC-gated stub that records the request it got.
func capturingSentinel(t *testing.T, got *captured) *httptest.Server {
	t.Helper()
	h := auth.SentinelHMACMiddleware([]byte(kindTestSecret), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.method, got.path = r.Method, r.URL.Path
		got.body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func TestSentinelTokenKind_Set(t *testing.T) {
	var k sentinelTokenKind
	for _, ok := range []string{"tunnel-join", "audit-ingest"} {
		if err := k.Set(ok); err != nil || string(k) != ok {
			t.Fatalf("Set(%q) = %v, kind %q", ok, err, k)
		}
	}
	if err := k.Set("bogus"); err == nil {
		t.Fatal("an unknown kind must fail at flag parse")
	}
	if k.Type() == "" {
		t.Fatal("Type must be non-empty for --help")
	}
}

func TestRegisterToken_DefaultKindIsUnchangedTunnelJoin(t *testing.T) {
	t.Cleanup(resetKindFlags)
	resetKindFlags()
	var got captured
	srv := capturingSentinel(t, &got)
	sentinelRegisterTokenSentinelURL, sentinelRegisterTokenSecret = srv.URL, kindTestSecret
	sentinelRegisterTokenToken = "host.secret"
	sentinelRegisterTokenPools = []string{"lab"}

	if err := runSentinelRegisterToken(kindTestCmd(), nil); err != nil {
		t.Fatal(err)
	}
	if got.method != http.MethodPost || got.path != "/sentinel/tunnel-tokens" {
		t.Fatalf("regression: default kind hit %s %s", got.method, got.path)
	}
	var body sentinel.TunnelTokenRegisterRequest
	if err := json.Unmarshal(got.body, &body); err != nil || body.Token != "host.secret" || len(body.Pools) != 1 || body.Pools[0] != "lab" {
		t.Fatalf("regression: body = %s (%v)", got.body, err)
	}
}

func TestRegisterToken_AuditIngest(t *testing.T) {
	t.Cleanup(resetKindFlags)
	resetKindFlags()
	var got captured
	srv := capturingSentinel(t, &got)
	sentinelRegisterTokenSentinelURL, sentinelRegisterTokenSecret = srv.URL, kindTestSecret
	sentinelRegisterTokenKind = sentinelTokenKindAuditIngest
	sentinelRegisterTokenBackend, sentinelRegisterTokenToken = "backend-a", "jwt.aaa.bbb"

	if err := runSentinelRegisterToken(kindTestCmd(), nil); err != nil {
		t.Fatal(err)
	}
	if got.method != http.MethodPost || got.path != "/sentinel/audit-ingest-tokens" {
		t.Fatalf("hit %s %s", got.method, got.path)
	}
	var body sentinel.AuditIngestTokenRegisterRequest
	if err := json.Unmarshal(got.body, &body); err != nil || body.BackendID != "backend-a" || body.Token != "jwt.aaa.bbb" {
		t.Fatalf("body = %s (%v)", got.body, err)
	}
}

func TestRegisterToken_AuditIngestRequiresBackendAndRejectsPools(t *testing.T) {
	t.Cleanup(resetKindFlags)
	resetKindFlags()
	sentinelRegisterTokenSentinelURL, sentinelRegisterTokenSecret = "http://unused.invalid", kindTestSecret
	sentinelRegisterTokenKind, sentinelRegisterTokenToken = sentinelTokenKindAuditIngest, "t"

	if err := runSentinelRegisterToken(kindTestCmd(), nil); err == nil || !strings.Contains(err.Error(), "--backend") {
		t.Fatalf("missing --backend: err = %v", err)
	}
	sentinelRegisterTokenBackend, sentinelRegisterTokenPools = "b", []string{"lab"}
	if err := runSentinelRegisterToken(kindTestCmd(), nil); err == nil || !strings.Contains(err.Error(), "--pool") {
		t.Fatalf("--pool with audit-ingest must be rejected: err = %v", err)
	}
}

func TestRegisterToken_TunnelJoinRejectsBackend(t *testing.T) {
	t.Cleanup(resetKindFlags)
	resetKindFlags()
	sentinelRegisterTokenSentinelURL, sentinelRegisterTokenSecret = "http://unused.invalid", kindTestSecret
	sentinelRegisterTokenToken, sentinelRegisterTokenBackend = "t", "b"
	if err := runSentinelRegisterToken(kindTestCmd(), nil); err == nil || !strings.Contains(err.Error(), "--backend") {
		t.Fatalf("--backend with tunnel-join must be rejected: err = %v", err)
	}
}

func TestDeregisterToken_AuditIngest(t *testing.T) {
	t.Cleanup(resetKindFlags)
	resetKindFlags()
	var got captured
	srv := capturingSentinel(t, &got)
	sentinelDeregisterTokenSentinelURL, sentinelDeregisterTokenSecret = srv.URL, kindTestSecret
	sentinelDeregisterTokenKind, sentinelDeregisterTokenBackend = sentinelTokenKindAuditIngest, "backend-a"

	if err := runSentinelDeregisterToken(kindTestCmd(), nil); err != nil {
		t.Fatal(err)
	}
	if got.method != http.MethodDelete || got.path != "/sentinel/audit-ingest-tokens" {
		t.Fatalf("hit %s %s", got.method, got.path)
	}
	var body sentinel.AuditIngestTokenDeregisterRequest
	if err := json.Unmarshal(got.body, &body); err != nil || body.BackendID != "backend-a" {
		t.Fatalf("body = %s (%v)", got.body, err)
	}
}

func TestDeregisterToken_AuditIngestRequiresBackend(t *testing.T) {
	t.Cleanup(resetKindFlags)
	resetKindFlags()
	sentinelDeregisterTokenSentinelURL, sentinelDeregisterTokenSecret = "http://unused.invalid", kindTestSecret
	sentinelDeregisterTokenKind = sentinelTokenKindAuditIngest
	if err := runSentinelDeregisterToken(kindTestCmd(), nil); err == nil || !strings.Contains(err.Error(), "--backend") {
		t.Fatalf("err = %v", err)
	}
	sentinelDeregisterTokenBackend, sentinelDeregisterTokenToken = "b", "t"
	if err := runSentinelDeregisterToken(kindTestCmd(), nil); err == nil {
		t.Fatal("--token with audit-ingest must be rejected")
	}
}

// The flag is wired to the typed value, so a typo fails before any request.
func TestKindFlag_BogusValueFailsAtParse(t *testing.T) {
	t.Cleanup(resetKindFlags)
	if err := sentinelRegisterTokenCmd.Flags().Set("kind", "bogus"); err == nil {
		t.Fatal("register-token --kind bogus must fail at parse")
	}
	if err := sentinelDeregisterTokenCmd.Flags().Set("kind", "bogus"); err == nil {
		t.Fatal("deregister-token --kind bogus must fail at parse")
	}
}
