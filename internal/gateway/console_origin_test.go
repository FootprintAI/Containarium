package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

// The console-attach route must apply the same Origin rule as the terminal
// route (issue #2721): same header-combination table, same refusal body and
// status, same Sec-Websocket-Version header.

func TestConsoleUpgrader_OriginTable(t *testing.T) {
	t.Setenv("CONTAINARIUM_ALLOWED_ORIGINS", "")

	tests := []struct {
		name   string
		req    *http.Request
		wantOK bool
		reason string
	}{
		{"empty origin + subprotocol bearer upgrades", newOriginRequest("", withSubprotocolBearer), true, ""},
		{"empty origin + Authorization bearer upgrades", newOriginRequest("", withAuthorizationBearer), true, ""},
		{"empty origin + no bearer refused", newOriginRequest("", nil), false, originRequired},
		{"empty origin + only ?token= refused", newOriginRequest("", func(r *http.Request) {
			r.URL.RawQuery = "token=header.payload.sig"
		}), false, originRequired},
		{"Origin: null + bearer refused", newOriginRequest("null", withSubprotocolBearer), false, originNotAllowed},
		{"unlisted origin + bearer refused", newOriginRequest("https://evil.example", withSubprotocolBearer), false, originNotAllowed},
		{"unlisted origin, no bearer refused", newOriginRequest("https://evil.example", nil), false, originNotAllowed},
		{"default-allowed origin + bearer upgrades", newOriginRequest("http://localhost:3000", withSubprotocolBearer), true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			up := newConsoleUpgrader()
			if got := up.CheckOrigin(tt.req); got != tt.wantOK {
				t.Fatalf("console CheckOrigin = %v, want %v", got, tt.wantOK)
			}
			// Parity: identical decision to the terminal rule.
			ok, reason := checkTerminalOrigin(tt.req)
			if ok != tt.wantOK || reason != tt.reason {
				t.Fatalf("terminal rule = (%v, %q), want (%v, %q)", ok, reason, tt.wantOK, tt.reason)
			}
		})
	}
}

func TestConsoleUpgrader_ConfiguredOrigins(t *testing.T) {
	t.Setenv("CONTAINARIUM_ALLOWED_ORIGINS", "https://ui.example, https://other.example")
	up := newConsoleUpgrader()
	if !up.CheckOrigin(newOriginRequest("https://ui.example", withSubprotocolBearer)) {
		t.Fatal("listed origin should upgrade")
	}
	if up.CheckOrigin(newOriginRequest("http://localhost:3000", withSubprotocolBearer)) {
		t.Fatal("default origin should be refused once the env var is set")
	}
	if up.CheckOrigin(newOriginRequest("https://evil.example", withSubprotocolBearer)) {
		t.Fatal("unlisted origin should be refused")
	}
}

type refusal struct {
	status  int
	body    string
	version string
}

func upgradeServer(up websocket.Upgrader) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if conn, err := up.Upgrade(w, r, nil); err == nil {
			_ = conn.Close()
		}
	}))
}

func refuse(t *testing.T, up websocket.Upgrader, h http.Header) refusal {
	t.Helper()
	srv := upgradeServer(up)
	defer srv.Close()
	_, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), h)
	if err == nil || resp == nil {
		t.Fatalf("expected refusal, got err=%v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return refusal{resp.StatusCode, string(b), resp.Header.Get("Sec-Websocket-Version")}
}

func TestConsoleUpgrader_RefusalMatchesTerminal(t *testing.T) {
	t.Setenv("CONTAINARIUM_ALLOWED_ORIGINS", "")
	for name, h := range map[string]http.Header{
		"origin required":    {},
		"origin not allowed": {"Origin": {"https://evil.example"}},
	} {
		t.Run(name, func(t *testing.T) {
			term := refuse(t, newTerminalUpgrader(), h)
			cons := refuse(t, newConsoleUpgrader(), h)
			if cons != term {
				t.Fatalf("console refusal %+v != terminal refusal %+v", cons, term)
			}
			if cons.status != http.StatusForbidden || cons.version != "13" {
				t.Fatalf("unexpected refusal %+v", cons)
			}
		})
	}

	// Bearer with no Origin upgrades end to end.
	srv := upgradeServer(newConsoleUpgrader())
	defer srv.Close()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"),
		http.Header{"Authorization": {"Bearer header.payload.sig"}})
	if err != nil {
		t.Fatalf("bearer + no Origin should upgrade: %v", err)
	}
	_ = conn.Close()
}
