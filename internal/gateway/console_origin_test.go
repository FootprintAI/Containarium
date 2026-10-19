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
//
// Since #2701 the no-Origin exemption follows a bearer the route wrapper
// VALIDATED and recorded on the context (markValidated here stands in for
// the wrapper), never a bearer that is merely present on the request. The
// console route wrapper in gateway.go records it exactly like the terminal
// wrapper does.

func TestConsoleUpgrader_OriginTable(t *testing.T) {
	t.Setenv("CONTAINARIUM_ALLOWED_ORIGINS", "")

	tests := []struct {
		name   string
		req    *http.Request
		wantOK bool
		reason string
	}{
		{"empty origin + validated subprotocol bearer upgrades", markValidated(newOriginRequest("", withSubprotocolBearer)), true, ""},
		{"empty origin + validated Authorization bearer upgrades", markValidated(newOriginRequest("", withAuthorizationBearer)), true, ""},
		{"empty origin + subprotocol bearer never validated refused", newOriginRequest("", withSubprotocolBearer), false, originRequired},
		{"empty origin + Authorization bearer never validated refused", newOriginRequest("", withAuthorizationBearer), false, originRequired},
		{"empty origin + no bearer refused", markValidated(newOriginRequest("", nil)), false, originRequired},
		{"empty origin + only validated ?token= refused", markValidated(newOriginRequest("", func(r *http.Request) {
			r.URL.RawQuery = "token=header.payload.sig"
		})), false, originRequired},
		{"Origin: null + validated bearer refused", markValidated(newOriginRequest("null", withSubprotocolBearer)), false, originNotAllowed},
		{"unlisted origin + validated bearer refused", markValidated(newOriginRequest("https://evil.example", withSubprotocolBearer)), false, originNotAllowed},
		{"unlisted origin, no bearer refused", newOriginRequest("https://evil.example", nil), false, originNotAllowed},
		{"default-allowed origin + validated bearer upgrades", markValidated(newOriginRequest("http://localhost:3000", withSubprotocolBearer)), true, ""},
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

// upgradeServer serves the upgrader behind the route wrapper's contract:
// the request reaches the upgrader with its bearer marked validated, as the
// gateway's terminal and console wrappers do after ValidateToken succeeds.
func upgradeServer(up websocket.Upgrader) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if conn, err := up.Upgrade(w, markValidated(r), nil); err == nil {
			_ = conn.Close()
		}
	}))
}

// rawUpgradeServer serves the upgrader with no wrapper: a bearer on the
// request is present but never validated.
func rawUpgradeServer(up websocket.Upgrader) *httptest.Server {
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

	// Validated bearer with no Origin upgrades end to end.
	bearer := http.Header{"Authorization": {"Bearer header.payload.sig"}}
	srv := upgradeServer(newConsoleUpgrader())
	defer srv.Close()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), bearer)
	if err != nil {
		t.Fatalf("validated bearer + no Origin should upgrade: %v", err)
	}
	_ = conn.Close()

	// The same bearer, never validated, is refused on both routes alike
	// (#2701): presence on the request does not unlock the exemption.
	for name, up := range map[string]websocket.Upgrader{
		"terminal": newTerminalUpgrader(),
		"console":  newConsoleUpgrader(),
	} {
		raw := rawUpgradeServer(up)
		_, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(raw.URL, "http"), bearer)
		raw.Close()
		if err == nil || resp == nil {
			t.Fatalf("%s: never-validated bearer + no Origin should be refused, got err=%v", name, err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden || strings.TrimSpace(string(b)) != originRequired {
			t.Fatalf("%s: never-validated refusal = %d %q, want 403 %q", name, resp.StatusCode, b, originRequired)
		}
	}
}
