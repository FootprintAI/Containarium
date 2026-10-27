package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/gorilla/websocket"
)

// fakeWSJWT is shaped like a JWT so the subprotocol parser accepts it. It is
// never validated: whether the bearer counts as validated is the table's
// "validated" column, standing in for the gateway wrapper's ValidateToken.
const fakeWSJWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJlLXRlc3Q"

// TestTerminalUpgrader_OriginRuleOverTheWire dials the real upgrader with a
// real client. The no-Origin exemption must follow a bearer the wrapper
// validated, never a bearer that is merely present on the request.
func TestTerminalUpgrader_OriginRuleOverTheWire(t *testing.T) {
	type bearerForm int
	const (
		noBearer bearerForm = iota
		subprotocolBearer
		headerBearer
		queryBearer
	)

	tests := []struct {
		name       string
		envOrigins string
		origin     string
		bearer     bearerForm
		validated  bool
		wantStatus int
		wantBody   string // substring of the 403 body; "" = not checked
	}{
		{name: "no origin + validated subprotocol bearer is accepted", bearer: subprotocolBearer, validated: true, wantStatus: http.StatusSwitchingProtocols},
		{name: "no origin + validated Authorization bearer is accepted", bearer: headerBearer, validated: true, wantStatus: http.StatusSwitchingProtocols},
		{name: "no origin + no bearer is rejected", bearer: noBearer, validated: true, wantStatus: http.StatusForbidden, wantBody: originRequired},
		{name: "no origin + subprotocol bearer never validated is rejected", bearer: subprotocolBearer, wantStatus: http.StatusForbidden, wantBody: originRequired},
		{name: "no origin + Authorization bearer never validated is rejected", bearer: headerBearer, wantStatus: http.StatusForbidden, wantBody: originRequired},
		{name: "no origin + validated deprecated ?token= is rejected", bearer: queryBearer, validated: true, wantStatus: http.StatusForbidden, wantBody: originRequired},
		{name: "configured origin + validated bearer is accepted", envOrigins: "https://app.example.com", origin: "https://app.example.com", bearer: subprotocolBearer, validated: true, wantStatus: http.StatusSwitchingProtocols},
		{name: "disallowed origin + validated bearer is rejected", envOrigins: "https://app.example.com", origin: "https://attacker.example.net", bearer: subprotocolBearer, validated: true, wantStatus: http.StatusForbidden, wantBody: originNotAllowed},
		{name: "localhost default is still accepted without a bearer", origin: "http://localhost", wantStatus: http.StatusSwitchingProtocols},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("CONTAINARIUM_ALLOWED_ORIGINS", tt.envOrigins)

			up := newTerminalUpgrader()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.validated {
					r = markValidated(r)
				}
				if conn, err := up.Upgrade(w, r, nil); err == nil {
					_ = conn.Close()
				}
			}))
			defer srv.Close()

			wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/containers/alice/terminal"
			header := http.Header{}
			if tt.origin != "" {
				header.Set("Origin", tt.origin)
			}
			dialer := websocket.Dialer{}
			switch tt.bearer {
			case subprotocolBearer:
				dialer.Subprotocols = []string{auth.WSSubprotocolBearer, fakeWSJWT}
			case headerBearer:
				header.Set("Authorization", "Bearer "+fakeWSJWT)
			case queryBearer:
				wsURL += "?token=" + fakeWSJWT
			}

			conn, resp, err := dialer.Dial(wsURL, header)
			if conn != nil {
				_ = conn.Close()
			}
			if resp == nil {
				t.Fatalf("no HTTP response: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("status = %d, want %d (err: %v)", resp.StatusCode, tt.wantStatus, err)
			}
			if tt.wantBody != "" {
				body, _ := io.ReadAll(resp.Body)
				if !strings.Contains(string(body), tt.wantBody) {
					t.Errorf("403 body = %q, want it to name %q", body, tt.wantBody)
				}
			}
		})
	}
}
