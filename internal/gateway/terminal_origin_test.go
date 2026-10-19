package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/gorilla/websocket"
)

func newOriginRequest(origin string, mutate func(*http.Request)) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/v1/containers/alice/terminal", nil)
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if mutate != nil {
		mutate(r)
	}
	return r
}

func withSubprotocolBearer(r *http.Request) {
	r.Header.Set("Sec-WebSocket-Protocol", auth.WSSubprotocolBearer+", header.payload.sig")
}

func withAuthorizationBearer(r *http.Request) {
	r.Header.Set("Authorization", "Bearer header.payload.sig")
}

func TestCheckTerminalOrigin(t *testing.T) {
	t.Setenv("CONTAINARIUM_ALLOWED_ORIGINS", "")

	tests := []struct {
		name       string
		req        *http.Request
		wantOK     bool
		wantReason string
	}{
		{"empty origin + subprotocol bearer upgrades", newOriginRequest("", withSubprotocolBearer), true, ""},
		{"empty origin + Authorization bearer upgrades", newOriginRequest("", withAuthorizationBearer), true, ""},
		{"empty origin + no bearer refused", newOriginRequest("", nil), false, originRequired},
		{"empty origin + only ?token= refused", newOriginRequest("", func(r *http.Request) {
			r.URL.RawQuery = "token=header.payload.sig"
		}), false, originRequired},
		{"unlisted origin + bearer refused", newOriginRequest("https://evil.example", withSubprotocolBearer), false, originNotAllowed},
		{"unlisted origin, no bearer refused", newOriginRequest("https://evil.example", nil), false, originNotAllowed},
		{"allowed origin + bearer upgrades", newOriginRequest("http://localhost:3000", withSubprotocolBearer), true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, reason := checkTerminalOrigin(tt.req)
			if ok != tt.wantOK || reason != tt.wantReason {
				t.Fatalf("checkTerminalOrigin = (%v, %q), want (%v, %q)", ok, reason, tt.wantOK, tt.wantReason)
			}
		})
	}
}

// The refusal must name its reason on the wire so a 403 here is not
// mistaken for a tenant-authorization failure.
func TestTerminalUpgrader_RefusalBodyNamesReason(t *testing.T) {
	up := newTerminalUpgrader()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if conn, err := up.Upgrade(w, r, nil); err == nil {
			_ = conn.Close()
		}
	}))
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	dial := func(h http.Header) (*http.Response, error) {
		_, resp, err := websocket.DefaultDialer.Dial(wsURL, h)
		return resp, err
	}

	// Bearer with no Origin upgrades end to end.
	h := http.Header{"Authorization": {"Bearer header.payload.sig"}}
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, h)
	if err != nil {
		t.Fatalf("bearer + no Origin should upgrade: %v", err)
	}
	_ = conn.Close()

	for name, tc := range map[string]struct {
		h    http.Header
		want string
	}{
		"origin required":    {http.Header{}, originRequired},
		"origin not allowed": {http.Header{"Origin": {"https://evil.example"}}, originNotAllowed},
	} {
		t.Run(name, func(t *testing.T) {
			resp, err := dial(tc.h)
			if err == nil || resp == nil {
				t.Fatalf("expected refusal, got err=%v resp=%v", err, resp)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", resp.StatusCode)
			}
			buf := make([]byte, 256)
			n, _ := resp.Body.Read(buf)
			if !strings.Contains(string(buf[:n]), tc.want) {
				t.Fatalf("body %q does not name %q", buf[:n], tc.want)
			}
		})
	}
}
