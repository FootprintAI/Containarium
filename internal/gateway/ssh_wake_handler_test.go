package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func okWake(_ context.Context, _ string) (bool, string, error) { return true, "10.0.0.7", nil }

func TestServeSSHWake_NilFn(t *testing.T) {
	rr := httptest.NewRecorder()
	ServeSSHWake(nil)(rr, httptest.NewRequest(http.MethodPost, "/ssh-wake", strings.NewReader(`{"username":"u"}`)))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("nil fn: code = %d, want 503", rr.Code)
	}
}

func TestServeSSHWake_MethodNotAllowed(t *testing.T) {
	rr := httptest.NewRecorder()
	ServeSSHWake(okWake)(rr, httptest.NewRequest(http.MethodGet, "/ssh-wake", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: code = %d, want 405", rr.Code)
	}
}

func TestServeSSHWake_MissingUsername(t *testing.T) {
	rr := httptest.NewRecorder()
	ServeSSHWake(okWake)(rr, httptest.NewRequest(http.MethodPost, "/ssh-wake", strings.NewReader(`{}`)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("empty username: code = %d, want 400", rr.Code)
	}
}

func TestServeSSHWake_Happy(t *testing.T) {
	var got string
	fn := func(_ context.Context, u string) (bool, string, error) { got = u; return true, "10.0.0.9", nil }

	rr := httptest.NewRecorder()
	ServeSSHWake(fn)(rr, httptest.NewRequest(http.MethodPost, "/ssh-wake", strings.NewReader(`{"username":"alice"}`)))

	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rr.Code)
	}
	if got != "alice" {
		t.Fatalf("fn got username %q, want alice", got)
	}
	var resp SSHWakeResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Ready || resp.IP != "10.0.0.9" {
		t.Fatalf("resp = %+v, want {Ready:true IP:10.0.0.9}", resp)
	}
}
