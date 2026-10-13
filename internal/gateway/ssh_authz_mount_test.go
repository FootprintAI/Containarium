package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
)

var sshAuthzSecret = []byte(strings.Repeat("a", auth.SentinelMinSecretLen))

func TestSSHAuthzHandlerRejectsUnsignedAndInvalidRequests(t *testing.T) {
	inner := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("unverified request reached SSH authorization stub")
	})
	h := sshAuthzHandler(auth.NewSentinelVerifier(nil, sshAuthzSecret), inner, time.Now)

	tests := []struct {
		name string
		prep func(*http.Request)
	}{
		{name: "unsigned", prep: func(*http.Request) {}},
		{name: "wrong secret", prep: func(r *http.Request) {
			auth.SignSentinelRequest(r, []byte(strings.Repeat("x", auth.SentinelMinSecretLen)))
		}},
		{name: "incomplete", prep: func(r *http.Request) {
			r.Header.Set(auth.SentinelHeaderSignature, "invalid")
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, SSHAuthzPath, strings.NewReader(`{"login":"box-user"}`))
			tt.prep(req)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rr.Code)
			}
		})
	}
}

func TestSSHAuthzHandlerVerifiedRequestReachesStub(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		username, ok := auth.UsernameFromContext(r.Context())
		if !ok || username != SSHAuthzUsername {
			t.Errorf("username = %q, ok = %v; want %q", username, ok, SSHAuthzUsername)
		}
		w.WriteHeader(http.StatusNotImplemented)
	})
	h := sshAuthzHandler(auth.NewSentinelVerifier(nil, sshAuthzSecret), inner, time.Now)

	req := httptest.NewRequest(http.MethodPost, SSHAuthzPath, strings.NewReader(`{"login":"box-user"}`))
	auth.SignSentinelRequest(req, sshAuthzSecret)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotImplemented || !called {
		t.Fatalf("status = %d, called = %v; want verified request to reach stub", rr.Code, called)
	}
}
