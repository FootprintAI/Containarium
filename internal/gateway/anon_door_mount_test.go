package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
)

type anonDoorProbe struct {
	jwtCalled, innerCalled bool
	username               string
	scopes                 []string
	roles                  []string
}

func (p *anonDoorProbe) handlers() (jwt, inner http.Handler) {
	jwt = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { p.jwtCalled = true; w.WriteHeader(http.StatusTeapot) })
	inner = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.innerCalled = true
		p.username, _ = auth.UsernameFromContext(r.Context())
		p.scopes, _ = auth.ScopesFromContext(r.Context())
		p.roles, _ = auth.RolesFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	return jwt, inner
}

var anonDoorSecret = []byte(strings.Repeat("s", auth.SentinelMinSecretLen))

func TestAnonDoorHandler_SentinelSignatureGetsDoorIdentity(t *testing.T) {
	p := &anonDoorProbe{}
	jwt, inner := p.handlers()
	h := anonDoorHandler(auth.NewSentinelVerifier(nil, anonDoorSecret), jwt, inner, nil)

	req := httptest.NewRequest(http.MethodPost, AnonDoorEnsurePath, strings.NewReader(`{"publicKey":"ssh-ed25519 AAAA x"}`))
	auth.SignSentinelRequest(req, anonDoorSecret)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK || !p.innerCalled || p.jwtCalled {
		t.Fatalf("code=%d inner=%v jwt=%v, want inner only with 200", rr.Code, p.innerCalled, p.jwtCalled)
	}
	if p.username != AnonDoorUsername {
		t.Errorf("username = %q, want %q", p.username, AnonDoorUsername)
	}
	if len(p.scopes) != 1 || p.scopes[0] != auth.ScopeAnonDoor {
		t.Errorf("scopes = %v, want [%s] only", p.scopes, auth.ScopeAnonDoor)
	}
	if len(p.roles) != 0 {
		t.Errorf("roles = %v, want none: the door is not an admin", p.roles)
	}
}

func TestAnonDoorHandler_NoSignatureFallsThroughToJWT(t *testing.T) {
	p := &anonDoorProbe{}
	jwt, inner := p.handlers()
	h := anonDoorHandler(auth.NewSentinelVerifier(nil, anonDoorSecret), jwt, inner, nil)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, AnonDoorEnsurePath, nil))

	if rr.Code != http.StatusTeapot || !p.jwtCalled || p.innerCalled {
		t.Fatalf("code=%d jwt=%v inner=%v, want the JWT chain only", rr.Code, p.jwtCalled, p.innerCalled)
	}
}

func TestAnonDoorHandler_BadSignatureIs401NeverJWT(t *testing.T) {
	tests := []struct {
		name string
		mut  func(*http.Request)
		v    auth.SentinelVerifier
	}{
		{"wrong secret", func(r *http.Request) {
			auth.SignSentinelRequest(r, []byte(strings.Repeat("x", auth.SentinelMinSecretLen)))
		}, auth.NewSentinelVerifier(nil, anonDoorSecret)},
		{"tampered path", func(r *http.Request) {
			auth.SignSentinelRequest(r, anonDoorSecret)
			r.URL.Path = "/v1/anon/boxes:claim"
		}, auth.NewSentinelVerifier(nil, anonDoorSecret)},
		{"stale timestamp", func(r *http.Request) {
			auth.SignSentinelRequest(r, anonDoorSecret)
			r.Header.Set(auth.SentinelHeaderTimestamp, "1000000000")
		}, auth.NewSentinelVerifier(nil, anonDoorSecret)},
		{"verifier unconfigured", func(r *http.Request) { auth.SignSentinelRequest(r, anonDoorSecret) }, auth.NewSentinelVerifier(nil, nil)},
		{"signature header only", func(r *http.Request) { r.Header.Set(auth.SentinelHeaderSignature, "abc") }, auth.NewSentinelVerifier(nil, anonDoorSecret)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &anonDoorProbe{}
			jwt, inner := p.handlers()
			h := anonDoorHandler(tt.v, jwt, inner, func() time.Time { return time.Now() })

			req := httptest.NewRequest(http.MethodPost, AnonDoorEnsurePath, nil)
			tt.mut(req)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if rr.Code != http.StatusUnauthorized || p.jwtCalled || p.innerCalled {
				t.Fatalf("code=%d jwt=%v inner=%v, want 401 and no handler", rr.Code, p.jwtCalled, p.innerCalled)
			}
		})
	}
}
