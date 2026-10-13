package sshauthz_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	authz "github.com/footprintai/containarium/internal/sentinel/sshauthz"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestHTTPAuthorizer(t *testing.T) {
	secret := []byte(strings.Repeat("s", auth.SentinelMinSecretLen))
	for _, tc := range []struct {
		name                 string
		status               int
		body                 string
		unavailable, success bool
	}{
		{"allow", 200, `{"decision":"SSH_AUTHZ_DECISION_ALLOW","userId":"user-a","cacheTtl":"30s"}`, false, true},
		{"deny", 200, `{"decision":"SSH_AUTHZ_DECISION_DENY","denyReason":"SSH_DENY_REASON_UNKNOWN_KEY"}`, false, true},
		{"pending", 200, `{"decision":"SSH_AUTHZ_DECISION_DENY","denyReason":"SSH_DENY_REASON_APPROVAL_PENDING"}`, false, true},
		{"5xx", 503, "offline", true, false},
		{"4xx", 401, "unauthorized", false, false},
		{"bad json", 200, "broken", false, false},
		{"oversized", 200, strings.Repeat("x", (1<<20)+1), false, false},
		{"redirect", 302, "", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seen := 0
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen++
				if r.Method != "POST" || r.URL.Path != authz.AuthorizePath || r.Header.Get("Content-Type") != "application/json" {
					t.Error("wrong request shape")
				}
				data, _ := io.ReadAll(r.Body)
				if err := auth.NewSentinelVerifier(nil, secret).VerifyBodyRequest(r, data, time.Now()); err != nil {
					t.Error(err)
				}

				input := new(pb.AuthorizeSSHRequest)
				if err := protojson.Unmarshal(data, input); err != nil || input.Login != "alice" {
					t.Errorf("body %s: %v", data, err)
				}
				if tc.status == 302 {
					w.Header().Set("Location", "/redirected")
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer ts.Close()
			a := &authz.HTTPAuthorizer{BackendURL: func(b string) (string, error) {
				if b != "a" {
					t.Error(b)
				}
				return ts.URL, nil
			}, Sign: func(r *http.Request, body []byte) { auth.SignSentinelBodyRequest(r, secret, body) }}
			resp, err := a.Authorize(context.Background(), "a", &pb.AuthorizeSSHRequest{Login: "alice"})
			if (err == nil) != tc.success || errors.Is(err, authz.ErrUpstreamUnavailable) != tc.unavailable {
				t.Fatalf("resp=%v err=%v", resp, err)
			}
			if seen != 1 {
				t.Fatalf("redirect or retry made %d requests", seen)
			}
		})
	}
}

func TestHTTPAuthorizerTimeoutAndTransport(t *testing.T) {
	for _, tc := range []struct {
		name    string
		timeout time.Duration
	}{{"default", 0}, {"override", 20 * time.Millisecond}} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				deadline, ok := r.Context().Deadline()
				want := tc.timeout
				if want == 0 {
					want = authz.DefaultTimeout
				}
				if !ok || time.Until(deadline) > want {
					t.Fatal("missing bounded deadline")
				}
				if tc.timeout > 0 {
					<-r.Context().Done()
					return nil, r.Context().Err()
				}
				return nil, errors.New("connection refused")
			})}
			a := &authz.HTTPAuthorizer{Client: client, Timeout: tc.timeout, BackendURL: func(string) (string, error) { return "http://example.com", nil }, Sign: func(*http.Request, []byte) {}}
			_, err := a.Authorize(context.Background(), "a", &pb.AuthorizeSSHRequest{})
			if !errors.Is(err, authz.ErrUpstreamUnavailable) {
				t.Fatal(err)
			}
		})
	}
}
