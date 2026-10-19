package client

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TerminateUserSessions REST call (#2522) must match the google.api.http
// mapping in service.proto: POST /v1/users/{username}/sessions:terminate.
func TestTerminateUserSessions_HTTPPathAndDecoding(t *testing.T) {
	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.EscapedPath()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"terminatedSessions":3,"boxesTouched":2}`)
	}))
	defer srv.Close()
	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.TerminateUserSessions("alice")
	if err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/users/alice/sessions:terminate" {
		t.Errorf("%s %s", gotMethod, gotPath)
	}
	if resp.GetTerminatedSessions() != 3 || resp.GetBoxesTouched() != 2 {
		t.Errorf("decoded %+v", resp)
	}
	if TerminateUserSessionsPath("a/b") != "/v1/users/a%2Fb/sessions:terminate" {
		t.Errorf("username must be path-escaped: %s", TerminateUserSessionsPath("a/b"))
	}
}
