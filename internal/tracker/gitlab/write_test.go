package gitlab

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/footprintai/containarium/internal/tracker"
)

func TestComment_PostsAndNormalizes(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.EscapedPath()
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"author": {"username": "agent"}, "created_at": "2027-01-01T00:00:00Z", "body": "hello"}`))
	}))
	defer srv.Close()

	a := New(nil)
	comment, err := a.Comment(context.Background(), tracker.Conn{BaseURL: srv.URL, Project: "acme/widgets", Credential: "glpat-x"}, 5, "hello")
	if err != nil {
		t.Fatalf("Comment: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/api/v4/projects/acme%2Fwidgets/issues/5/notes" {
		t.Errorf("method=%s path=%s, want POST /api/v4/projects/acme%%2Fwidgets/issues/5/notes", gotMethod, gotPath)
	}
	if gotBody["body"] != "hello" {
		t.Errorf("request body = %v, want body=hello", gotBody)
	}
	if comment.Author != "agent" || comment.Body != "hello" {
		t.Errorf("comment = %+v, want author=agent body=hello", comment)
	}
}

func TestAssignIfUnassigned_AssignsWhenUnassigned(t *testing.T) {
	var putBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.EscapedPath() == "/api/v4/projects/acme%2Fwidgets/issues/5":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"iid": 5, "title": "t", "state": "opened", "labels": [], "assignee": null}`))
		case r.Method == http.MethodGet && r.URL.EscapedPath() == "/api/v4/user":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id": 42, "username": "the-bot", "bot": true}`))
		case r.Method == http.MethodPut:
			_ = json.NewDecoder(r.Body).Decode(&putBody)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.EscapedPath())
		}
	}))
	defer srv.Close()

	a := New(nil)
	assigned, err := a.AssignIfUnassigned(context.Background(), tracker.Conn{BaseURL: srv.URL, Project: "acme/widgets", Credential: "glpat-x"}, 5)
	if err != nil {
		t.Fatalf("AssignIfUnassigned: %v", err)
	}
	if !assigned {
		t.Error("assigned = false, want true (issue was unassigned)")
	}
	ids, ok := putBody["assignee_ids"].([]any)
	if !ok || len(ids) != 1 || ids[0] != float64(42) {
		t.Errorf("PUT body = %v, want assignee_ids=[42]", putBody)
	}
}

func TestAssignIfUnassigned_NeverReplacesExistingAssignee(t *testing.T) {
	var putCalled bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"iid": 5, "title": "t", "state": "opened", "labels": [], "assignee": {"username": "someone-else"}}`))
		case http.MethodPut:
			putCalled = true
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	a := New(nil)
	assigned, err := a.AssignIfUnassigned(context.Background(), tracker.Conn{BaseURL: srv.URL, Project: "acme/widgets", Credential: "glpat-x"}, 5)
	if err != nil {
		t.Fatalf("AssignIfUnassigned: %v", err)
	}
	if assigned {
		t.Error("assigned = true, want false — issue already had an assignee")
	}
	if putCalled {
		t.Error("PUT was called despite an existing assignee")
	}
}

func TestSetLabels_AddAndRemoveInOneCall(t *testing.T) {
	var gotMethod string
	var putBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		_ = json.NewDecoder(r.Body).Decode(&putBody)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	a := New(nil)
	err := a.SetLabels(context.Background(), tracker.Conn{BaseURL: srv.URL, Project: "acme/widgets", Credential: "glpat-x"}, 5,
		[]string{"bug", "p1"}, []string{"wontfix"})
	if err != nil {
		t.Fatalf("SetLabels: %v", err)
	}
	if gotMethod != http.MethodPut {
		t.Errorf("method = %s, want PUT (one call for both add and remove)", gotMethod)
	}
	if putBody["add_labels"] != "bug,p1" {
		t.Errorf("add_labels = %v, want bug,p1", putBody["add_labels"])
	}
	if putBody["remove_labels"] != "wontfix" {
		t.Errorf("remove_labels = %v, want wontfix", putBody["remove_labels"])
	}
}

func TestSetLabels_NoOpWhenNothingToChange(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()

	a := New(nil)
	if err := a.SetLabels(context.Background(), tracker.Conn{BaseURL: srv.URL, Project: "acme/widgets"}, 5, nil, nil); err != nil {
		t.Fatalf("SetLabels: %v", err)
	}
	if called {
		t.Error("SetLabels made an HTTP call with nothing to add or remove")
	}
}
