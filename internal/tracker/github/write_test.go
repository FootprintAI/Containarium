package github

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
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"user": {"login": "agent"}, "created_at": "2027-01-01T00:00:00Z", "body": "hello"}`))
	}))
	defer srv.Close()

	a := New(nil)
	comment, err := a.Comment(context.Background(), tracker.Conn{BaseURL: srv.URL, Project: "acme/widgets", Credential: "ghp_x"}, 5, "hello")
	if err != nil {
		t.Fatalf("Comment: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/repos/acme/widgets/issues/5/comments" {
		t.Errorf("method=%s path=%s, want POST /repos/acme/widgets/issues/5/comments", gotMethod, gotPath)
	}
	if gotBody["body"] != "hello" {
		t.Errorf("request body = %v, want body=hello", gotBody)
	}
	if comment.Author != "agent" || comment.Body != "hello" {
		t.Errorf("comment = %+v, want author=agent body=hello", comment)
	}
}

func TestAssignIfUnassigned_AssignsWhenUnassigned(t *testing.T) {
	var assignPath string
	var assignBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/repos/acme/widgets/issues/5" && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"number": 5, "title": "t", "state": "open", "labels": [], "assignee": null}`))
		case r.URL.Path == "/user":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"login": "the-bot"}`))
		case r.URL.Path == "/repos/acme/widgets/issues/5/assignees":
			assignPath = r.URL.Path
			_ = json.NewDecoder(r.Body).Decode(&assignBody)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	a := New(nil)
	assigned, err := a.AssignIfUnassigned(context.Background(), tracker.Conn{BaseURL: srv.URL, Project: "acme/widgets", Credential: "ghp_x"}, 5)
	if err != nil {
		t.Fatalf("AssignIfUnassigned: %v", err)
	}
	if !assigned {
		t.Error("assigned = false, want true (issue was unassigned)")
	}
	if assignPath == "" {
		t.Fatal("assignees endpoint was never called")
	}
	labels, ok := assignBody["assignees"].([]any)
	if !ok || len(labels) != 1 || labels[0] != "the-bot" {
		t.Errorf("assign body = %v, want assignees=[the-bot]", assignBody)
	}
}

func TestAssignIfUnassigned_NeverReplacesExistingAssignee(t *testing.T) {
	var assignCalled bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/widgets/issues/5":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"number": 5, "title": "t", "state": "open", "labels": [], "assignee": {"login": "someone-else"}}`))
		case "/repos/acme/widgets/issues/5/assignees":
			assignCalled = true
			w.WriteHeader(http.StatusCreated)
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
		}
	}))
	defer srv.Close()

	a := New(nil)
	assigned, err := a.AssignIfUnassigned(context.Background(), tracker.Conn{BaseURL: srv.URL, Project: "acme/widgets", Credential: "ghp_x"}, 5)
	if err != nil {
		t.Fatalf("AssignIfUnassigned: %v", err)
	}
	if assigned {
		t.Error("assigned = true, want false — issue already had an assignee")
	}
	if assignCalled {
		t.Error("assignees endpoint was called despite an existing assignee")
	}
}

func TestSetLabels_AddsAndRemoves(t *testing.T) {
	var addBody map[string]any
	var removedLabels []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/repos/acme/widgets/issues/5/labels":
			_ = json.NewDecoder(r.Body).Decode(&addBody)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[]`))
		case r.Method == http.MethodDelete:
			removedLabels = append(removedLabels, r.URL.Path)
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	a := New(nil)
	err := a.SetLabels(context.Background(), tracker.Conn{BaseURL: srv.URL, Project: "acme/widgets", Credential: "ghp_x"}, 5,
		[]string{"bug", "p1"}, []string{"wontfix"})
	if err != nil {
		t.Fatalf("SetLabels: %v", err)
	}
	added, ok := addBody["labels"].([]any)
	if !ok || len(added) != 2 {
		t.Errorf("add body = %v, want 2 labels", addBody)
	}
	if len(removedLabels) != 1 || removedLabels[0] != "/repos/acme/widgets/issues/5/labels/wontfix" {
		t.Errorf("removedLabels = %v, want exactly the wontfix delete", removedLabels)
	}
}

func TestSetLabels_RemoveMissingLabelIsNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound) // label wasn't on the issue
	}))
	defer srv.Close()

	a := New(nil)
	err := a.SetLabels(context.Background(), tracker.Conn{BaseURL: srv.URL, Project: "acme/widgets", Credential: "ghp_x"}, 5,
		nil, []string{"not-there"})
	if err != nil {
		t.Fatalf("SetLabels should tolerate removing an already-absent label: %v", err)
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
