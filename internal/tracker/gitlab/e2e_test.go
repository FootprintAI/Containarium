//go:build gitlab_e2e

// Package gitlab_test's e2e suite is the design note's opt-in lane: "a real
// GitLab CE container proving quick-action sanitization and single-assignee
// behavior end to end". It runs against a REAL GitLab instance (env below),
// never a fixture, because both properties it proves are exactly the ones a
// recorded fixture cannot: whether GitLab's own parser executes a quick
// action, and how GitLab's own single-assignee model actually reacts to a
// second assignment attempt.
//
// Env (all required — a missing one fails the suite, per this repo's
// "a skipped test here is indistinguishable from a passing one" convention;
// see store-integration.yml):
//
//	GITLAB_E2E_URL    site root, e.g. http://localhost:8929
//	GITLAB_E2E_TOKEN  a personal access token with the `api` scope
//
// The suite creates and deletes its own project per run (TestMain), so it
// is safe to re-run against the same instance.
//
// Run it locally:
//
//	docker run -d --name gitlab-ce --hostname gitlab.local \
//	  -e GITLAB_OMNIBUS_CONFIG='external_url "http://gitlab.local"; puma["worker_processes"] = 0; sidekiq["max_concurrency"] = 5; prometheus_monitoring["enable"] = false;' \
//	  -p 8929:80 --shm-size 256m gitlab/gitlab-ce:latest
//	# wait for: docker exec gitlab-ce curl -s http://localhost/-/readiness -> 200 (~1-2 min)
//	docker exec gitlab-ce gitlab-rails runner "
//	  t = User.find_by_username('root').personal_access_tokens.create(scopes: ['api'], name: 'e2e', expires_at: 1.day.from_now)
//	  t.set_token('local-e2e-token'); t.save!"
//	GITLAB_E2E_URL=http://localhost:8929 GITLAB_E2E_TOKEN=local-e2e-token \
//	  go test -tags gitlab_e2e -v ./internal/tracker/gitlab/... -run TestGitLabE2E
//	docker rm -f gitlab-ce
package gitlab_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/tracker"
	trackergitlab "github.com/footprintai/containarium/internal/tracker/gitlab"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

var (
	e2eBaseURL    string
	e2eToken      string
	e2eProject    string // "namespace/path", set by TestMain
	e2eProjectID  int
	e2eHTTPClient = &http.Client{Timeout: 30 * time.Second}
)

func e2eRequire(t testing.TB, name string) string {
	t.Helper()
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		t.Fatalf("gitlab e2e: %s is required (this suite fails rather than skips on a missing env — see package doc)", name)
	}
	return v
}

// apiCall is a raw, adapter-independent GitLab v4 call used to set up
// fixtures and to observe ground truth (did GitLab actually execute a quick
// action, is this issue actually assigned). Using the adapter under test to
// verify the adapter under test would prove nothing. Returns an error
// instead of failing a *testing.T directly, so it works from TestMain (which
// has none) as well as from within a test via e2eAPI below.
func apiCall(method, path string, body any) (map[string]any, error) {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request: %w", err)
		}
		reader = strings.NewReader(string(b))
	}
	req, err := http.NewRequest(method, e2eBaseURL+"/api/v4"+path, reader)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("PRIVATE-TOKEN", e2eToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := e2eHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, raw)
	}
	if len(raw) == 0 {
		return nil, nil
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("%s %s: decode response: %w\n%s", method, path, err, raw)
	}
	return out, nil
}

// e2eAPI wraps apiCall for use inside a test: any error fails the test
// immediately, since every caller here is fixture setup or a ground-truth
// read that the test's own assertions depend on.
func e2eAPI(t testing.TB, method, path string, body any) map[string]any {
	t.Helper()
	out, err := apiCall(method, path, body)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestMain(m *testing.M) {
	e2eBaseURL = strings.TrimSuffix(os.Getenv("GITLAB_E2E_URL"), "/")
	e2eToken = os.Getenv("GITLAB_E2E_TOKEN")
	if e2eBaseURL == "" || e2eToken == "" {
		// Let the individual tests fail loudly via e2eRequire rather than
		// silently skipping the whole binary here.
		os.Exit(m.Run())
	}

	name := fmt.Sprintf("e2e-%d", time.Now().UnixNano())
	proj, err := apiCall(http.MethodPost, "/projects", map[string]any{
		"name": name, "path": name, "visibility": "private",
		"initialize_with_readme": false,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "gitlab e2e: create project:", err)
		os.Exit(1)
	}
	if proj == nil {
		fmt.Fprintln(os.Stderr, "gitlab e2e: project creation returned no body")
		os.Exit(1)
	}
	e2eProjectID = int(proj["id"].(float64))
	e2eProject = proj["path_with_namespace"].(string)

	code := m.Run()

	if _, err := apiCall(http.MethodDelete, fmt.Sprintf("/projects/%d", e2eProjectID), nil); err != nil {
		fmt.Fprintln(os.Stderr, "gitlab e2e: cleanup: delete project:", err)
	}
	os.Exit(code)
}

func e2eConn(t testing.TB) tracker.Conn {
	t.Helper()
	e2eRequire(t, "GITLAB_E2E_URL")
	e2eRequire(t, "GITLAB_E2E_TOKEN")
	if e2eProject == "" {
		t.Fatal("gitlab e2e: no project (TestMain did not run — env was set after the binary started?)")
	}
	return tracker.Conn{BaseURL: e2eBaseURL, Project: e2eProject, Credential: e2eToken}
}

func e2eCreateIssue(t testing.TB, title string) int64 {
	t.Helper()
	resp := e2eAPI(t, http.MethodPost, fmt.Sprintf("/projects/%s/issues", url.PathEscape(e2eProject)),
		map[string]any{"title": title})
	return int64(resp["iid"].(float64))
}

func e2eIssueState(t testing.TB, iid int64) string {
	t.Helper()
	resp := e2eAPI(t, http.MethodGet, fmt.Sprintf("/projects/%s/issues/%d", url.PathEscape(e2eProject), iid), nil)
	return resp["state"].(string)
}

func e2eIssueAssigneeID(t testing.TB, iid int64) (int64, bool) {
	t.Helper()
	resp := e2eAPI(t, http.MethodGet, fmt.Sprintf("/projects/%s/issues/%d", url.PathEscape(e2eProject), iid), nil)
	a, ok := resp["assignee"].(map[string]any)
	if !ok || a == nil {
		return 0, false
	}
	return int64(a["id"].(float64)), true
}

func e2eSetIssueState(t testing.TB, iid int64, event string) {
	t.Helper()
	e2eAPI(t, http.MethodPut, fmt.Sprintf("/projects/%s/issues/%d", url.PathEscape(e2eProject), iid),
		map[string]any{"state_event": event})
}

func e2ePostRawComment(t testing.TB, iid int64, body string) {
	t.Helper()
	e2eAPI(t, http.MethodPost, fmt.Sprintf("/projects/%s/issues/%d/notes", url.PathEscape(e2eProject), iid),
		map[string]any{"body": body})
}

// TestGitLabE2E_QuickActionSanitization is the property a recorded fixture
// cannot prove: that tracker.Sanitize's transformation of an agent-supplied
// "/close" defeats GitLab's OWN quick-action parser, not just some assumption
// about how it works.
func TestGitLabE2E_QuickActionSanitization(t *testing.T) {
	conn := e2eConn(t)
	adapter := trackergitlab.New(nil)
	ctx := context.Background()

	iid := e2eCreateIssue(t, "sanitization baseline")

	// Baseline: an UNSANITIZED "/close" posted directly (bypassing our
	// adapter entirely) really does close the issue on this GitLab version.
	// If this assertion ever starts failing, the sanitizer isn't protecting
	// against anything real any more and the test itself needs to be revisited
	// — not silently left green.
	e2ePostRawComment(t, iid, "/close")
	if got := e2eIssueState(t, iid); got != "closed" {
		t.Fatalf("baseline: unsanitized /close did not close the issue (state=%q) — GitLab's quick-action behavior changed; this test's premise needs revisiting", got)
	}
	e2eSetIssueState(t, iid, "reopen")

	// The real assertion: through our adapter, with tracker.Sanitize applied
	// (exactly what internal/server/tracker_write_server.go does before
	// calling Comment), the same text must NOT close the issue.
	sanitized := tracker.Sanitize("/close")
	if sanitized == "/close" {
		t.Fatal("tracker.Sanitize did not transform /close — nothing to test")
	}
	comment, err := adapter.Comment(ctx, conn, iid, sanitized)
	if err != nil {
		t.Fatalf("Comment: %v", err)
	}
	if got := e2eIssueState(t, iid); got != "opened" {
		t.Errorf("issue state = %q after a sanitized /close comment, want opened — GitLab executed a quick action our sanitizer was supposed to defeat", got)
	}
	issue, err := adapter.GetIssue(ctx, conn, iid)
	if err != nil {
		t.Fatalf("GetIssue: %v", err)
	}
	if issue.State == pb.TrackerIssueState_TRACKER_ISSUE_STATE_CLOSED {
		t.Error("adapter's own GetIssue also reports the issue closed")
	}
	found := false
	for _, c := range issue.Comments {
		if c.Body == comment.Body {
			found = true
		}
	}
	if !found {
		t.Error("sanitized comment not present in GetIssue's own comment list")
	}
}

// TestGitLabE2E_SingleAssigneeBehavior proves AssignIfUnassigned's contract
// against GitLab's actual single-assignee model (GitLab Free/CE): it assigns
// once, and a second call is a true no-op rather than an error or a silent
// reassignment.
func TestGitLabE2E_SingleAssigneeBehavior(t *testing.T) {
	conn := e2eConn(t)
	adapter := trackergitlab.New(nil)
	ctx := context.Background()

	iid := e2eCreateIssue(t, "single assignee")
	if _, ok := e2eIssueAssigneeID(t, iid); ok {
		t.Fatal("freshly created issue already has an assignee")
	}

	self, err := adapter.WhoAmI(ctx, conn)
	if err != nil {
		t.Fatalf("WhoAmI: %v", err)
	}
	if self == "" {
		t.Fatal("WhoAmI returned an empty login")
	}

	assigned, err := adapter.AssignIfUnassigned(ctx, conn, iid)
	if err != nil {
		t.Fatalf("AssignIfUnassigned (first call): %v", err)
	}
	if !assigned {
		t.Fatal("AssignIfUnassigned on an unassigned issue returned false")
	}
	gotID, ok := e2eIssueAssigneeID(t, iid)
	if !ok {
		t.Fatal("issue has no assignee after AssignIfUnassigned reported true")
	}

	assigned, err = adapter.AssignIfUnassigned(ctx, conn, iid)
	if err != nil {
		t.Fatalf("AssignIfUnassigned (second call): %v", err)
	}
	if assigned {
		t.Error("AssignIfUnassigned on an already-assigned issue returned true — never replaces an existing assignee")
	}
	stillID, ok := e2eIssueAssigneeID(t, iid)
	if !ok || stillID != gotID {
		t.Errorf("assignee changed across the second call: was %d, now %d (ok=%v)", gotID, stillID, ok)
	}
}
