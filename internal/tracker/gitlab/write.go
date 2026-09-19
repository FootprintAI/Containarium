package gitlab

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/footprintai/containarium/internal/tracker"
)

var _ tracker.WriterProvider = (*Adapter)(nil)

// Comment posts a comment (a GitLab "note") and returns its normalized
// form.
func (a *Adapter) Comment(ctx context.Context, conn tracker.Conn, number int64, body string) (tracker.Comment, error) {
	apiBase := apiBaseURL(conn.BaseURL)
	projectPath := url.PathEscape(conn.Project)
	reqBody := struct {
		Body string `json:"body"`
	}{Body: body}

	var resp glNote
	if err := a.do(ctx, http.MethodPost, fmt.Sprintf("%s/projects/%s/issues/%d/notes", apiBase, projectPath, number),
		conn.Credential, reqBody, &resp); err != nil {
		return tracker.Comment{}, err
	}
	return tracker.Comment{
		Author:    resp.Author.Username,
		CreatedAt: parseGitLabTime(resp.CreatedAt),
		Body:      resp.Body,
	}, nil
}

// AssignIfUnassigned assigns the credential's own account to the
// issue, but only if it currently has no assignee.
func (a *Adapter) AssignIfUnassigned(ctx context.Context, conn tracker.Conn, number int64) (bool, error) {
	apiBase := apiBaseURL(conn.BaseURL)
	projectPath := url.PathEscape(conn.Project)

	var issue glIssue
	if err := a.get(ctx, fmt.Sprintf("%s/projects/%s/issues/%d", apiBase, projectPath, number), conn.Credential, &issue); err != nil {
		return false, err
	}
	if issue.Assignee != nil {
		return false, nil // never replace an existing assignee
	}

	var me userResponse
	if err := a.get(ctx, apiBase+"/user", conn.Credential, &me); err != nil {
		return false, fmt.Errorf("resolve credential's own user id: %w", err)
	}

	reqBody := struct {
		AssigneeIDs []int64 `json:"assignee_ids"`
	}{AssigneeIDs: []int64{me.ID}}
	if err := a.do(ctx, http.MethodPut, fmt.Sprintf("%s/projects/%s/issues/%d", apiBase, projectPath, number),
		conn.Credential, reqBody, nil); err != nil {
		return false, err
	}
	return true, nil
}

// SetLabels adds and removes labels in one call — GitLab's issue-edit
// endpoint accepts add_labels/remove_labels directly, unlike GitHub's
// separate add/remove endpoints.
func (a *Adapter) SetLabels(ctx context.Context, conn tracker.Conn, number int64, add, remove []string) error {
	if len(add) == 0 && len(remove) == 0 {
		return nil
	}
	apiBase := apiBaseURL(conn.BaseURL)
	projectPath := url.PathEscape(conn.Project)

	reqBody := struct {
		AddLabels    string `json:"add_labels,omitempty"`
		RemoveLabels string `json:"remove_labels,omitempty"`
	}{}
	if len(add) > 0 {
		reqBody.AddLabels = strings.Join(add, ",")
	}
	if len(remove) > 0 {
		reqBody.RemoveLabels = strings.Join(remove, ",")
	}
	return a.do(ctx, http.MethodPut, fmt.Sprintf("%s/projects/%s/issues/%d", apiBase, projectPath, number),
		conn.Credential, reqBody, nil)
}
