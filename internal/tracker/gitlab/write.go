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

// resolveSelfUser resolves the credential's own GitLab user via GET
// /user — shared by AssignIfUnassigned (needs the numeric id) and
// WhoAmI (needs the username).
func (a *Adapter) resolveSelfUser(ctx context.Context, apiBase, token string) (userResponse, error) {
	var me userResponse
	err := a.get(ctx, apiBase+"/user", token, &me)
	return me, err
}

// WhoAmI resolves conn's credential to its own GitLab username.
func (a *Adapter) WhoAmI(ctx context.Context, conn tracker.Conn) (string, error) {
	me, err := a.resolveSelfUser(ctx, apiBaseURL(conn.BaseURL), conn.Credential)
	if err != nil {
		return "", err
	}
	return me.Username, nil
}

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

	me, err := a.resolveSelfUser(ctx, apiBase, conn.Credential)
	if err != nil {
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

// validateWireLabels refuses any label that GitLab's comma-joined wire
// format would split into more than one (review of #2034). The daemon's
// allow-list already rejects these before calling the adapter; this is
// defense in depth, so no caller can ever put a smuggled label on the wire.
func validateWireLabels(lists ...[]string) error {
	for _, list := range lists {
		for _, l := range list {
			if err := tracker.ValidateLabel(l); err != nil {
				return err
			}
		}
	}
	return nil
}

// SetLabels adds and removes labels in one call — GitLab's issue-edit
// endpoint accepts add_labels/remove_labels directly, unlike GitHub's
// separate add/remove endpoints.
func (a *Adapter) SetLabels(ctx context.Context, conn tracker.Conn, number int64, add, remove []string) error {
	if len(add) == 0 && len(remove) == 0 {
		return nil
	}
	if err := validateWireLabels(add, remove); err != nil {
		return err
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

// CreateIssue opens an issue (#2024). GitLab's create endpoint takes the
// body as `description` and labels as ONE comma-joined string (unlike
// GitHub's array) — the same shape SetLabels already uses. The daemon
// has already allow-listed the labels and composed the body. The 201
// response is normalized through toIssue (iid, never id).
func (a *Adapter) CreateIssue(ctx context.Context, conn tracker.Conn, n tracker.NewIssue) (tracker.Issue, error) {
	if err := validateWireLabels(n.Labels); err != nil {
		return tracker.Issue{}, err
	}
	apiBase := apiBaseURL(conn.BaseURL)
	projectPath := url.PathEscape(conn.Project)
	reqBody := struct {
		Title       string `json:"title"`
		Description string `json:"description"`
		Labels      string `json:"labels,omitempty"`
	}{Title: n.Title, Description: n.Body, Labels: strings.Join(n.Labels, ",")}

	var raw glIssue
	if err := a.do(ctx, http.MethodPost, fmt.Sprintf("%s/projects/%s/issues", apiBase, projectPath),
		conn.Credential, reqBody, &raw); err != nil {
		return tracker.Issue{}, err
	}
	return toIssue(raw, nil), nil
}
