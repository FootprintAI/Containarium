package github

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/footprintai/containarium/internal/tracker"
)

var _ tracker.WriterProvider = (*Adapter)(nil)

// Comment posts a comment and returns its normalized form.
func (a *Adapter) Comment(ctx context.Context, conn tracker.Conn, number int64, body string) (tracker.Comment, error) {
	base := apiBase(conn.BaseURL)
	reqBody := struct {
		Body string `json:"body"`
	}{Body: body}

	var resp ghComment
	if err := a.do(ctx, http.MethodPost, fmt.Sprintf("%s/repos/%s/issues/%d/comments", base, conn.Project, number),
		conn.Credential, reqBody, &resp); err != nil {
		return tracker.Comment{}, err
	}
	return tracker.Comment{
		Author:    resp.User.Login,
		CreatedAt: parseGitHubTime(resp.CreatedAt),
		Body:      resp.Body,
	}, nil
}

// AssignIfUnassigned assigns the credential's own account to the issue,
// but only if it currently has no assignee. Requires the credential to
// be able to call GET /user (a classic or fine-grained PAT) — a GitHub
// App installation token has no "self" user to resolve this way, and
// assigning its bot identity would need the app's slug, which this
// adapter doesn't have; AssignIfUnassigned returns an error for that
// credential type rather than guessing.
func (a *Adapter) AssignIfUnassigned(ctx context.Context, conn tracker.Conn, number int64) (bool, error) {
	base := apiBase(conn.BaseURL)

	var issue ghIssue
	if err := a.get(ctx, fmt.Sprintf("%s/repos/%s/issues/%d", base, conn.Project, number), conn.Credential, &issue); err != nil {
		return false, err
	}
	if issue.Assignee != nil {
		return false, nil // never replace an existing assignee
	}

	login, err := a.currentUserLogin(ctx, base, conn.Credential)
	if err != nil {
		return false, fmt.Errorf("resolve credential's own login: %w", err)
	}

	reqBody := struct {
		Assignees []string `json:"assignees"`
	}{Assignees: []string{login}}
	if err := a.do(ctx, http.MethodPost, fmt.Sprintf("%s/repos/%s/issues/%d/assignees", base, conn.Project, number),
		conn.Credential, reqBody, nil); err != nil {
		return false, err
	}
	return true, nil
}

// currentUserLogin resolves the credential's own GitHub login via
// GET /user.
func (a *Adapter) currentUserLogin(ctx context.Context, base, token string) (string, error) {
	var u ghUser
	if err := a.get(ctx, base+"/user", token, &u); err != nil {
		return "", err
	}
	return u.Login, nil
}

// SetLabels adds and removes labels. GitHub has no single call for
// both: adding is one POST with the whole batch, removing is one
// DELETE per label (there is no batch-remove endpoint).
func (a *Adapter) SetLabels(ctx context.Context, conn tracker.Conn, number int64, add, remove []string) error {
	base := apiBase(conn.BaseURL)

	if len(add) > 0 {
		reqBody := struct {
			Labels []string `json:"labels"`
		}{Labels: add}
		if err := a.do(ctx, http.MethodPost, fmt.Sprintf("%s/repos/%s/issues/%d/labels", base, conn.Project, number),
			conn.Credential, reqBody, nil); err != nil {
			return fmt.Errorf("add labels: %w", err)
		}
	}

	for _, label := range remove {
		removeURL := fmt.Sprintf("%s/repos/%s/issues/%d/labels/%s", base, conn.Project, number, url.PathEscape(label))
		if err := a.do(ctx, http.MethodDelete, removeURL, conn.Credential, nil, nil); err != nil {
			if errors.Is(err, tracker.ErrNotFound) {
				// Already not present on the issue — same end state as
				// a successful removal, not an error.
				continue
			}
			return fmt.Errorf("remove label %q: %w", label, err)
		}
	}
	return nil
}
