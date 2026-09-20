package gitlab

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/footprintai/containarium/internal/tracker"
)

var _ tracker.Provider = (*Adapter)(nil)

// draftTitlePrefix marks a merge request as draft/WIP. GitLab has no
// dedicated boolean field for this on the create-MR endpoint (unlike
// GitHub's `draft`); the documented, UI-recognized mechanism is this
// title prefix.
const draftTitlePrefix = "Draft: "

// OpenChange opens a merge request from req.HeadBranch onto
// req.BaseBranch. req.Description is used as-is — the closing
// reference and platform-stamped signature are the caller's
// responsibility to have already composed into it.
func (a *Adapter) OpenChange(ctx context.Context, conn tracker.Conn, req tracker.OpenChangeRequest) (tracker.Change, error) {
	apiBase := apiBaseURL(conn.BaseURL)
	projectPath := url.PathEscape(conn.Project)

	title := req.Title
	if req.Draft && !strings.HasPrefix(title, draftTitlePrefix) {
		title = draftTitlePrefix + title
	}

	reqBody := struct {
		SourceBranch string `json:"source_branch"`
		TargetBranch string `json:"target_branch"`
		Title        string `json:"title"`
		Description  string `json:"description"`
	}{
		SourceBranch: req.HeadBranch,
		TargetBranch: req.BaseBranch,
		Title:        title,
		Description:  req.Description,
	}

	var mr glMergeRequest
	if err := a.do(ctx, http.MethodPost, fmt.Sprintf("%s/projects/%s/merge_requests", apiBase, projectPath),
		conn.Credential, reqBody, &mr); err != nil {
		return tracker.Change{}, err
	}

	return tracker.Change{
		Number: mr.IID,
		State:  mergeRequestStateToTracker(mr.State),
		// A freshly opened MR has no pipeline yet; pipelineToVerdict(nil)
		// already returns NONE — the same call GetChange makes, kept
		// consistent rather than hardcoding the enum value here too.
		CIVerdict: pipelineToVerdict(mr.HeadPipeline),
		URL:       mr.WebURL,
		Branch:    req.HeadBranch,
	}, nil
}

// glProject mirrors the subset of GET /projects/{id} DefaultBranch needs.
type glProject struct {
	DefaultBranch string `json:"default_branch"`
}

// DefaultBranch resolves the project's actual default branch from
// GitLab itself, never guessed.
func (a *Adapter) DefaultBranch(ctx context.Context, conn tracker.Conn) (string, error) {
	apiBase := apiBaseURL(conn.BaseURL)
	var proj glProject
	if err := a.get(ctx, fmt.Sprintf("%s/projects/%s", apiBase, url.PathEscape(conn.Project)), conn.Credential, &proj); err != nil {
		return "", err
	}
	if proj.DefaultBranch == "" {
		return "", fmt.Errorf("gitlab: %s reports no default branch", conn.Project)
	}
	return proj.DefaultBranch, nil
}
