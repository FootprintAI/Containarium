package mcp

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// Wire types below mirror proto/containarium/v1/tracker.proto's messages —
// see internal/mcp/wire_format_test.go's package doc for why int64 fields
// (Number) carry a `,string` tag: grpc-gateway serializes them as JSON
// strings, and a plain int64 tag silently breaks json.Unmarshal against a
// real daemon while still passing a symmetric httptest mock.

// TrackerComment mirrors proto TrackerComment.
type TrackerComment struct {
	Author    string `json:"author"`
	CreatedAt string `json:"createdAt"`
	Body      string `json:"body"`
}

// TrackerIssue mirrors proto TrackerIssue.
type TrackerIssue struct {
	Number   int64            `json:"number,string"`
	Title    string           `json:"title"`
	Body     string           `json:"body"`
	State    string           `json:"state"`
	Labels   []string         `json:"labels,omitempty"`
	Assignee string           `json:"assignee,omitempty"`
	Comments []TrackerComment `json:"comments,omitempty"`
}

// TrackerChange mirrors proto TrackerChange.
type TrackerChange struct {
	Number    int64  `json:"number,string"`
	State     string `json:"state"`
	CiVerdict string `json:"ciVerdict"`
	Url       string `json:"url,omitempty"`
	Branch    string `json:"branch,omitempty"`
}

// GetTrackerIssueRequest's Username/Connection/Number are path-bound
// (json:"-") — they ride the URL, never the body, same convention as
// AddCollaboratorRequest.OwnerUsername.
type GetTrackerIssueRequest struct {
	Username   string `json:"-"`
	Connection string `json:"-"`
	Number     int64  `json:"-"`
}

type getTrackerIssueResponse struct {
	Issue TrackerIssue `json:"issue"`
}

// GetTrackerIssue reads a single issue, including its comments.
func (c *Client) GetTrackerIssue(req GetTrackerIssueRequest) (*TrackerIssue, error) {
	path := fmt.Sprintf("/v1/tracker/%s/%s/issues/%d",
		url.PathEscape(req.Username), url.PathEscape(req.Connection), req.Number)
	respBody, err := c.doRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}
	var resp getTrackerIssueResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	return &resp.Issue, nil
}

// ListTrackerIssuesRequest's filters are all optional; zero-value skips
// them. State is the CLI-style lowercase name ("open"/"closed") — this
// converts it to the wire enum name, same normalization
// ListSecuritySentryFindings applies to its own enum filters.
type ListTrackerIssuesRequest struct {
	Username   string
	Connection string
	State      string
	Labels     []string
	Search     string
}

type listTrackerIssuesResponse struct {
	Issues []TrackerIssue `json:"issues"`
}

// ListTrackerIssues enumerates issues, optionally filtered.
func (c *Client) ListTrackerIssues(req ListTrackerIssuesRequest) ([]TrackerIssue, error) {
	q := url.Values{}
	if req.State != "" {
		q.Set("state", "TRACKER_ISSUE_STATE_"+strings.ToUpper(req.State))
	}
	for _, l := range req.Labels {
		q.Add("labels", l)
	}
	if req.Search != "" {
		q.Set("search", req.Search)
	}
	path := fmt.Sprintf("/v1/tracker/%s/%s/issues", url.PathEscape(req.Username), url.PathEscape(req.Connection))
	if enc := q.Encode(); enc != "" {
		path += "?" + enc
	}
	respBody, err := c.doRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}
	var resp listTrackerIssuesResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	return resp.Issues, nil
}

// GetTrackerChangeRequest's fields are path-bound, same as GetTrackerIssueRequest.
type GetTrackerChangeRequest struct {
	Username   string `json:"-"`
	Connection string `json:"-"`
	Number     int64  `json:"-"`
}

type getTrackerChangeResponse struct {
	Change TrackerChange `json:"change"`
}

// GetTrackerChange reads a single change request's state and CI verdict.
func (c *Client) GetTrackerChange(req GetTrackerChangeRequest) (*TrackerChange, error) {
	path := fmt.Sprintf("/v1/tracker/%s/%s/changes/%d",
		url.PathEscape(req.Username), url.PathEscape(req.Connection), req.Number)
	respBody, err := c.doRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}
	var resp getTrackerChangeResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	return &resp.Change, nil
}

// CommentOnTrackerIssueRequest. Username/Connection/Number are path-bound;
// Body rides the JSON body.
type CommentOnTrackerIssueRequest struct {
	Username   string `json:"-"`
	Connection string `json:"-"`
	Number     int64  `json:"-"`
	Body       string `json:"body"`
}

type commentOnTrackerIssueResponse struct {
	Comment TrackerComment `json:"comment"`
}

// CommentOnTrackerIssue posts a stamped, sanitized comment.
func (c *Client) CommentOnTrackerIssue(req CommentOnTrackerIssueRequest) (*TrackerComment, error) {
	path := fmt.Sprintf("/v1/tracker/%s/%s/issues/%d/comments",
		url.PathEscape(req.Username), url.PathEscape(req.Connection), req.Number)
	respBody, err := c.doRequest("POST", path, struct {
		Body string `json:"body"`
	}{Body: req.Body})
	if err != nil {
		return nil, err
	}
	var resp commentOnTrackerIssueResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	return &resp.Comment, nil
}

// ClaimTrackerIssueRequest. StaleAfterSeconds 0 uses the daemon's default.
type ClaimTrackerIssueRequest struct {
	Username          string `json:"-"`
	Connection        string `json:"-"`
	Number            int64  `json:"-"`
	StaleAfterSeconds int64  `json:"staleAfterSeconds,omitempty"`
}

// ClaimTrackerIssueResult mirrors proto ClaimTrackerIssueResponse.
type ClaimTrackerIssueResult struct {
	Claimed               bool   `json:"claimed"`
	AlreadyClaimedByRunID string `json:"alreadyClaimedByRunId,omitempty"`
	Assigned              bool   `json:"assigned"`
}

// ClaimTrackerIssue attempts to claim an issue for the calling run.
func (c *Client) ClaimTrackerIssue(req ClaimTrackerIssueRequest) (*ClaimTrackerIssueResult, error) {
	path := fmt.Sprintf("/v1/tracker/%s/%s/issues/%d/claim",
		url.PathEscape(req.Username), url.PathEscape(req.Connection), req.Number)
	respBody, err := c.doRequest("POST", path, struct {
		StaleAfterSeconds int64 `json:"staleAfterSeconds,omitempty"`
	}{StaleAfterSeconds: req.StaleAfterSeconds})
	if err != nil {
		return nil, err
	}
	var resp ClaimTrackerIssueResult
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	return &resp, nil
}

// SetTrackerIssueLabelsRequest. At least one of AddLabels/RemoveLabels
// must be non-empty (the daemon rejects an empty request).
type SetTrackerIssueLabelsRequest struct {
	Username     string   `json:"-"`
	Connection   string   `json:"-"`
	Number       int64    `json:"-"`
	AddLabels    []string `json:"addLabels,omitempty"`
	RemoveLabels []string `json:"removeLabels,omitempty"`
}

// SetTrackerIssueLabels adds and/or removes labels on an issue.
func (c *Client) SetTrackerIssueLabels(req SetTrackerIssueLabelsRequest) error {
	path := fmt.Sprintf("/v1/tracker/%s/%s/issues/%d/labels",
		url.PathEscape(req.Username), url.PathEscape(req.Connection), req.Number)
	_, err := c.doRequest("POST", path, struct {
		AddLabels    []string `json:"addLabels,omitempty"`
		RemoveLabels []string `json:"removeLabels,omitempty"`
	}{AddLabels: req.AddLabels, RemoveLabels: req.RemoveLabels})
	return err
}

// SubmitTrackerChangeRequest (#1923). Username/Connection are path-bound;
// Issue/Title/Description/Draft ride the JSON body. No remote, no
// target ref, and no credential — the daemon resolves all three from
// the run's own JWT and the connection record. See
// docs/architecture/agent-tracker-broker.md's "Submit path".
type SubmitTrackerChangeRequest struct {
	Username    string `json:"-"`
	Connection  string `json:"-"`
	Issue       int64  `json:"issue"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Draft       bool   `json:"draft,omitempty"`
}

type submitTrackerChangeResponse struct {
	Change TrackerChange `json:"change"`
}

// SubmitTrackerChange bundles the calling run's committed workspace out
// of its box, pushes it, and opens a change request.
func (c *Client) SubmitTrackerChange(req SubmitTrackerChangeRequest) (*TrackerChange, error) {
	path := fmt.Sprintf("/v1/tracker/%s/%s/changes", url.PathEscape(req.Username), url.PathEscape(req.Connection))
	respBody, err := c.doRequest("POST", path, struct {
		Issue       int64  `json:"issue"`
		Title       string `json:"title"`
		Description string `json:"description,omitempty"`
		Draft       bool   `json:"draft,omitempty"`
	}{Issue: req.Issue, Title: req.Title, Description: req.Description, Draft: req.Draft})
	if err != nil {
		return nil, err
	}
	var resp submitTrackerChangeResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	return &resp.Change, nil
}
