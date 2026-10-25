package mcp

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
)

// Sprint board reads. The board is a mirror a hosted control plane keeps on
// each sprint umbrella issue; these calls read it, never compute it. The
// routes exist only on a hosted control plane, so against a standalone
// daemon they come back as a plain not-found API error.

// SprintMirrorState says what reading one umbrella's mirror found. The values
// are the enum names the REST gateway emits.
type SprintMirrorState string

const (
	SprintMirrorStatePresent              SprintMirrorState = "SPRINT_MIRROR_STATE_PRESENT"
	SprintMirrorStateNoMirrorYet          SprintMirrorState = "SPRINT_MIRROR_STATE_NO_MIRROR_YET"
	SprintMirrorStateRejected             SprintMirrorState = "SPRINT_MIRROR_STATE_REJECTED"
	SprintMirrorStateNotEnabled           SprintMirrorState = "SPRINT_MIRROR_STATE_NOT_ENABLED"
	SprintMirrorStateProviderNotSupported SprintMirrorState = "SPRINT_MIRROR_STATE_PROVIDER_NOT_SUPPORTED"
)

// TrackerProvider is the umbrella's tracker, as the REST gateway names it.
type TrackerProvider string

const (
	TrackerProviderGitHub TrackerProvider = "TRACKER_PROVIDER_GITHUB"
	TrackerProviderGitLab TrackerProvider = "TRACKER_PROVIDER_GITLAB"
)

// SprintIssueRef addresses a sprint by its umbrella issue. Number is an int64
// on the wire, which the gateway serializes as a JSON string.
type SprintIssueRef struct {
	Provider TrackerProvider `json:"provider"`
	Project  string          `json:"project"`
	Number   int64           `json:"number,string"`
}

// SprintItem is one issue on a board.
type SprintItem struct {
	Number       int64   `json:"number,string"`
	Title        string  `json:"title"`
	URL          string  `json:"url,omitempty"`
	Rank         int32   `json:"rank,omitempty"`
	State        string  `json:"state"`
	Blockers     []int64 `json:"blockers,omitempty"`
	OpenBlockers []int64 `json:"openBlockers,omitempty"`
	RunStatus    string  `json:"runStatus,omitempty"`
	// RunStartedAt and WaitSince are RFC 3339 timestamps, empty when unset.
	RunStartedAt string   `json:"runStartedAt,omitempty"`
	WaitSince    string   `json:"waitSince,omitempty"`
	PRURL        string   `json:"prUrl,omitempty"`
	PRState      string   `json:"prState,omitempty"`
	Attention    []string `json:"attention,omitempty"`
	Note         string   `json:"note,omitempty"`
}

// UnmarshalJSON accepts the gateway's encoding of repeated int64 fields, which
// is an array of JSON strings (",string" only covers scalar fields).
func (i *SprintItem) UnmarshalJSON(data []byte) error {
	type plain SprintItem
	aux := struct {
		*plain
		Blockers     []json.Number `json:"blockers"`
		OpenBlockers []json.Number `json:"openBlockers"`
		Number       json.Number   `json:"number"`
	}{plain: (*plain)(i)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	var err error
	if aux.Number != "" {
		if i.Number, err = strconv.ParseInt(aux.Number.String(), 10, 64); err != nil {
			return fmt.Errorf("sprint item number: %w", err)
		}
	}
	if i.Blockers, err = parseInt64s(aux.Blockers); err != nil {
		return err
	}
	i.OpenBlockers, err = parseInt64s(aux.OpenBlockers)
	return err
}

func parseInt64s(in []json.Number) ([]int64, error) {
	var out []int64
	for _, n := range in {
		v, err := strconv.ParseInt(n.String(), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("sprint item issue number %q: %w", n, err)
		}
		out = append(out, v)
	}
	return out, nil
}

// SprintBoard is the typed board. Set only when the state is PRESENT.
type SprintBoard struct {
	SprintID           string       `json:"sprintId,omitempty"`
	Provider           string       `json:"provider,omitempty"`
	ContentHash        string       `json:"contentHash,omitempty"`
	Project            string       `json:"project"`
	Umbrella           int64        `json:"umbrella,string"`
	UmbrellaTitle      string       `json:"umbrellaTitle"`
	AsOf               string       `json:"asOf,omitempty"`
	MergeLagSeconds    int32        `json:"mergeLagSeconds,omitempty"`
	Items              []SprintItem `json:"items,omitempty"`
	RankEditUnverified bool         `json:"rankEditUnverified,omitempty"`
	Partial            bool         `json:"partial,omitempty"`
	PartialReason      string       `json:"partialReason,omitempty"`
}

// SprintMirror is the result of reading one umbrella's mirror.
type SprintMirror struct {
	Umbrella         SprintIssueRef    `json:"umbrella"`
	Title            string            `json:"title,omitempty"`
	State            SprintMirrorState `json:"state"`
	Board            *SprintBoard      `json:"board,omitempty"`
	RenderedMarkdown string            `json:"renderedMarkdown,omitempty"`
}

// ListSprintsRequest names the organization whose sprints to list.
type ListSprintsRequest struct {
	OrgID string
}

// GetSprintBoardRequest addresses one umbrella. Provider defaults to GitHub.
type GetSprintBoardRequest struct {
	OrgID    string
	Provider TrackerProvider
	Project  string
	Number   int64
}

// ListSprints lists the organization's sprints with each one's mirror state.
func (c *Client) ListSprints(req ListSprintsRequest) ([]SprintMirror, error) {
	respBody, err := c.doRequest("GET", "/v1/orgs/"+url.PathEscape(req.OrgID)+"/sprints", nil)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Sprints []SprintMirror `json:"sprints"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	return resp.Sprints, nil
}

// GetSprintBoard reads the board in one umbrella's mirror. A missing mirror
// is a result (state NO_MIRROR_YET), not an error.
func (c *Client) GetSprintBoard(req GetSprintBoardRequest) (*SprintMirror, error) {
	provider := req.Provider
	if provider == "" {
		provider = TrackerProviderGitHub
	}
	q := url.Values{}
	q.Set("umbrella.provider", string(provider))
	q.Set("umbrella.project", req.Project)
	q.Set("umbrella.number", strconv.FormatInt(req.Number, 10))
	path := "/v1/orgs/" + url.PathEscape(req.OrgID) + "/sprints/board?" + q.Encode()
	respBody, err := c.doRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Mirror SprintMirror `json:"mirror"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	return &resp.Mirror, nil
}
