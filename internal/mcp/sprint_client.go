package mcp

import "github.com/footprintai/containarium/internal/client"

// The sprint wire types and the read functions live in internal/client so the
// `containarium sprint` CLI and these MCP tools share one implementation.
// These aliases keep the mcp package's API unchanged.
type (
	SprintMirrorState     = client.SprintMirrorState
	TrackerProvider       = client.TrackerProvider
	SprintIssueRef        = client.SprintIssueRef
	SprintItem            = client.SprintItem
	SprintBoard           = client.SprintBoard
	SprintMirror          = client.SprintMirror
	ListSprintsRequest    = client.ListSprintsRequest
	GetSprintBoardRequest = client.GetSprintBoardRequest
)

const (
	SprintMirrorStatePresent              = client.SprintMirrorStatePresent
	SprintMirrorStateNoMirrorYet          = client.SprintMirrorStateNoMirrorYet
	SprintMirrorStateRejected             = client.SprintMirrorStateRejected
	SprintMirrorStateNotEnabled           = client.SprintMirrorStateNotEnabled
	SprintMirrorStateProviderNotSupported = client.SprintMirrorStateProviderNotSupported
	TrackerProviderGitHub                 = client.TrackerProviderGitHub
	TrackerProviderGitLab                 = client.TrackerProviderGitLab
)

// ListSprints lists the organization's sprints with each one's mirror state.
func (c *Client) ListSprints(req ListSprintsRequest) ([]SprintMirror, error) {
	return client.ListSprints(c.sprintGet, req)
}

// GetSprintBoard reads the board in one umbrella's mirror. A missing mirror
// is a result (state NO_MIRROR_YET), not an error.
func (c *Client) GetSprintBoard(req GetSprintBoardRequest) (*SprintMirror, error) {
	return client.GetSprintBoard(c.sprintGet, req)
}

func (c *Client) sprintGet(path string) ([]byte, error) {
	return c.doRequest("GET", path, nil)
}
