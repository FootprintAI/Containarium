package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Sprint board reads, shared by `containarium sprint` and the platform MCP
// sprint tools so both go through the same functions.
//
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

// HTTPStatusError is a non-2xx REST response. Its text is the form the MCP
// client has always reported ("API error (status N): body"), so callers that
// surface it verbatim do not change.
type HTTPStatusError struct {
	Status int
	Body   string
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("API error (status %d): %s", e.Status, e.Body)
}

// IsSprintRouteMissing reports whether err is the generic route-not-found a
// standalone daemon returns for the hosted-only sprint routes: a 404 whose
// body is empty or the gateway's bare "Not Found". A 404 carrying a real
// message (for example an unknown repository) is not a missing route.
func IsSprintRouteMissing(err error) bool {
	var se *HTTPStatusError
	if !errors.As(err, &se) || se.Status != http.StatusNotFound {
		return false
	}
	body := strings.TrimSpace(se.Body)
	if body == "" {
		return true
	}
	var gw struct {
		Message string `json:"message"`
	}
	if json.Unmarshal([]byte(body), &gw) != nil {
		return strings.EqualFold(body, "404 page not found") || strings.EqualFold(body, "not found")
	}
	return gw.Message == "" || strings.EqualFold(gw.Message, "not found")
}

// SprintGet performs one authenticated GET of a REST path and returns the
// body, or an *HTTPStatusError for a non-2xx response. Each caller supplies
// its own transport and credentials.
type SprintGet func(path string) ([]byte, error)

// ListSprints lists the organization's sprints with each one's mirror state.
func ListSprints(get SprintGet, req ListSprintsRequest) ([]SprintMirror, error) {
	respBody, err := get("/v1/orgs/" + url.PathEscape(req.OrgID) + "/sprints")
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
func GetSprintBoard(get SprintGet, req GetSprintBoardRequest) (*SprintMirror, error) {
	provider := req.Provider
	if provider == "" {
		provider = TrackerProviderGitHub
	}
	q := url.Values{}
	q.Set("umbrella.provider", string(provider))
	q.Set("umbrella.project", req.Project)
	q.Set("umbrella.number", strconv.FormatInt(req.Number, 10))
	respBody, err := get("/v1/orgs/" + url.PathEscape(req.OrgID) + "/sprints/board?" + q.Encode())
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

// ListSprints lists the organization's sprints over the REST client.
func (c *HTTPClient) ListSprints(req ListSprintsRequest) ([]SprintMirror, error) {
	return ListSprints(c.sprintGet, req)
}

// GetSprintBoard reads one umbrella's mirror over the REST client.
func (c *HTTPClient) GetSprintBoard(req GetSprintBoardRequest) (*SprintMirror, error) {
	return GetSprintBoard(c.sprintGet, req)
}

func (c *HTTPClient) sprintGet(path string) ([]byte, error) {
	resp, err := c.doRequest(context.Background(), http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer drainClose(resp)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &HTTPStatusError{Status: resp.StatusCode, Body: string(body)}
	}
	return body, nil
}

// ParseSprintProvider maps the --provider / provider argument ("github", the
// default, or "gitlab") to the wire enum.
func ParseSprintProvider(s string) (TrackerProvider, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "github":
		return TrackerProviderGitHub, nil
	case "gitlab":
		return TrackerProviderGitLab, nil
	}
	return "", fmt.Errorf("provider must be \"github\" or \"gitlab\", got %q", s)
}

// SprintStateWord is the state name without its enum prefix, e.g. PRESENT.
func SprintStateWord(s SprintMirrorState) string {
	return strings.TrimPrefix(string(s), "SPRINT_MIRROR_STATE_")
}

// ErrSprintMirrorRejected marks a mirror that failed verification; callers
// treat it as a failure (non-zero exit, MCP error), unlike the other states.
var ErrSprintMirrorRejected = errors.New("sprint mirror REJECTED: the mirror comment failed verification and was not returned")

// FormatSprintBoard renders one board read for a human or an agent. PRESENT
// returns a one-line summary followed by the rendered markdown;
// NO_MIRROR_YET, NOT_ENABLED and PROVIDER_NOT_SUPPORTED are results, not
// errors; REJECTED wraps ErrSprintMirrorRejected; anything else is an error.
func FormatSprintBoard(project string, number int64, m *SprintMirror) (string, error) {
	ref := fmt.Sprintf("%s#%d", project, number)
	switch m.State {
	case SprintMirrorStatePresent:
		var b strings.Builder
		fmt.Fprintf(&b, "Sprint board %s (state: PRESENT)", ref)
		if m.Board != nil {
			fmt.Fprintf(&b, ", %d items", len(m.Board.Items))
			if m.Board.Partial {
				fmt.Fprintf(&b, ", partial: %s", m.Board.PartialReason)
			}
			if m.Board.AsOf != "" {
				fmt.Fprintf(&b, ", as of %s", m.Board.AsOf)
			}
		}
		b.WriteString("\n\n")
		b.WriteString(m.RenderedMarkdown)
		return b.String(), nil
	case SprintMirrorStateNoMirrorYet:
		return fmt.Sprintf("%s: state NO_MIRROR_YET: no board yet (it has not been written for this sprint).", ref), nil
	case SprintMirrorStateNotEnabled:
		return fmt.Sprintf("%s: state NOT_ENABLED: the sprint board is not enabled for this repository.", ref), nil
	case SprintMirrorStateProviderNotSupported:
		return fmt.Sprintf("%s: state PROVIDER_NOT_SUPPORTED: reading sprint boards is not supported yet for this tracker.", ref), nil
	case SprintMirrorStateRejected:
		return "", fmt.Errorf("%s: %w", ref, ErrSprintMirrorRejected)
	default:
		return "", fmt.Errorf("%s: unexpected sprint mirror state %q", ref, m.State)
	}
}

// FormatSprintList renders the sprint list, one line per sprint.
func FormatSprintList(sprints []SprintMirror) string {
	if len(sprints) == 0 {
		return "No sprints found (a sprint is an open issue labelled \"sprint\" on a repository that opted in)."
	}
	var b strings.Builder
	for _, s := range sprints {
		fmt.Fprintf(&b, "%s#%d  %s  [%s]\n", s.Umbrella.Project, s.Umbrella.Number, s.Title, SprintStateWord(s.State))
	}
	return b.String()
}
