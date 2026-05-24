package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// NewGitHubClient returns a GitHubAPI backed by a real
// http.Client talking to api.github.com. The CLI and MCP tool
// both use this in production; tests pass a fake instead.
//
// httpClient is allowed to be nil — we'll build one with a
// sensible timeout. Pass your own if you want a custom transport
// (e.g. tracing, retry middleware).
func NewGitHubClient(httpClient *http.Client) GitHubAPI {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &githubClient{http: httpClient}
}

type githubClient struct {
	http *http.Client
}

// runnersListResponse mirrors the shape GitHub returns from
// GET /repos/{repo}/actions/runners. We only deserialize the
// fields Provision needs — typed struct, not map[string]any,
// per CLAUDE.md.
type runnersListResponse struct {
	TotalCount int `json:"total_count"`
	Runners    []struct {
		ID     int64  `json:"id"`
		Name   string `json:"name"`
		Status string `json:"status"`
		Busy   bool   `json:"busy"`
	} `json:"runners"`
}

func (c *githubClient) ListRunners(ctx context.Context, repo, pat string) ([]RegisteredRunner, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/actions/runners", repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "token "+pat)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github list runners: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("github list runners: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var parsed runnersListResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("decode runners list: %w", err)
	}

	out := make([]RegisteredRunner, 0, len(parsed.Runners))
	for _, r := range parsed.Runners {
		out = append(out, RegisteredRunner{
			ID:     r.ID,
			Name:   r.Name,
			Status: r.Status,
			Busy:   r.Busy,
		})
	}
	return out, nil
}

func (c *githubClient) RemoveRunner(ctx context.Context, repo, pat string, runnerID int64) error {
	url := fmt.Sprintf("https://api.github.com/repos/%s/actions/runners/%d", repo, runnerID)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "token "+pat)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("github delete runner: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK:
		return nil
	case http.StatusNotFound:
		// Idempotent: a runner that's already gone is fine.
		return nil
	default:
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("github delete runner: HTTP %d: %s", resp.StatusCode, string(body))
	}
}
