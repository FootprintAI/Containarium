// Package releasecheck reports the latest Containarium release published on
// GitHub, cached server-side so a busy fleet's status checks don't burn the
// unauthenticated GitHub rate limit (~60/hr). Used to surface "newer version
// available" next to each backend's running version (#354).
package releasecheck

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/blang/semver/v4"
)

const (
	// DefaultOwner / DefaultRepo identify the Containarium repo on GitHub.
	DefaultOwner = "FootprintAI"
	DefaultRepo  = "Containarium"

	// DefaultTTL is how long a fetched tag is served before refetching.
	DefaultTTL = time.Hour
)

// Checker fetches and caches the latest release tag. Safe for concurrent use.
type Checker struct {
	owner   string
	repo    string
	baseURL string // overridable in tests; defaults to the GitHub API
	client  *http.Client
	ttl     time.Duration
	now     func() time.Time

	mu       sync.Mutex
	cached   string
	cachedAt time.Time
	hasCache bool
}

// New returns a Checker for the Containarium repo with sensible defaults.
func New() *Checker {
	return &Checker{
		owner:   DefaultOwner,
		repo:    DefaultRepo,
		baseURL: "https://api.github.com",
		client:  &http.Client{Timeout: 10 * time.Second},
		ttl:     DefaultTTL,
		now:     time.Now,
	}
}

// Latest returns the latest release tag (e.g. "v0.21.2"), cached for the TTL.
//
// Best-effort by design: on a fetch error it serves the last good value if
// one was ever cached (stale beats nothing for a status panel), and only
// returns an error when there's no cache to fall back on. Callers that just
// want drift info can ignore the error and use the (possibly empty) string.
func (c *Checker) Latest(ctx context.Context) (string, error) {
	c.mu.Lock()
	if c.hasCache && c.now().Sub(c.cachedAt) < c.ttl {
		v := c.cached
		c.mu.Unlock()
		return v, nil
	}
	c.mu.Unlock()

	tag, err := c.fetch(ctx)
	if err != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.hasCache {
			return c.cached, nil // serve stale
		}
		return "", err
	}

	c.mu.Lock()
	c.cached = tag
	c.cachedAt = c.now()
	c.hasCache = true
	c.mu.Unlock()
	return tag, nil
}

// githubRelease is the subset of the GitHub releases API we read.
type githubRelease struct {
	TagName string `json:"tag_name"`
}

func (c *Checker) fetch(ctx context.Context) (string, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/releases/latest", c.baseURL, c.owner, c.repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch latest release: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("github API status %d: %s", resp.StatusCode, string(body))
	}
	var rel githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", fmt.Errorf("decode release: %w", err)
	}
	if rel.TagName == "" {
		return "", fmt.Errorf("latest release has no tag_name")
	}
	return rel.TagName, nil
}

// UpdateAvailable reports whether latest is a newer semver than current.
// Tolerant of a leading "v" on either; returns false on empty or unparseable
// input (a status panel should not claim "update available" on bad data).
func UpdateAvailable(current, latest string) bool {
	cv, err1 := semver.ParseTolerant(current)
	lv, err2 := semver.ParseTolerant(latest)
	if err1 != nil || err2 != nil {
		return false
	}
	return cv.LT(lv)
}
