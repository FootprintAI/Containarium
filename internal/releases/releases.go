// Package releases fetches the project's latest published GitHub release
// and caches it, so operators can see "a newer version is available"
// without every page load burning GitHub's unauthenticated rate limit
// (60 req/h/IP). It backs the /v1/releases/latest endpoint and the
// `containarium version --check` CLI. See issue #354.
package releases

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultLatestURL is GitHub's "latest published release" API for this repo.
const DefaultLatestURL = "https://api.github.com/repos/FootprintAI/Containarium/releases/latest"

// DefaultTTL is how long a fetched release is served from cache before the
// next upstream call. One hour keeps us far under the rate limit while
// still surfacing a new release the same operating session.
const DefaultTTL = time.Hour

// Release is the subset of GitHub's release record we surface.
type Release struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	HTMLURL     string    `json:"html_url"`
	PublishedAt time.Time `json:"published_at"`
}

// Client fetches and caches the latest release. Safe for concurrent use.
type Client struct {
	url string
	ttl time.Duration
	hc  *http.Client
	now func() time.Time

	mu        sync.Mutex
	cached    *Release
	fetchedAt time.Time
}

// Option configures a Client.
type Option func(*Client)

// WithURL overrides the upstream URL (tests point it at an httptest server).
func WithURL(u string) Option { return func(c *Client) { c.url = u } }

// WithTTL overrides the cache TTL.
func WithTTL(d time.Duration) Option { return func(c *Client) { c.ttl = d } }

// WithHTTPClient overrides the HTTP client.
func WithHTTPClient(hc *http.Client) Option { return func(c *Client) { c.hc = hc } }

// WithClock overrides the time source (tests advance it to expire the cache).
func WithClock(now func() time.Time) Option { return func(c *Client) { c.now = now } }

// NewClient builds a Client with sensible defaults.
func NewClient(opts ...Option) *Client {
	c := &Client{
		url: DefaultLatestURL,
		ttl: DefaultTTL,
		hc:  &http.Client{Timeout: 10 * time.Second},
		now: time.Now,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Latest returns the latest release. The second return value is true when
// the result was served from cache. On an upstream error a still-cached
// (stale) value is served if one exists — staleness beats a hard failure
// for a "newer version available" hint — and the error is returned only
// when there is nothing cached to fall back to.
func (c *Client) Latest(ctx context.Context) (*Release, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cached != nil && c.now().Sub(c.fetchedAt) < c.ttl {
		return c.cached, true, nil
	}

	rel, err := c.fetch(ctx)
	if err != nil {
		if c.cached != nil {
			return c.cached, true, nil // serve stale rather than fail
		}
		return nil, false, err
	}
	c.cached = rel
	c.fetchedAt = c.now()
	return rel, false, nil
}

func (c *Client) fetch(ctx context.Context) (*Release, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch latest release: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github releases API returned %d", resp.StatusCode)
	}
	var rel Release
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("decode release: %w", err)
	}
	if rel.TagName == "" {
		return nil, fmt.Errorf("release has empty tag_name")
	}
	return &rel, nil
}

// Compare returns -1, 0, or +1 as semantic version a is less than, equal
// to, or greater than b. A leading "v" and any pre-release/build suffix
// (after '-' or '+') are ignored — sufficient for this project's vX.Y.Z
// release tags. A non-numeric or missing component sorts as 0.
func Compare(a, b string) int {
	pa, pb := splitVersion(a), splitVersion(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// IsBehind reports whether current is an older release than latest.
func IsBehind(current, latest string) bool {
	return Compare(current, latest) < 0
}

// splitVersion turns "v0.22.10" / "0.22.10-rc1" into [0,22,10].
func splitVersion(s string) [3]int {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	// Drop pre-release / build metadata.
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	var out [3]int
	for i, part := range strings.SplitN(s, ".", 3) {
		if i > 2 {
			break
		}
		n, _ := strconv.Atoi(strings.TrimSpace(part))
		out[i] = n
	}
	return out
}
