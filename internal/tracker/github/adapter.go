// Package github translates internal/tracker's provider-neutral verbs to
// the GitHub REST API. stdlib net/http, no SDK dependency — precedent:
// internal/runner/github.go. #1921 lands only DescribeCredential; the
// read/write verbs (GetIssue, Comment, OpenChange, …) are #1922/#1923.
package github

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/tracker"
)

// defaultAPIBase is github.com's REST API root. GitHub Enterprise Server
// uses <host>/api/v3 instead — callers set Conn.BaseURL to that when
// connecting to a self-managed instance.
const defaultAPIBase = "https://api.github.com"

// Adapter talks to the GitHub REST API.
type Adapter struct {
	http *http.Client
}

var _ tracker.CredentialDescriber = (*Adapter)(nil)

// New returns an Adapter. A nil httpClient gets a sensible default
// timeout; pass your own for custom transport (tracing, retries).
func New(httpClient *http.Client) *Adapter {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &Adapter{http: httpClient}
}

// DescribeCredential reports what the credential can do, per the design
// note's "Preferred credential types" table: GitHub App installation
// tokens and single-repository fine-grained PATs are preferred; classic
// PATs (and anything else) are broad.
//
// Breadth is classified from the token's own prefix — a GitHub
// convention stable across API versions (ghp_ classic, github_pat_
// fine-grained, ghs_ App installation, gho_/ghu_ OAuth) — so it needs no
// network round trip and degrades to BreadthBroad (never a false
// "preferred") for anything unrecognized, e.g. a GitHub Enterprise
// Server token predating the prefix convention.
//
// Expiry: GitHub does not expose a classic or fine-grained PAT's expiry
// through any endpoint the credential itself can call — only through the
// account-settings surface a human owner reaches by signing in, which
// this adapter has no reason to touch. Installation tokens are minted
// with a fixed ~1h lifetime the daemon would need to have recorded at
// mint time; describing one after the fact can't recover that either.
// ExpiresAt is therefore always zero from this adapter — "unknown," not
// "never expires."
func (a *Adapter) DescribeCredential(ctx context.Context, conn tracker.Conn) (tracker.CredentialInfo, error) {
	base := strings.TrimRight(conn.BaseURL, "/")
	if base == "" {
		base = defaultAPIBase
	}
	breadth := breadthFromTokenPrefix(conn.Credential)

	if strings.HasPrefix(conn.Credential, "ghs_") {
		// Installation tokens aren't tied to a user identity — /user
		// unconditionally 403s for them. /rate_limit is the one
		// endpoint every credential type can call with no scope
		// requirement, so it's the reachability+validity probe here.
		if err := a.probeRateLimit(ctx, base, conn.Credential); err != nil {
			return tracker.CredentialInfo{Breadth: breadth}, err
		}
		return tracker.CredentialInfo{Breadth: breadth}, nil
	}

	scopes, err := a.describeViaUser(ctx, base, conn.Credential)
	if err != nil {
		return tracker.CredentialInfo{Breadth: breadth}, err
	}
	return tracker.CredentialInfo{Scopes: scopes, Breadth: breadth}, nil
}

// breadthFromTokenPrefix classifies a GitHub credential by its
// documented prefix, never by guessing from behavior.
func breadthFromTokenPrefix(token string) tracker.CredentialBreadth {
	switch {
	case strings.HasPrefix(token, "github_pat_"), strings.HasPrefix(token, "ghs_"):
		return tracker.BreadthPreferred
	default:
		// ghp_ (classic PAT), gho_/ghu_ (OAuth), or an unrecognized
		// shape (e.g. a pre-prefix-convention GHES token) — treat as
		// broad. A false "broad" only produces an extra warning; a
		// false "preferred" would hide a real one.
		return tracker.BreadthBroad
	}
}

func (a *Adapter) describeViaUser(ctx context.Context, base, token string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/user", nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	setHeaders(req, token)

	resp, err := a.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", tracker.ErrUnreachable, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return splitScopes(resp.Header.Get("X-OAuth-Scopes")), nil
	case http.StatusUnauthorized, http.StatusForbidden:
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%w: HTTP %d: %s", tracker.ErrCredentialInvalid, resp.StatusCode, string(body))
	default:
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("github describe credential: HTTP %d: %s", resp.StatusCode, string(body))
	}
}

func (a *Adapter) probeRateLimit(ctx context.Context, base, token string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/rate_limit", nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	setHeaders(req, token)

	resp, err := a.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", tracker.ErrUnreachable, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%w: HTTP %d: %s", tracker.ErrCredentialInvalid, resp.StatusCode, string(body))
	default:
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("github describe credential: HTTP %d: %s", resp.StatusCode, string(body))
	}
}

func setHeaders(req *http.Request, token string) {
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
}

// splitScopes parses the X-OAuth-Scopes header ("repo, read:org") into
// its scope list. Returns nil (not empty-non-nil) for a missing/empty
// header — a fine-grained PAT or installation token never sets it, and
// nil vs "explicitly no scopes granted" ([]string{}) is a real
// distinction the design note's "unknown, not zero" framing cares about.
func splitScopes(header string) []string {
	if strings.TrimSpace(header) == "" {
		return nil
	}
	parts := strings.Split(header, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
