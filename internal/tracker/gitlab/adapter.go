// Package gitlab translates internal/tracker's provider-neutral verbs to
// the GitLab REST API (v4). stdlib net/http, no SDK dependency. #1921
// lands only DescribeCredential; the read/write verbs are #1922/#1923.
package gitlab

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/tracker"
)

// defaultBaseURL is gitlab.com's site root (not the API root — API()
// appends /api/v4). Self-managed GitLab sets Conn.BaseURL to the
// instance's site root the same way.
const defaultBaseURL = "https://gitlab.com"

// apiDateLayout is the date-only format GitLab returns for a PAT's
// expires_at ("2027-01-01") — access tokens expire at day granularity,
// not a specific time.
const apiDateLayout = "2006-01-02"

// Adapter talks to the GitLab REST API v4.
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
// note's "Preferred credential types" table: a GitLab project access
// token is preferred; a group or personal access token is broad.
//
// Unlike GitHub, GitLab's own introspection endpoint
// (personal_access_tokens/self) reports scopes AND expiry in one call —
// project and group access tokens are implemented as PATs under a bot
// user, so the same endpoint covers all three credential shapes. Breadth
// needs a second call (GET /user) to tell a project/group bot account
// from a real personal one; if that second call fails, DescribeCredential
// still succeeds with BreadthUnspecified rather than discarding the
// scopes/expiry it already has.
func (a *Adapter) DescribeCredential(ctx context.Context, conn tracker.Conn) (tracker.CredentialInfo, error) {
	base := strings.TrimSuffix(conn.BaseURL, "/")
	if base == "" {
		base = defaultBaseURL
	}
	apiBase := base
	if !strings.HasSuffix(apiBase, "/api/v4") {
		apiBase += "/api/v4"
	}

	info, err := a.describeSelf(ctx, apiBase, conn.Credential)
	if err != nil {
		return tracker.CredentialInfo{}, err
	}

	// Breadth is best-effort on top of an already-successful describe —
	// a scope narrow enough to read the token's own metadata but not
	// call /user must not turn a successful describe into an error.
	info.Breadth = a.classifyBreadth(ctx, apiBase, conn.Credential)
	return info, nil
}

// patSelfResponse mirrors GET /personal_access_tokens/self. Named
// response struct, not map[string]interface{}, per CLAUDE.md.
type patSelfResponse struct {
	Active    bool     `json:"active"`
	Revoked   bool     `json:"revoked"`
	Scopes    []string `json:"scopes"`
	ExpiresAt *string  `json:"expires_at"`
}

func (a *Adapter) describeSelf(ctx context.Context, apiBase, token string) (tracker.CredentialInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/personal_access_tokens/self", nil)
	if err != nil {
		return tracker.CredentialInfo{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("PRIVATE-TOKEN", token)

	resp, err := a.http.Do(req)
	if err != nil {
		return tracker.CredentialInfo{}, fmt.Errorf("%w: %v", tracker.ErrUnreachable, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var parsed patSelfResponse
		if derr := json.NewDecoder(resp.Body).Decode(&parsed); derr != nil {
			return tracker.CredentialInfo{}, fmt.Errorf("decode personal_access_tokens/self: %w", derr)
		}
		if parsed.Revoked || !parsed.Active {
			return tracker.CredentialInfo{}, fmt.Errorf("%w: token is revoked or inactive", tracker.ErrCredentialInvalid)
		}
		var expires time.Time
		if parsed.ExpiresAt != nil {
			if t, perr := time.Parse(apiDateLayout, *parsed.ExpiresAt); perr == nil {
				expires = t
			}
			// A malformed date is treated as "unknown" (zero), not an
			// error — the credential itself already checked out above.
		}
		return tracker.CredentialInfo{Scopes: parsed.Scopes, ExpiresAt: expires}, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		body, _ := io.ReadAll(resp.Body)
		return tracker.CredentialInfo{}, fmt.Errorf("%w: HTTP %d: %s", tracker.ErrCredentialInvalid, resp.StatusCode, string(body))
	default:
		body, _ := io.ReadAll(resp.Body)
		return tracker.CredentialInfo{}, fmt.Errorf("gitlab describe credential: HTTP %d: %s", resp.StatusCode, string(body))
	}
}

// userResponse mirrors the fields of GET /user this adapter needs.
type userResponse struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Bot      bool   `json:"bot"`
}

// classifyBreadth tells a project/group access token's bot account from
// a real personal one. GitLab's project and group access tokens are
// PATs owned by a bot user whose username is machine-generated with a
// documented prefix ("project_<id>_bot..." / "group_<id>_bot...");
// anything else (bot=false, or an unrecognized bot username shape) is
// treated as broad — never a false "preferred".
func (a *Adapter) classifyBreadth(ctx context.Context, apiBase, token string) tracker.CredentialBreadth {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/user", nil)
	if err != nil {
		return tracker.BreadthUnspecified
	}
	req.Header.Set("PRIVATE-TOKEN", token)

	resp, err := a.http.Do(req)
	if err != nil {
		return tracker.BreadthUnspecified
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return tracker.BreadthUnspecified
	}

	var parsed userResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return tracker.BreadthUnspecified
	}
	if !parsed.Bot {
		return tracker.BreadthBroad // a real personal account's own PAT
	}
	if strings.HasPrefix(parsed.Username, "project_") {
		return tracker.BreadthPreferred
	}
	return tracker.BreadthBroad // group_<id>_bot… or an unrecognized bot shape
}
