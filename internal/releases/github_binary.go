package releases

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// GitHubReleaseBaseURL is the root of GitHub's release-asset download URLs
// for this repo, shared by every caller that fetches a release binary
// directly from GitHub (#1028) — as opposed to via the sentinel's own
// fetch-release proxy, which mirrors this same layout independently
// (internal/sentinel/selfupdate.go) since that package stays self-contained
// by design. A var, not a const, so tests can point it at an httptest
// server (matches this codebase's established pattern for otherwise-fixed
// values a test needs to override, e.g. ossprimary's sentinelAdminBinaryPort).
var GitHubReleaseBaseURL = "https://github.com/FootprintAI/Containarium/releases/download"

// BinaryDownloadURL returns the direct GitHub download URL for binaryName at
// the given release tag.
func BinaryDownloadURL(tag, binaryName string) string {
	return GitHubReleaseBaseURL + "/" + tag + "/" + binaryName
}

// FetchSHA256 downloads SHA256SUMS.txt from the given GitHub release tag and
// returns the checksum for binaryName. SHA256SUMS.txt is GNU sha256sum
// format: "<hash>  <filename>" (two spaces), one line per released asset.
func FetchSHA256(ctx context.Context, tag, binaryName string) (string, error) {
	sumsURL := GitHubReleaseBaseURL + "/" + tag + "/SHA256SUMS.txt"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sumsURL, nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch %s: %w", sumsURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d from %s", resp.StatusCode, sumsURL)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", sumsURL, err)
	}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		name := strings.TrimPrefix(fields[1], "./")
		if name == binaryName {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("%q not found in %s", binaryName, sumsURL)
}
