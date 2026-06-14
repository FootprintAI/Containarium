package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/releasecheck"
	"github.com/spf13/cobra"
)

var backendsVersionsFormat string

var backendsVersionsCmd = &cobra.Command{
	Use:   "versions",
	Short: "Show the daemon version of every backend vs the latest release",
	Long: `Show a cluster-wide version overview: the daemon version running on the
local daemon and each tunnel peer, the latest published GitHub release, and a
per-backend status (current / behind) so drift is visible at a glance.

Composes the existing /v1/backends (per-backend version) and /v1/releases/latest
(cached GitHub lookup) endpoints — both HTTP-only and admin-authenticated, so
this command requires --server pointing at the daemon's HTTP address. See #354.`,
	Aliases: []string{"version", "ver"},
	RunE:    runBackendsVersions,
}

func init() {
	backendsCmd.AddCommand(backendsVersionsCmd)
	backendsVersionsCmd.Flags().StringVarP(&backendsVersionsFormat, "format", "f", "table",
		"Output format: table, json")
}

// latestReleaseResponse mirrors the /v1/releases/latest (GetLatestRelease)
// response shape (camelCase from grpc-gateway). Kept local so a server-side
// schema change surfaces as a decode failure here, not a silent field-drop.
type latestReleaseResponse struct {
	LatestRelease   string `json:"latestRelease"`
	CurrentVersion  string `json:"currentVersion"`
	UpdateAvailable bool   `json:"updateAvailable"`
}

// backendVersionRow is the rendered per-backend version line.
type backendVersionRow struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Healthy bool   `json:"healthy"`
	Version string `json:"version"`
	Status  string `json:"status"` // current | behind | dev | unknown
}

type backendsVersionsOutput struct {
	LatestRelease string              `json:"latestRelease"`
	Backends      []backendVersionRow `json:"backends"`
}

// backendVersionStatus classifies a backend's version against the latest
// published release. "behind" when the latest is a newer semver; "current"
// when equal or ahead; "dev" for an unversioned dev build; "unknown" when
// either side is missing or unparseable.
func backendVersionStatus(current, latest string) string {
	if current == "" {
		return "unknown"
	}
	if current == "dev" {
		return "dev"
	}
	if latest == "" {
		return "unknown"
	}
	if releasecheck.UpdateAvailable(current, latest) {
		return "behind"
	}
	return "current"
}

func runBackendsVersions(cmd *cobra.Command, args []string) error {
	// Backend version / release checks are operator-owned on the hosted
	// control plane (the platform keeps it current) — refuse client-side (#456).
	if isCloudTarget(serverAddr, authToken) {
		return errUnsupportedOnCloud("backends versions", "the platform keeps the control plane current")
	}
	if serverAddr == "" {
		return fmt.Errorf("--server is required (the platform daemon's HTTP address, e.g. http://host:8080)")
	}
	base := strings.TrimSuffix(serverAddr, "/")

	var backendsResp backendsListResponse
	if err := getJSON(base+"/v1/backends", &backendsResp); err != nil {
		return fmt.Errorf("fetch backends: %w", err)
	}

	// Latest-release lookup is best-effort: a rate-limited / offline daemon
	// still gives us the version table, just without the "behind" column.
	var latest latestReleaseResponse
	if err := getJSON(base+"/v1/releases/latest", &latest); err != nil {
		fmt.Printf("Warning: could not fetch latest release (%v); status column will read 'unknown'\n", err)
	}

	rows := make([]backendVersionRow, 0, len(backendsResp.Backends))
	for _, b := range backendsResp.Backends {
		rows = append(rows, backendVersionRow{
			ID:      b.ID,
			Type:    b.Type,
			Healthy: b.Healthy,
			Version: b.Version,
			Status:  backendVersionStatus(b.Version, latest.LatestRelease),
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })

	if backendsVersionsFormat == "json" {
		out := backendsVersionsOutput{LatestRelease: latest.LatestRelease, Backends: rows}
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}

	w := cmd.OutOrStdout()
	if latest.LatestRelease != "" {
		fmt.Fprintf(w, "Latest release: %s\n\n", latest.LatestRelease)
	} else {
		fmt.Fprintf(w, "Latest release: (unavailable)\n\n")
	}
	fmt.Fprintf(w, "%-28s %-8s %-12s %s\n", "BACKEND", "TYPE", "VERSION", "STATUS")
	for _, r := range rows {
		ver := r.Version
		if ver == "" {
			ver = "?"
		}
		status := r.Status
		switch status {
		case "behind":
			status = "⚠ behind"
		case "current":
			status = "✓ current"
		}
		fmt.Fprintf(w, "%-28s %-8s %-12s %s\n", r.ID, r.Type, ver, status)
	}
	return nil
}

// getJSON does an admin-authenticated GET and decodes the JSON body.
func getJSON(url string, out interface{}) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}
	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
