package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var backendsGetCmd = &cobra.Command{
	Use:   "get <id>",
	Short: "Show a single backend's details by ID",
	Long: `Fetch one backend's metadata by ID — same shape as 'backends list'
but filtered to a single host. Returns a clear "not found" if the ID
doesn't match any registered backend.

Use this when you have a backend ID from 'backends list' or from a
container's BackendID field and want to drill down without paging
through the full list.

Example:
  containarium backends get tunnel-fts-13700k-gpu --server <host:port>`,
	Args: cobra.ExactArgs(1),
	RunE: runBackendsGet,
}

func init() {
	backendsCmd.AddCommand(backendsGetCmd)
	backendsGetCmd.Flags().StringVarP(&backendsListFormat, "format", "f", "table",
		"Output format: table, json")
}

func runBackendsGet(cmd *cobra.Command, args []string) error {
	if serverAddr == "" {
		return fmt.Errorf("--server is required (the platform daemon's HTTP address)")
	}
	id := args[0]

	// Implementation note: the daemon doesn't have a /v1/backends/{id}
	// route — only /v1/backends/{id}/system-info, which forwards to
	// the peer for system info, not metadata. So we list-and-filter.
	// Cheap (the list is small) and means the CLI stays in sync if a
	// dedicated endpoint lands later.
	url := strings.TrimSuffix(serverAddr, "/") + "/v1/backends"
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
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("api error (status %d): %s", resp.StatusCode, string(body))
	}

	var parsed backendsListResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	for i := range parsed.Backends {
		if parsed.Backends[i].ID == id {
			switch backendsListFormat {
			case "json":
				out, err := json.MarshalIndent(parsed.Backends[i], "", "  ")
				if err != nil {
					return err
				}
				fmt.Println(string(out))
			case "table":
				printBackendsTable([]backendInfo{parsed.Backends[i]})
			default:
				return fmt.Errorf("unknown format: %s (use: table, json)", backendsListFormat)
			}
			return nil
		}
	}
	return fmt.Errorf("backend %q not found (got %d backend(s) total)", id, len(parsed.Backends))
}
