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

var (
	backendsListFormat string
)

var backendsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List backend hosts (local daemon + tunnel peers)",
	Long: `List all backend hosts registered with the platform daemon. Returns
id, type (local/tunnel), health, hostname, OS, container count, and
GPU inventory per backend.

The /v1/backends endpoint is HTTP-only (not gRPC), so this command
requires --server pointing at the daemon's HTTP address.`,
	Aliases: []string{"ls"},
	RunE:    runBackendsList,
}

func init() {
	backendsCmd.AddCommand(backendsListCmd)
	backendsListCmd.Flags().StringVarP(&backendsListFormat, "format", "f", "table",
		"Output format: table, json")
}

// backendInfo mirrors the /v1/backends response shape. Kept local to
// the CLI so a server-side schema change shows up here as a decode
// failure rather than a silent field-drop.
type backendInfo struct {
	ID             string       `json:"id"`
	Type           string       `json:"type"`
	Healthy        bool         `json:"healthy"`
	Version        string       `json:"version,omitempty"`
	Hostname       string       `json:"hostname,omitempty"`
	UptimeSeconds  int64        `json:"uptimeSeconds,omitempty"`
	LastSeenAt     string       `json:"lastSeenAt,omitempty"`
	OS             string       `json:"os,omitempty"`
	ContainerCount int32        `json:"containerCount"`
	GPUs           []backendGPU `json:"gpus,omitempty"`
}

type backendGPU struct {
	Vendor    string `json:"vendor,omitempty"`
	ModelName string `json:"modelName,omitempty"`
	VRAMBytes int64  `json:"vramBytes,omitempty"`
}

type backendsListResponse struct {
	Backends []backendInfo `json:"backends"`
}

// fetchBackends GETs /v1/backends from the platform daemon and returns the
// decoded backend list. Shared by `backends list` and `pool list` (a pool is
// the set of backends a daemon sees) so they can't drift.
func fetchBackends() ([]backendInfo, error) {
	if serverAddr == "" {
		return nil, fmt.Errorf("--server is required (the platform daemon's HTTP address, e.g. http://host:8080)")
	}
	url := strings.TrimSuffix(serverAddr, "/") + "/v1/backends"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("api error (status %d): %s", resp.StatusCode, string(body))
	}

	var parsed backendsListResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return parsed.Backends, nil
}

func runBackendsList(cmd *cobra.Command, args []string) error {
	backends, err := fetchBackends()
	if err != nil {
		return err
	}

	switch backendsListFormat {
	case "json":
		out, err := json.MarshalIndent(backendsListResponse{Backends: backends}, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(out))
	case "table":
		printBackendsTable(backends)
	default:
		return fmt.Errorf("unknown format: %s (use: table, json)", backendsListFormat)
	}
	return nil
}

func printBackendsTable(backends []backendInfo) {
	if len(backends) == 0 {
		fmt.Println("No backends registered (running standalone, no peers).")
		return
	}
	fmt.Printf("%-40s %-8s %-10s %-25s %-10s %s\n",
		"BACKEND ID", "TYPE", "HEALTH", "HOSTNAME", "CONTAINERS", "GPUS")
	fmt.Println(strings.Repeat("-", 110))
	for _, b := range backends {
		health := "✓"
		if !b.Healthy {
			health = "✗"
		}
		gpus := "-"
		if len(b.GPUs) > 0 {
			parts := make([]string, 0, len(b.GPUs))
			for _, g := range b.GPUs {
				parts = append(parts, g.ModelName)
			}
			gpus = strings.Join(parts, ", ")
		}
		hostname := b.Hostname
		if hostname == "" {
			hostname = "-"
		}
		fmt.Printf("%-40s %-8s %-10s %-25s %-10d %s\n",
			b.ID, b.Type, health, hostname, b.ContainerCount, gpus)
	}
	fmt.Printf("\nTotal: %d backend(s)\n", len(backends))
}
