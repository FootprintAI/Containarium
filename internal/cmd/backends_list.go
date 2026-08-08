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
id, type (local/tunnel), health, hostname, OS, container count, live
host load (1-minute CPU load average against core count, plus memory
and disk in use), and GPU inventory per backend.

Live load is measured on each host, including tunnel-connected BYOC
hosts. A "-" means the daemon had no usable sample for that host —
unknown, not idle.

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
	// HostLoad is what the machine is actually doing right now, or nil
	// when the daemon had no usable sample. Nil is meaningful: it means
	// "unknown", not "idle".
	HostLoad *hostLoad `json:"hostLoad,omitempty"`
	// Storage is the pool backing this backend's containers and whether it
	// isolates tenant volumes, or nil when the backend reported none. Nil is
	// meaningful: "we don't know", not "isolated". See #1209 / #1206.
	Storage *backendStorage `json:"storage,omitempty"`
}

// backendStorage mirrors the BackendInfo.storage wire shape (#1209).
// Enums arrive as their protojson string names.
type backendStorage struct {
	Pool       string `json:"pool,omitempty"`
	Driver     string `json:"driver,omitempty"`
	Isolation  string `json:"isolation,omitempty"`
	DriverName string `json:"driverName,omitempty"`
}

// hostLoad mirrors the BackendInfo.host_load wire shape (cloud #966).
type hostLoad struct {
	CPULoad1m        float64 `json:"cpuLoad1m,omitempty"`
	CPULoad5m        float64 `json:"cpuLoad5m,omitempty"`
	CPULoad15m       float64 `json:"cpuLoad15m,omitempty"`
	CPUCores         int32   `json:"cpuCores,omitempty"`
	MemoryUsedBytes  int64   `json:"memoryUsedBytes,omitempty,string"`
	MemoryTotalBytes int64   `json:"memoryTotalBytes,omitempty,string"`
	DiskUsedBytes    int64   `json:"diskUsedBytes,omitempty,string"`
	DiskTotalBytes   int64   `json:"diskTotalBytes,omitempty,string"`
	SampledAt        string  `json:"sampledAt,omitempty"`
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
	fmt.Printf("%-40s %-8s %-10s %-25s %-10s %-10s %-6s %-6s %-12s %s\n",
		"BACKEND ID", "TYPE", "HEALTH", "HOSTNAME", "CONTAINERS", "CPU LOAD", "MEM", "DISK", "STORAGE", "GPUS")
	fmt.Println(strings.Repeat("-", 155))
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
		fmt.Printf("%-40s %-8s %-10s %-25s %-10d %-10s %-6s %-6s %-12s %s\n",
			b.ID, b.Type, health, hostname, b.ContainerCount,
			formatCPULoad(b.HostLoad),
			formatUsedPercent(b.HostLoad, memoryUsage),
			formatUsedPercent(b.HostLoad, diskUsage),
			formatStorage(b.Storage),
			gpus)
	}
	fmt.Printf("\nTotal: %d backend(s)\n", len(backends))

	// The exposure is invisible until tenants are concurrently busy, and idle
	// metrics on a shared-filesystem pool look BETTER than the alternatives.
	// So say it outright rather than leaving a glyph in a column to be
	// noticed. See #1206.
	if n := sharedFilesystemBackends(backends); n > 0 {
		fmt.Printf("\n⚠  %d backend(s) on a shared-filesystem storage pool (dir).\n", n)
		fmt.Printf("   Every tenant rootfs shares one filesystem journal, so one tenant's\n")
		fmt.Printf("   writeback can stall another tenant's fsync. Idle benchmarks will not\n")
		fmt.Printf("   show this. See docs/BACKEND-STORAGE-DRIVER.md and issue #1206.\n")
	}
}

// usageKind selects which of a host's two byte-usage pairs to render.
type usageKind int

const (
	memoryUsage usageKind = iota
	diskUsage
)

// formatCPULoad renders the 1-minute load average against the host's core
// count ("6.50/8"), which is the only form in which a load average means
// anything — the same number is idle on a 64-core host and saturated on a
// 4-core one.
//
// "-" when the daemon had no usable sample. Deliberately not "0.00/0": an
// unmeasured host must not read as an unloaded one, which is the failure
// mode that made capacity decisions blind in the first place (cloud #966).
func formatCPULoad(l *hostLoad) string {
	if l == nil {
		return "-"
	}
	if l.CPUCores <= 0 {
		return fmt.Sprintf("%.2f", l.CPULoad1m)
	}
	return fmt.Sprintf("%.2f/%d", l.CPULoad1m, l.CPUCores)
}

// formatUsedPercent renders used-of-total as a whole-number percentage, or
// "-" when there is no sample (or a zero total, which would divide by zero
// and means the probe returned nothing usable anyway).
func formatUsedPercent(l *hostLoad, kind usageKind) string {
	if l == nil {
		return "-"
	}
	used, total := l.MemoryUsedBytes, l.MemoryTotalBytes
	if kind == diskUsage {
		used, total = l.DiskUsedBytes, l.DiskTotalBytes
	}
	if total <= 0 {
		return "-"
	}
	return fmt.Sprintf("%d%%", used*100/total)
}

// Isolation values as they arrive over protojson.
const (
	isolationPerContainer     = "STORAGE_ISOLATION_PER_CONTAINER"
	isolationSharedFilesystem = "STORAGE_ISOLATION_SHARED_FILESYSTEM"
	isolationUnknownDriver    = "STORAGE_ISOLATION_UNKNOWN_DRIVER"
)

// formatStorage renders the storage column: the driver name, flagged when the
// pool does not isolate tenant volumes.
//
// "-" when the backend reported nothing. Deliberately not a driver guess: an
// unmeasured pool must not read as a safe one, the same rule formatCPULoad
// follows for an unmeasured host.
func formatStorage(s *backendStorage) string {
	if s == nil || s.DriverName == "" {
		return "-"
	}
	switch s.Isolation {
	case isolationSharedFilesystem:
		return s.DriverName + " ⚠"
	case isolationUnknownDriver:
		// Read, but not a driver we classify — flag it as unverified rather
		// than asserting the shared-journal mechanism we have not established
		// for it.
		return s.DriverName + " ?"
	default:
		return s.DriverName
	}
}

// sharedFilesystemBackends counts backends positively known to be on a
// shared-filesystem pool.
//
// Backends that reported nothing, and drivers we could not classify, are NOT
// counted: "unknown" is not "exposed", and padding the count with unknowns
// would make the warning something operators learn to ignore.
func sharedFilesystemBackends(backends []backendInfo) int {
	n := 0
	for _, b := range backends {
		if b.Storage != nil && b.Storage.Isolation == isolationSharedFilesystem {
			n++
		}
	}
	return n
}
