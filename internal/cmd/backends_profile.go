package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var (
	profileBackendSkipGPU bool
	profileBackendGet     bool
	profileBackendFormat  string
)

var backendsProfileCmd = &cobra.Command{
	Use:   "profile [backend-id]",
	Short: "Record (or read) a backend's hardware capability profile",
	Long: `Record a backend's hardware capability profile: hardware class (CPU cores +
model, GPU model via the passthrough probe, RAM/disk), a bounded CPU/memory
micro-benchmark, and region. The measured class is reconciled against the
backend's self-reported class so drift is visible.

With no backend-id it profiles the local/primary daemon's host; with a peer id
it forwards to that peer (which profiles its own host). The profile is surfaced
through 'containarium backends list'.

  --skip-gpu  skip the GPU passthrough probe (CPU-only backends; faster)
  --get       read the last-recorded profile without re-running the benchmark

Admin-only. Recording runs a short micro-benchmark and (unless --skip-gpu) a
throwaway GPU probe LXC, so it can take ~30s. See #681.

Requires --server pointing at the daemon's HTTP address.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runBackendsProfile,
}

func init() {
	backendsCmd.AddCommand(backendsProfileCmd)
	backendsProfileCmd.Flags().BoolVar(&profileBackendSkipGPU, "skip-gpu", false,
		"Skip the GPU passthrough probe (CPU-only backends). Records gpu_available=false.")
	backendsProfileCmd.Flags().BoolVar(&profileBackendGet, "get", false,
		"Read the last-recorded profile instead of re-recording it.")
	backendsProfileCmd.Flags().StringVarP(&profileBackendFormat, "format", "f", "text",
		"Output format: text, json")
}

// profileBackendReq is the typed /v1/capabilities/profile request body.
type profileBackendReq struct {
	BackendID string `json:"backend_id,omitempty"`
	SkipGpu   bool   `json:"skip_gpu,omitempty"`
}

// capabilityBenchmark mirrors the proto CapabilityBenchmark wire shape.
type capabilityBenchmark struct {
	CpuOpsPerSec   int64 `json:"cpuOpsPerSec,omitempty"`
	MemBytesPerSec int64 `json:"memBytesPerSec,omitempty"`
	DurationMs     int64 `json:"durationMs,omitempty"`
}

// capabilityProfile mirrors the proto CapabilityProfile wire shape (camelCase
// via grpc-gateway JSON).
type capabilityProfile struct {
	CpuCores         int32                `json:"cpuCores,omitempty"`
	CpuModel         string               `json:"cpuModel,omitempty"`
	TotalMemoryBytes int64                `json:"totalMemoryBytes,omitempty"`
	TotalDiskBytes   int64                `json:"totalDiskBytes,omitempty"`
	GpuModel         string               `json:"gpuModel,omitempty"`
	GpuDriverVersion string               `json:"gpuDriverVersion,omitempty"`
	GpuAvailable     bool                 `json:"gpuAvailable,omitempty"`
	Region           string               `json:"region,omitempty"`
	ReportedClass    string               `json:"reportedClass,omitempty"`
	MeasuredClass    string               `json:"measuredClass,omitempty"`
	ClassConsistent  bool                 `json:"classConsistent,omitempty"`
	Benchmark        *capabilityBenchmark `json:"benchmark,omitempty"`
	ProfiledAt       string               `json:"profiledAt,omitempty"`
}

// profileBackendResp mirrors both ProfileBackendResponse and
// GetCapabilityProfileResponse (same shape).
type profileBackendResp struct {
	Profile   *capabilityProfile `json:"profile"`
	BackendID string             `json:"backendId"`
}

func runBackendsProfile(cmd *cobra.Command, args []string) error {
	if serverAddr == "" {
		return fmt.Errorf("--server is required (the platform daemon's HTTP address, e.g. http://host:8080)")
	}
	backendID := ""
	if len(args) == 1 {
		backendID = args[0]
	}

	url := strings.TrimSuffix(serverAddr, "/") + "/v1/capabilities/profile"
	var req *http.Request
	var err error
	if profileBackendGet {
		if backendID != "" {
			url += "?backend_id=" + backendID
		}
		req, err = http.NewRequest("GET", url, nil)
	} else {
		reqBody, _ := json.Marshal(profileBackendReq{BackendID: backendID, SkipGpu: profileBackendSkipGPU})
		req, err = http.NewRequest("POST", url, bytes.NewReader(reqBody))
	}
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}

	// Generous timeout: recording runs a micro-benchmark and (unless skipped)
	// creates+starts+execs+deletes a throwaway GPU probe LXC.
	httpClient := &http.Client{Timeout: 5 * time.Minute}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request %s: %w", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	if profileBackendFormat == "json" {
		if _, err := cmd.OutOrStdout().Write(body); err != nil {
			return fmt.Errorf("write response: %w", err)
		}
		fmt.Fprintln(cmd.OutOrStdout())
		return nil
	}

	var out profileBackendResp
	if err := json.Unmarshal(body, &out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	target := out.BackendID
	if target == "" {
		target = "(local)"
	}
	if out.Profile == nil {
		fmt.Fprintf(cmd.OutOrStdout(), "no capability profile recorded for %s yet (run 'containarium backends profile %s')\n", target, out.BackendID)
		return nil
	}

	p := out.Profile
	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "Capability profile for %s:\n", target)
	fmt.Fprintf(w, "  Region:          %s\n", orDash(p.Region))
	fmt.Fprintf(w, "  CPU:             %d cores  %s\n", p.CpuCores, orDash(p.CpuModel))
	fmt.Fprintf(w, "  Memory:          %s\n", humanBytes(p.TotalMemoryBytes))
	fmt.Fprintf(w, "  Disk:            %s\n", humanBytes(p.TotalDiskBytes))
	if p.GpuAvailable {
		fmt.Fprintf(w, "  GPU:             %s (driver %s)\n", orDash(p.GpuModel), orDash(p.GpuDriverVersion))
	} else {
		fmt.Fprintf(w, "  GPU:             none\n")
	}
	if p.Benchmark != nil {
		fmt.Fprintf(w, "  Benchmark:       CPU %d ops/s, mem %s/s (%dms)\n",
			p.Benchmark.CpuOpsPerSec, humanBytes(p.Benchmark.MemBytesPerSec), p.Benchmark.DurationMs)
	}
	fmt.Fprintf(w, "  Reported class:  %s\n", orDash(p.ReportedClass))
	fmt.Fprintf(w, "  Measured class:  %s\n", orDash(p.MeasuredClass))
	if p.ClassConsistent {
		fmt.Fprintf(w, "  Class:           consistent\n")
	} else {
		fmt.Fprintf(w, "  Class:           DRIFT — measured %q != reported %q\n", p.MeasuredClass, p.ReportedClass)
	}
	if p.ProfiledAt != "" {
		fmt.Fprintf(w, "  Profiled at:     %s\n", p.ProfiledAt)
	}
	return nil
}
