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

// capacityCmd is the parent for advertising / withdrawing this backend's spare
// scheduling headroom to the control plane (#680). A box that would otherwise
// scale down can instead offer its freed headroom for control-plane-directed
// scheduling, bounded by a local policy.
var capacityCmd = &cobra.Command{
	Use:   "capacity",
	Short: "Advertise or withdraw this backend's spare scheduling capacity",
	Long: `Publish (or withdraw) this backend's spare scheduling headroom to the
control plane. The advertisement is bounded by a local policy: an
optional time window, excluded workload classes, and a safety
reservation. It is surfaced through the backend list (containarium
backends list).

Examples:
  # Advertise all available headroom (always-open window)
  containarium capacity advertise --server <host:port>

  # Advertise only 09:00-17:00, holding back 20%, excluding a class
  containarium capacity advertise --window 9-17 --reserve 0.2 \
      --exclude batch --server <host:port>

  # Withdraw (idempotent)
  containarium capacity withdraw --server <host:port>

  # Read the current advertisement
  containarium capacity get --server <host:port>`,
}

var (
	capWindow   string
	capReserve  float64
	capExclude  []string
	capFormat   string
)

type capacityPolicyJSON struct {
	WindowStartHour         int32    `json:"windowStartHour,omitempty"`
	WindowEndHour           int32    `json:"windowEndHour,omitempty"`
	ExcludedWorkloadClasses []string `json:"excludedWorkloadClasses,omitempty"`
	ReserveFraction         float64  `json:"reserveFraction,omitempty"`
}

type capacityHeadroomJSON struct {
	Advertised       bool                `json:"advertised"`
	SpareCpus        int32               `json:"spareCpus,omitempty"`
	SpareMemoryBytes int64               `json:"spareMemoryBytes,omitempty"`
	SpareDiskBytes   int64               `json:"spareDiskBytes,omitempty"`
	IdleFraction     float64             `json:"idleFraction,omitempty"`
	AdvertisedAt     string              `json:"advertisedAt,omitempty"`
	Policy           *capacityPolicyJSON `json:"policy,omitempty"`
}

type capacityHeadroomResponse struct {
	Headroom *capacityHeadroomJSON `json:"headroom"`
}

func init() {
	rootCmd.AddCommand(capacityCmd)

	advertiseCmd := &cobra.Command{
		Use:   "advertise",
		Short: "Advertise spare scheduling capacity (bounded by a local policy)",
		RunE:  runCapacityAdvertise,
	}
	advertiseCmd.Flags().StringVar(&capWindow, "window", "",
		"Local-clock advertisement window as START-END hours (e.g. 9-17, or 22-6 for overnight); empty = always open")
	advertiseCmd.Flags().Float64Var(&capReserve, "reserve", 0,
		"Fraction of host resources to hold back as a safety reservation [0,1)")
	advertiseCmd.Flags().StringSliceVar(&capExclude, "exclude", nil,
		"Workload class(es) to exclude from the idle/spare computation (repeatable)")
	advertiseCmd.Flags().StringVarP(&capFormat, "format", "f", "table", "Output format: table, json")
	capacityCmd.AddCommand(advertiseCmd)

	withdrawCmd := &cobra.Command{
		Use:   "withdraw",
		Short: "Withdraw the spare-capacity advertisement (idempotent)",
		RunE:  runCapacityWithdraw,
	}
	withdrawCmd.Flags().StringVarP(&capFormat, "format", "f", "table", "Output format: table, json")
	capacityCmd.AddCommand(withdrawCmd)

	getCmd := &cobra.Command{
		Use:   "get",
		Short: "Show the current spare-capacity advertisement",
		RunE:  runCapacityGet,
	}
	getCmd.Flags().StringVarP(&capFormat, "format", "f", "table", "Output format: table, json")
	capacityCmd.AddCommand(getCmd)
}

// parseWindow turns "9-17" / "22-6" into (start, end) hours. An empty string
// yields (0,0) which the daemon treats as always-open.
func parseWindow(w string) (int32, int32, error) {
	if w == "" {
		return 0, 0, nil
	}
	parts := strings.SplitN(w, "-", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid --window %q (want START-END, e.g. 9-17)", w)
	}
	var start, end int32
	if _, err := fmt.Sscanf(parts[0], "%d", &start); err != nil {
		return 0, 0, fmt.Errorf("invalid window start %q: %w", parts[0], err)
	}
	if _, err := fmt.Sscanf(parts[1], "%d", &end); err != nil {
		return 0, 0, fmt.Errorf("invalid window end %q: %w", parts[1], err)
	}
	if start < 0 || start > 23 || end < 0 || end > 23 {
		return 0, 0, fmt.Errorf("window hours must be 0-23, got %d-%d", start, end)
	}
	return start, end, nil
}

func runCapacityAdvertise(cmd *cobra.Command, args []string) error {
	if serverAddr == "" {
		return fmt.Errorf("--server is required (the daemon's HTTP address, e.g. http://host:8080)")
	}
	start, end, err := parseWindow(capWindow)
	if err != nil {
		return err
	}
	if capReserve < 0 || capReserve >= 1 {
		return fmt.Errorf("--reserve must be in [0,1), got %v", capReserve)
	}
	body, err := json.Marshal(map[string]any{
		"policy": capacityPolicyJSON{
			WindowStartHour:         start,
			WindowEndHour:           end,
			ExcludedWorkloadClasses: capExclude,
			ReserveFraction:         capReserve,
		},
	})
	if err != nil {
		return err
	}
	return capacityCall("POST", "/v1/capacity/headroom", body)
}

func runCapacityWithdraw(cmd *cobra.Command, args []string) error {
	if serverAddr == "" {
		return fmt.Errorf("--server is required (the daemon's HTTP address, e.g. http://host:8080)")
	}
	return capacityCall("DELETE", "/v1/capacity/headroom", nil)
}

func runCapacityGet(cmd *cobra.Command, args []string) error {
	if serverAddr == "" {
		return fmt.Errorf("--server is required (the daemon's HTTP address, e.g. http://host:8080)")
	}
	return capacityCall("GET", "/v1/capacity/headroom", nil)
}

func capacityCall(method, path string, reqBody []byte) error {
	url := strings.TrimSuffix(serverAddr, "/") + path
	var rdr io.Reader
	if reqBody != nil {
		rdr = bytes.NewReader(reqBody)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request %s: %w", url, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("api error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var parsed capacityHeadroomResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	switch capFormat {
	case "json":
		out, err := json.MarshalIndent(parsed, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(out))
	default:
		printHeadroom(parsed.Headroom)
	}
	return nil
}

func printHeadroom(h *capacityHeadroomJSON) {
	if h == nil {
		fmt.Println("No headroom advertised.")
		return
	}
	state := "withdrawn"
	if h.Advertised {
		state = "advertised"
	}
	fmt.Printf("Capacity advertisement: %s\n", state)
	if h.Advertised {
		fmt.Printf("  spare cpus:   %d\n", h.SpareCpus)
		fmt.Printf("  spare memory: %d bytes\n", h.SpareMemoryBytes)
		fmt.Printf("  spare disk:   %d bytes\n", h.SpareDiskBytes)
		fmt.Printf("  idle frac:    %.2f\n", h.IdleFraction)
		if h.AdvertisedAt != "" {
			fmt.Printf("  since:        %s\n", h.AdvertisedAt)
		}
	}
	if h.Policy != nil {
		win := "always open"
		if h.Policy.WindowStartHour != h.Policy.WindowEndHour {
			win = fmt.Sprintf("%02d:00-%02d:00", h.Policy.WindowStartHour, h.Policy.WindowEndHour)
		}
		fmt.Printf("  policy:       window=%s reserve=%.2f exclude=%v\n",
			win, h.Policy.ReserveFraction, h.Policy.ExcludedWorkloadClasses)
	}
}
