package cmd

import (
	"fmt"
	"strings"

	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

// metricsExportProvider backs the --provider flag on `monitoring export
// enable`. #1069 only ships GCP; AWS is accepted here so the CLI's
// error message ("not yet implemented") comes from the same server
// validation the RPC enforces, rather than a second copy of the
// allow-list living in the CLI.
var metricsExportProvider string

var monitoringExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Enable, disable, or inspect cloud-native metrics export",
	Long: `Opt-in export of host/container infra metrics to the host cloud's
native monitoring (GCP Cloud Monitoring in the MVP). Disabled by
default, reversible any time. Enabling probes the host's credentials
before persisting anything — on GCP this resolves Application Default
Credentials with the monitoring-write scope; a host with no usable ADC
fails with an actionable error and nothing is enabled or exported.

Examples:
  containarium monitoring export enable --provider gcp
  containarium monitoring export status
  containarium monitoring export disable`,
}

var monitoringExportEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable cloud-native metrics export",
	Long: `Enable opt-in export to the given cloud provider's native
monitoring. Requires --provider. The daemon probes the host's
credentials synchronously before persisting anything — on GCP this
resolves Application Default Credentials (ADC) with the
monitoring-write scope; failure returns an actionable error (with an
IAM remediation hint) and nothing is enabled. Takes effect immediately,
no daemon restart required.

Examples:
  containarium monitoring export enable --provider gcp`,
	Args: cobra.NoArgs,
	RunE: runMetricsExportEnable,
}

var monitoringExportDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable cloud-native metrics export",
	Long: `Disable cloud-native metrics export. Emission stops within one
export interval; no daemon restart required.

Examples:
  containarium monitoring export disable`,
	Args: cobra.NoArgs,
	RunE: runMetricsExportDisable,
}

var monitoringExportStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show cloud-native metrics export status",
	Long: `Print whether cloud-native metrics export is enabled, which
provider it targets, the export interval, and last-known health
(last success time, last error, failure count — populated once the
metrics collector lands in a follow-up issue).

Examples:
  containarium monitoring export status`,
	Args: cobra.NoArgs,
	RunE: runMetricsExportStatus,
}

func init() {
	monitoringExportEnableCmd.Flags().StringVar(&metricsExportProvider, "provider", "", "cloud provider to export to (gcp)")

	monitoringCmd.AddCommand(monitoringExportCmd)
	monitoringExportCmd.AddCommand(monitoringExportEnableCmd)
	monitoringExportCmd.AddCommand(monitoringExportDisableCmd)
	monitoringExportCmd.AddCommand(monitoringExportStatusCmd)
}

// parseMetricsExportProvider maps the CLI's lowercase --provider flag
// to the typed CloudMetricsProvider enum. No magic strings past this
// boundary — every other layer (client, server, config) speaks the
// enum. Unknown strings are rejected here (a client-side typo like
// "gpc"); UNSPECIFIED and AWS are passed through so the server's own
// validation (InvalidArgument / Unimplemented) is the single source of
// truth for "is this provider usable".
func parseMetricsExportProvider(s string) (pb.CloudMetricsProvider, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_UNSPECIFIED, fmt.Errorf("--provider is required (e.g. --provider gcp)")
	case "gcp":
		return pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_GCP, nil
	case "aws":
		return pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_AWS, nil
	default:
		return pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_UNSPECIFIED, fmt.Errorf("unknown provider %q (supported: gcp)", s)
	}
}

func runMetricsExportEnable(cmd *cobra.Command, args []string) error {
	provider, err := parseMetricsExportProvider(metricsExportProvider)
	if err != nil {
		return err
	}
	if serverAddr == "" {
		return fmt.Errorf("--server is required for metrics export (no local fallback)")
	}

	resp, err := setMetricsExportClient(true, provider)
	if err != nil {
		return fmt.Errorf("failed to enable cloud metrics export: %w", err)
	}

	fmt.Printf("✓ cloud metrics export enabled (provider=%s, interval=%ds)\n",
		metricsExportProviderLabel(resp.Provider), resp.IntervalSeconds)
	if resp.Message != "" {
		fmt.Println(resp.Message)
	}
	return nil
}

func runMetricsExportDisable(cmd *cobra.Command, args []string) error {
	if serverAddr == "" {
		return fmt.Errorf("--server is required for metrics export (no local fallback)")
	}

	resp, err := setMetricsExportClient(false, pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_UNSPECIFIED)
	if err != nil {
		return fmt.Errorf("failed to disable cloud metrics export: %w", err)
	}

	fmt.Println("✓ cloud metrics export disabled")
	if resp.Message != "" {
		fmt.Println(resp.Message)
	}
	return nil
}

func runMetricsExportStatus(cmd *cobra.Command, args []string) error {
	if serverAddr == "" {
		return fmt.Errorf("--server is required for metrics export (no local fallback)")
	}

	resp, err := getMetricsExportClient()
	if err != nil {
		return fmt.Errorf("failed to get cloud metrics export status: %w", err)
	}

	if !resp.Enabled {
		fmt.Println("cloud metrics export: disabled")
		return nil
	}

	fmt.Printf("cloud metrics export: enabled (provider=%s, interval=%ds)\n",
		metricsExportProviderLabel(resp.Provider), resp.IntervalSeconds)
	if resp.LastSuccessAt != nil && resp.LastSuccessAt.IsValid() && resp.LastSuccessAt.AsTime().Unix() > 0 {
		fmt.Printf("  last success: %s\n", resp.LastSuccessAt.AsTime().Local().Format("2006-01-02 15:04:05 MST"))
	}
	if resp.LastError != "" {
		fmt.Printf("  last error: %s\n", resp.LastError)
	}
	if resp.ExportFailures > 0 {
		fmt.Printf("  export failures: %d\n", resp.ExportFailures)
	}
	return nil
}

// metricsExportProviderLabel renders the enum the way an operator
// expects to type it back on the CLI (lowercase, matching --provider).
func metricsExportProviderLabel(p pb.CloudMetricsProvider) string {
	switch p {
	case pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_GCP:
		return "gcp"
	case pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_AWS:
		return "aws"
	default:
		return "unspecified"
	}
}

// setMetricsExportClient and getMetricsExportClient route through
// whichever transport is active (gRPC or REST), mirroring
// runMonitoringToggle's httpMode branch in internal/cmd/monitoring.go.
// This is the one function the MCP tool also calls (internal/mcp/tools.go)
// — CLI-first per the repo convention.
func setMetricsExportClient(enabled bool, provider pb.CloudMetricsProvider) (*pb.SetMetricsExportResponse, error) {
	if httpMode {
		httpClient, err := client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return nil, err
		}
		defer func() { _ = httpClient.Close() }()
		return httpClient.SetMetricsExport(enabled, provider)
	}
	grpcClient, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return nil, err
	}
	defer func() { _ = grpcClient.Close() }()
	return grpcClient.SetMetricsExport(enabled, provider)
}

func getMetricsExportClient() (*pb.GetMetricsExportResponse, error) {
	if httpMode {
		httpClient, err := client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return nil, err
		}
		defer func() { _ = httpClient.Close() }()
		return httpClient.GetMetricsExport()
	}
	grpcClient, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return nil, err
	}
	defer func() { _ = grpcClient.Close() }()
	return grpcClient.GetMetricsExport()
}
