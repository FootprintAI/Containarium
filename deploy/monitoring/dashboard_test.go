// Package monitoring holds committed GCM configuration data (dashboard
// JSON, reproducible via `gcloud monitoring dashboards create`) rather
// than deployable Go code. This test file exists solely to pin the
// dashboard JSON against metric-name drift: every widget must reference
// one of cloudexport's actual exported instrument names, so a renamed
// or removed series is caught here instead of silently going stale in a
// committed artifact nobody re-generates.
package monitoring

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/metrics/cloudexport"
)

// knownMetricTypes is the complete set of GCM metric types the
// cloudexport collector can emit, derived from its exported instrument
// name consts (the same allowlist the collector's own golden tests
// pin). Prefixed with workload.googleapis.com/, matching how GCP's
// OTel exporter namespaces custom metrics.
func knownMetricTypes() map[string]bool {
	names := []string{
		cloudexport.MetricCPULoad1m,
		cloudexport.MetricCPULoad5m,
		cloudexport.MetricCPULoad15m,
		cloudexport.MetricMemoryUsed,
		cloudexport.MetricMemoryTotal,
		cloudexport.MetricDiskUsed,
		cloudexport.MetricDiskTotal,
		cloudexport.MetricContainerCount,
		cloudexport.MetricHeartbeat,
		cloudexport.MetricPlatformAPIRequests,
		cloudexport.MetricPlatformAPIErrors,
		cloudexport.MetricPlatformProvisionAttempts,
		cloudexport.MetricPlatformProvisionFailures,
		cloudexport.MetricPlatformProvisionDurationSecondsSum,
		cloudexport.MetricPlatformPeersConnected,
		cloudexport.MetricPlatformTunnelState,
	}
	out := make(map[string]bool, len(names))
	for _, n := range names {
		out["workload.googleapis.com/"+n] = true
	}
	return out
}

// TestDashboardJSON_ValidAndReferencesKnownMetrics loads the committed
// dashboard and asserts (1) it is valid JSON gcloud can accept, and (2)
// every metric.type filter it contains names a series the collector
// actually exports — catching a typo or a renamed/removed instrument
// that a hand-edited dashboard JSON would otherwise drift from silently.
func TestDashboardJSON_ValidAndReferencesKnownMetrics(t *testing.T) {
	data, err := os.ReadFile("gcm-containarium-hosts.json")
	if err != nil {
		t.Fatalf("read dashboard JSON: %v", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("dashboard JSON is invalid: %v", err)
	}

	if _, ok := doc["displayName"]; !ok {
		t.Error("dashboard JSON missing displayName")
	}

	known := knownMetricTypes()
	foundHost := false
	requiredPlatform := []string{cloudexport.MetricPlatformAPIErrors, cloudexport.MetricPlatformProvisionFailures, cloudexport.MetricPlatformPeersConnected}
	foundPlatform := map[string]bool{}
	for _, m := range requiredPlatform {
		foundPlatform[m] = false
	}

	// metric.type filters are buried in nested xyChart/timeSeriesQuery
	// widgets; rather than modeling the full GCM dashboard schema, walk
	// the raw JSON text for every metric.type = "..." filter fragment —
	// robust to layout (xyChart vs. scorecard vs. mosaic) and exactly
	// what matters for the drift check this test exists for.
	text := string(data)
	const marker = `metric.type = \"`
	for idx := strings.Index(text, marker); idx != -1; {
		rest := text[idx+len(marker):]
		end := strings.Index(rest, `\"`)
		if end == -1 {
			t.Fatalf("unterminated metric.type filter near offset %d", idx)
		}
		metricType := rest[:end]
		if !known[metricType] {
			t.Errorf("dashboard references unknown metric type %q — not one of cloudexport's exported instruments", metricType)
		}
		if strings.HasSuffix(metricType, "containarium.host.cpu.load_1m") {
			foundHost = true
		}
		for _, want := range requiredPlatform {
			if strings.HasSuffix(metricType, want) {
				foundPlatform[want] = true
			}
		}

		next := strings.Index(rest[end+2:], marker)
		if next == -1 {
			break
		}
		idx = idx + len(marker) + end + 2 + next
	}

	if !foundHost {
		t.Error("dashboard is missing a host-series chart (e.g. CPU load) alongside the platform charts")
	}
	for _, metric := range requiredPlatform {
		if !foundPlatform[metric] {
			t.Errorf("dashboard is missing a chart for required platform series %q (#1085 acceptance criterion)", metric)
		}
	}
}
