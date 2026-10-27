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
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/metrics/cloudexport"
)

// counterInstruments are the exported instruments that are monotonic
// counters (collector.go registers them with Int64/Float64ObservableCounter).
// Since the OTLP exporter (#2008, v0.100.0) Cloud Monitoring stores a counter
// as prometheus.googleapis.com/<name>/counter (CUMULATIVE) and every other
// instrument as .../gauge, on a prometheus_target resource (#2608). A new
// counter added to the dashboard must be listed here.
var counterInstruments = map[string]bool{
	cloudexport.MetricPlatformAPIRequests:                 true,
	cloudexport.MetricPlatformAPIErrors:                   true,
	cloudexport.MetricPlatformProvisionAttempts:           true,
	cloudexport.MetricPlatformProvisionFailures:           true,
	cloudexport.MetricPlatformProvisionDurationSecondsSum: true,
}

// knownMetricTypes is the complete set of GCM metric types the
// cloudexport collector can emit that the dashboard may reference, derived
// from its exported instrument name consts (the same allowlist the
// collector's own golden tests pin).
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
		kind := "gauge"
		if counterInstruments[n] {
			kind = "counter"
		}
		out["prometheus.googleapis.com/"+n+"/"+kind] = true
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
		if strings.Contains(metricType, "containarium.host.cpu.load_1m") {
			foundHost = true
		}
		for _, want := range requiredPlatform {
			if strings.Contains(metricType, want) {
				foundPlatform[want] = true
			}
		}

		next := strings.Index(rest[end+2:], marker)
		if next == -1 {
			break
		}
		idx = idx + len(marker) + end + 2 + next
	}

	// Every filter must select the resource the series is written on.
	if n := strings.Count(text, `resource.type = \"gce_instance\"`); n != 0 {
		t.Errorf("%d filter(s) still select resource.type gce_instance; the OTLP exporter writes prometheus_target", n)
	}
	if got, want := strings.Count(text, `resource.type = \"prometheus_target\"`), strings.Count(text, marker); got != want {
		t.Errorf("%d of %d metric filters select resource.type prometheus_target", got, want)
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

// TestNoDeprecatedSeriesNamedAsCurrent fails when a file under deploy/ or
// docs/ names the deprecated workload.googleapis.com/containarium.* type as
// if it were what a current host writes (#2608). A filter built from such a
// line is accepted by Cloud Monitoring and then selects no data. A line that
// is explicitly about older hosts may still name it.
func TestNoDeprecatedSeriesNamedAsCurrent(t *testing.T) {
	const stale = "workload.googleapis.com/containarium."
	historical := []string{"v0.100.0", "deprecated", "older", "below"}
	for _, root := range []string{".", "../../docs"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || strings.HasSuffix(path, "_test.go") {
				return err
			}
			data, rerr := os.ReadFile(path) // #nosec G304 -- walking the repo's own deploy/ and docs/ trees
			if rerr != nil {
				return rerr
			}
			for i, line := range strings.Split(string(data), "\n") {
				if !strings.Contains(line, stale) {
					continue
				}
				ok := false
				for _, h := range historical {
					if strings.Contains(line, h) {
						ok = true
					}
				}
				if !ok {
					t.Errorf("%s:%d names the deprecated %s* type as current; use prometheus.googleapis.com/<name>/{gauge,counter} on prometheus_target", path, i+1, stale)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
