package cloudexport

import (
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// DefaultIntervalSeconds is the fixed export cadence for the MVP. #1069
// does not expose an operator knob to change it — see the "cost guard"
// floor in docs/CLOUD-NATIVE-METRICS-EXPORT-DESIGN.md (custom metrics
// are billed per ingested sample).
const DefaultIntervalSeconds = 60

// ConfigStoreKey is the single daemon-config-store key the whole Config
// struct is persisted under (JSON-encoded). One key holding the
// complete struct — rather than spreading Enabled/Provider/
// IntervalSeconds across three loose keys — means every read and write
// is a full-config round trip by construction, not a partial update
// that could clobber a sibling field (the failure mode fixed for the
// BYOC ingress "listen" array in #1062/#1064).
const ConfigStoreKey = "metrics_export_config"

// Config is the typed, persisted state of the cloud-native metrics
// export toggle (#1069): whether export is on, which provider it
// targets, and the export cadence. It round-trips through
// SetMetricsExport / GetMetricsExport and survives a daemon restart via
// the daemon's existing config store.
type Config struct {
	Enabled         bool                    `json:"enabled"`
	Provider        pb.CloudMetricsProvider `json:"provider"`
	IntervalSeconds int32                   `json:"interval_seconds"`

	// Groups is the set of enabled metric groups (#1081). Omitted from a
	// v0.60.0 config (which predates groups) — an absent or empty value
	// is treated as [HOST] by NormalizeGroups everywhere it is consumed,
	// so an old config resumes exactly today's host-only behavior.
	// `omitempty` keeps a host-only config byte-identical to the pre-#1081
	// persisted form.
	Groups []pb.CloudMetricsGroup `json:"groups,omitempty"`
}

// DefaultConfig returns the zero-value config: export disabled, no
// provider configured, the fixed default interval. This is what a host
// that has never called SetMetricsExport reports from GetMetricsExport.
func DefaultConfig() Config {
	return Config{
		Enabled:         false,
		Provider:        pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_UNSPECIFIED,
		IntervalSeconds: DefaultIntervalSeconds,
	}
}
