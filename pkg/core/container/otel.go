package container

import (
	"log"
	"strings"
)

// otelEnvVars returns the OTel-related environment variables to stamp
// on a newly-created container when the operator opted in with the
// --monitoring flag. Per docs/OTEL-COLLECTOR-DESIGN.md, this is a
// per-container opt-in feature: containers created with
// opts.Monitoring=false get nothing here, and any OTel SDK the app
// pulls in falls back to its built-in "no endpoint, buffer + drop"
// behavior. Apps don't crash; they just don't ship telemetry.
//
// When Monitoring=true and the daemon doesn't have a collector
// endpoint configured (OTelCollectorEndpoint==""), we log a warning
// and return nil — stamping a dead endpoint into the container
// would have the SDK fail noisily for no benefit. Operators see the
// warning in the daemon log and know to set up the collector.
//
// Returns nil (no env vars) — not an empty map — so the caller can
// tell apart "monitoring off" from "monitoring on with zero vars."
// The Incus config-map merge code treats both the same in practice,
// but tests assert on the distinction.
func otelEnvVars(opts CreateOptions, containerName string) map[string]string {
	if !opts.Monitoring {
		return nil
	}
	if opts.OTelCollectorEndpoint == "" {
		log.Printf("[otel] container %s requested monitoring=true but daemon has no collector endpoint configured; skipping env-var injection", containerName)
		return nil
	}

	// OTEL_RESOURCE_ATTRIBUTES is the canonical way to attach
	// resource-scoped labels that the receiving collector will see
	// on every metric / span / log emitted by this app. We stamp
	// container.id (so the collector's anti-spoofing processor can
	// verify against source IP) and backend.id (so cross-VM
	// Grafana dashboards can group by daemon).
	resourceAttrs := strings.Join([]string{
		"container.id=" + containerName,
		"backend.id=" + opts.BackendID,
	}, ",")

	return map[string]string{
		"OTEL_EXPORTER_OTLP_ENDPOINT": opts.OTelCollectorEndpoint,
		"OTEL_EXPORTER_OTLP_PROTOCOL": "http/protobuf",
		"OTEL_SERVICE_NAME":           opts.Username,
		"OTEL_RESOURCE_ATTRIBUTES":    resourceAttrs,
	}
}

// OTelEnvVarsForMigration returns the same env-var set as
// otelEnvVars but with a fresh collector endpoint — used by
// AdoptMigratedContainer to re-stamp env vars at the destination's
// collector IP after MoveContainer. Exported because the
// migration-adopt handler lives in internal/server and needs to
// call into the container package's identity-stamping logic.
//
// containerName, username, backendID, and collectorEndpoint are
// all required; an empty endpoint returns nil (and logs nothing —
// the caller is responsible for deciding whether that's an error).
func OTelEnvVarsForMigration(username, containerName, backendID, collectorEndpoint string) map[string]string {
	if collectorEndpoint == "" {
		return nil
	}
	resourceAttrs := strings.Join([]string{
		"container.id=" + containerName,
		"backend.id=" + backendID,
	}, ",")
	return map[string]string{
		"OTEL_EXPORTER_OTLP_ENDPOINT": collectorEndpoint,
		"OTEL_EXPORTER_OTLP_PROTOCOL": "http/protobuf",
		"OTEL_SERVICE_NAME":           username,
		"OTEL_RESOURCE_ATTRIBUTES":    resourceAttrs,
	}
}
