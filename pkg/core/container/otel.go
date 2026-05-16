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
//
// Two parallel env-var formats are stamped:
//
//   - The legacy OTEL_RESOURCE_ATTRIBUTES comma-string (for apps that
//     read it directly via the OTel SDK env-discovery path).
//   - Split CONTAINARIUM_CONTAINER_ID / CONTAINARIUM_BACKEND_ID /
//     CONTAINARIUM_TENANT_ID for the platform-sidecar config language
//     (otelcol's ${env:VAR} reference can't parse comma strings).
//
// Both forms encode the same information; see
// docs/PLATFORM-SIDECAR-DESIGN.md decision #5 and
// docs/OTEL-AGENT-RELAY-DESIGN.md decision #5.
func otelEnvVars(opts CreateOptions, containerName string) map[string]string {
	if !opts.Monitoring {
		return nil
	}
	if opts.OTelCollectorEndpoint == "" {
		log.Printf("[otel] container %s requested monitoring=true but daemon has no collector endpoint configured; skipping env-var injection", containerName)
		return nil
	}
	return buildOTelEnvMap(opts.Username, containerName, opts.BackendID, opts.OTelCollectorEndpoint)
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
	return buildOTelEnvMap(username, containerName, backendID, collectorEndpoint)
}

// buildOTelEnvMap is the single source of truth for what
// monitoring-related env vars get stamped on a container. Both the
// create-time and migration-time entry points return the same shape.
//
// OTEL_RESOURCE_ATTRIBUTES is the canonical comma-encoded form that
// any OTel SDK auto-discovers. The three CONTAINARIUM_* keys are the
// split form the platform sidecar's baked-in otelcol config reads
// via ${env:CONTAINARIUM_CONTAINER_ID} etc. Keeping both means:
//
//   - Apps running directly in the LXC (non-docker) pick up the
//     OTel SDK auto-config from OTEL_RESOURCE_ATTRIBUTES with no
//     extra work.
//   - The OTel sidecar (docker-compose service inside the LXC) reads
//     the split form via `${VAR}` compose-interpolation, since the
//     interpolation runs at compose-up time and feeds the env into
//     the sidecar container.
func buildOTelEnvMap(username, containerName, backendID, collectorEndpoint string) map[string]string {
	resourceAttrs := strings.Join([]string{
		"container.id=" + containerName,
		"backend.id=" + backendID,
	}, ",")
	return map[string]string{
		// Legacy / auto-discovered form
		"OTEL_EXPORTER_OTLP_ENDPOINT": collectorEndpoint,
		"OTEL_EXPORTER_OTLP_PROTOCOL": "http/protobuf",
		"OTEL_SERVICE_NAME":           username,
		"OTEL_RESOURCE_ATTRIBUTES":    resourceAttrs,
		// Split form for sidecar compose-interpolation
		"CONTAINARIUM_CONTAINER_ID": containerName,
		"CONTAINARIUM_BACKEND_ID":   backendID,
		"CONTAINARIUM_TENANT_ID":    username,
	}
}
