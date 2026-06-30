package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	appconfig "github.com/footprintai/containarium/internal/config"
	"github.com/footprintai/containarium/pkg/core/incus"
)

const (
	// CoreOTelCollectorContainer is the name of the core OTel collector
	// LXC. It receives app-emitted OTLP from monitoring=true containers
	// and forwards to the local VictoriaMetrics via OTLP/HTTP.
	CoreOTelCollectorContainer = "containarium-core-otelcollector"

	// DefaultOTelOTLPHTTPPort is the OTLP/HTTP receiver port.
	DefaultOTelOTLPHTTPPort = 4318

	// DefaultOTelOTLPGRPCPort is the OTLP/gRPC receiver port.
	DefaultOTelOTLPGRPCPort = 4317

	// otelCollectorVersion pins the upstream contrib release.
	otelCollectorVersion = "0.110.0"

	// containerIPsFile is the path inside the collector LXC where
	// the daemon pushes the source-IP → container-name map. The
	// collector's filewatcher (v2) will hot-reload from it; in v1
	// the daemon regenerates the transform processor's OTTL
	// statements directly in config.yaml.
	containerIPsFile = "/var/lib/containarium/container_ips.json"
)

// DefaultOTelDropLabels is the cardinality guard's default drop-list.
// These attributes most often blow up TSDBs in practice (per-request,
// per-user, per-trace IDs). Operators can extend the list with
// --otel-drop-labels=a,b,c at daemon startup; this default is always
// applied. Per docs/OTEL-COLLECTOR-DESIGN.md §5.
var DefaultOTelDropLabels = []string{
	"request_id",
	"trace_id",
	"user_email",
	"session_id",
	"correlation_id",
}

// EnsureOTelCollector ensures the OTel collector container exists, is
// running, and has its config pointed at the provided VictoriaMetrics
// IP. Idempotent — safe to call on every daemon startup.
//
// dropLabels is the union of DefaultOTelDropLabels and any
// operator-provided extras (via --otel-drop-labels). The merged list
// is fed to the transform processor's OTTL delete_matching_keys
// statement.
func (cs *CoreServices) EnsureOTelCollector(ctx context.Context, victoriaMetricsIP string, dropLabels []string) (string, error) {
	if victoriaMetricsIP == "" {
		return "", fmt.Errorf("VictoriaMetrics IP required (cannot configure collector exporter without it)")
	}

	// Reserve 1GB so the collector keeps draining metrics even when
	// user containers fill the pool.
	cs.ensureCoreReservation(CoreOTelCollectorContainer, "1G")

	merged := mergeOTelDropLabels(DefaultOTelDropLabels, dropLabels)

	info, err := cs.incusClient.GetContainer(CoreOTelCollectorContainer)
	if err == nil {
		cs.backfillConfig(CoreOTelCollectorContainer, incus.RoleOTelCollector, "75")

		if info.State == "Running" {
			cs.otelCollectorIP = info.IPAddress
			log.Printf("OTel collector container already running at %s", cs.otelCollectorIP)
			// Always refresh config on re-run so VM IP or operator
			// drop-label changes propagate without a recreate.
			if err := cs.applyOTelCollectorConfig(victoriaMetricsIP, merged); err != nil {
				log.Printf("Warning: failed to refresh OTel collector config: %v", err)
			}
			return cs.otelCollectorIP, nil
		}

		log.Printf("Starting existing OTel collector container...")
		if err := cs.incusClient.StartContainer(CoreOTelCollectorContainer); err != nil {
			return "", fmt.Errorf("failed to start otel collector: %w", err)
		}
		ip, err := cs.incusClient.WaitForNetwork(CoreOTelCollectorContainer, 60*time.Second)
		if err != nil {
			return "", fmt.Errorf("failed to get otel collector IP: %w", err)
		}
		cs.otelCollectorIP = ip
		if err := cs.applyOTelCollectorConfig(victoriaMetricsIP, merged); err != nil {
			log.Printf("Warning: failed to refresh OTel collector config: %v", err)
		}
		return cs.otelCollectorIP, nil
	}

	log.Printf("Creating OTel collector container...")

	config := incus.ContainerConfig{
		Name:      CoreOTelCollectorContainer,
		Image:     "images:ubuntu/24.04",
		CPU:       "1",
		Memory:    "512MB",
		AutoStart: true,
		Disk: &incus.DiskDevice{
			Path: "/",
			Pool: "default",
			Size: "3GB",
		},
	}
	if err := cs.incusClient.CreateContainer(config); err != nil {
		return "", fmt.Errorf("failed to create otel collector container: %w", err)
	}

	cs.setContainerConfigBestEffort(CoreOTelCollectorContainer, incus.RoleKey, string(incus.RoleOTelCollector))
	cs.setContainerConfigBestEffort(CoreOTelCollectorContainer, "boot.autostart", "true")
	cs.setContainerConfigBestEffort(CoreOTelCollectorContainer, "boot.autostart.priority", "75")

	if err := cs.incusClient.StartContainer(CoreOTelCollectorContainer); err != nil {
		return "", fmt.Errorf("failed to start otel collector container: %w", err)
	}
	ip, err := cs.incusClient.WaitForNetwork(CoreOTelCollectorContainer, 60*time.Second)
	if err != nil {
		return "", fmt.Errorf("failed to get otel collector IP: %w", err)
	}
	cs.otelCollectorIP = ip
	log.Printf("OTel collector container IP: %s", cs.otelCollectorIP)

	if err := cs.installOTelCollector(ctx, victoriaMetricsIP, merged); err != nil {
		return "", fmt.Errorf("failed to setup otel collector: %w", err)
	}

	cs.applyBaseScripts(CoreOTelCollectorContainer, "ubuntu")

	return cs.otelCollectorIP, nil
}

// installOTelCollector installs otelcol-contrib and writes the initial
// config. Runs only on first-time create; later restarts go through
// applyOTelCollectorConfig.
func (cs *CoreServices) installOTelCollector(ctx context.Context, vmIP string, dropLabels []string) error {
	log.Printf("Installing otelcol-contrib %s...", otelCollectorVersion)

	time.Sleep(5 * time.Second)

	prep := [][]string{
		{"apt-get", "update"},
		{"apt-get", "install", "-y", "curl", "wget", "ca-certificates"},
		{"mkdir", "-p", "/etc/otelcol-contrib", "/var/lib/containarium"},
	}
	for _, c := range prep {
		if err := cs.incusClient.Exec(CoreOTelCollectorContainer, c); err != nil {
			return fmt.Errorf("failed to run %v: %w", c, err)
		}
	}

	// Download the contrib release tarball and extract the binary
	// only — full release tarball is ~80MB with sample configs we
	// don't need.
	tgzURL := fmt.Sprintf(
		"https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v%s/otelcol-contrib_%s_linux_amd64.tar.gz",
		otelCollectorVersion, otelCollectorVersion,
	)
	dl := [][]string{
		{"bash", "-c", fmt.Sprintf("wget -qO /tmp/otelcol-contrib.tar.gz %s", tgzURL)},
		{"bash", "-c", "tar -xzf /tmp/otelcol-contrib.tar.gz -C /usr/local/bin/ otelcol-contrib"},
		{"chmod", "+x", "/usr/local/bin/otelcol-contrib"},
		{"rm", "-f", "/tmp/otelcol-contrib.tar.gz"},
	}
	for _, c := range dl {
		if err := cs.incusClient.Exec(CoreOTelCollectorContainer, c); err != nil {
			return fmt.Errorf("failed to install otelcol-contrib: %w", err)
		}
	}

	// Empty initial IP map — daemon pushes the real one once
	// container lifecycle events start firing.
	if err := cs.incusClient.WriteFile(CoreOTelCollectorContainer, containerIPsFile, []byte("{}\n"), "0644"); err != nil {
		return fmt.Errorf("failed to seed container_ips.json: %w", err)
	}

	if err := cs.applyOTelCollectorConfig(vmIP, dropLabels); err != nil {
		return fmt.Errorf("failed to write initial otel config: %w", err)
	}

	unit := `[Unit]
Description=OpenTelemetry Collector Contrib
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/otelcol-contrib --config=/etc/otelcol-contrib/config.yaml
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`
	if err := cs.incusClient.WriteFile(CoreOTelCollectorContainer, "/etc/systemd/system/otelcol-contrib.service", []byte(unit), "0644"); err != nil {
		return fmt.Errorf("failed to write otelcol-contrib systemd unit: %w", err)
	}

	start := [][]string{
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", "otelcol-contrib"},
		{"systemctl", "restart", "otelcol-contrib"},
	}
	for _, c := range start {
		if err := cs.incusClient.Exec(CoreOTelCollectorContainer, c); err != nil {
			return fmt.Errorf("failed to start otelcol-contrib: %w", err)
		}
	}

	if err := cs.waitForOTelCollector(ctx); err != nil {
		return fmt.Errorf("otelcol-contrib not ready: %w", err)
	}

	log.Printf("OTel collector setup complete")
	return nil
}

// applyOTelCollectorConfig (re-)writes config.yaml with the supplied
// VM IP and drop-label set, then reloads the running collector via
// SIGHUP. Safe to call repeatedly; the collector picks up the new
// config without dropping in-flight batches.
//
// Phase 2.5 follow-up — when CONTAINARIUM_OTEL_REQUIRE_AUTH=true
// the config wires the bearertokenauth extension onto the OTLP
// receivers; every push must carry `Authorization: Bearer <secret>`.
// Default off so operators control the cutover: existing monitoring
// containers need to re-stamp the header (toggle off+on, or restart)
// before flipping enforcement on.
func (cs *CoreServices) applyOTelCollectorConfig(vmIP string, dropLabels []string) error {
	cfg := buildOTelCollectorConfig(vmIP, dropLabels, collectorBearerForConfig())
	if err := cs.incusClient.WriteFile(CoreOTelCollectorContainer, "/etc/otelcol-contrib/config.yaml", []byte(cfg), "0644"); err != nil {
		return fmt.Errorf("failed to write otelcol config: %w", err)
	}
	// best-effort reload — fine if the unit isn't up yet (first install).
	_ = cs.incusClient.Exec(CoreOTelCollectorContainer, []string{"systemctl", "reload-or-restart", "otelcol-contrib"})
	return nil
}

// collectorBearerForConfig returns the bearer to bake into
// the collector's config.yaml, or "" to skip enforcement.
// Empty when CONTAINARIUM_OTEL_REQUIRE_AUTH is unset / not
// recognized, or when the bearer load itself fails.
//
// Cutover sequence for operators:
//  1. Run the new daemon (bearer auto-created; header
//     stamped on new monitoring containers).
//  2. Re-toggle monitoring on existing containers so they
//     pick up the header (or restart, which re-stamps).
//  3. Set CONTAINARIUM_OTEL_REQUIRE_AUTH=true and restart
//     the daemon. Now the collector enforces; any
//     container without the header drops silently (and
//     that's the signal to find the laggard).
func collectorBearerForConfig() string {
	raw := strings.TrimSpace(os.Getenv(appconfig.EnvOTELRequireAuth))
	on := false
	switch strings.ToLower(raw) {
	case "1", "true", "yes", "on":
		on = true
	}
	if !on {
		return ""
	}
	bearer, err := LoadOrCreateOTelBearer()
	if err != nil || bearer == "" {
		// Auth required but no bearer available — that's a
		// misconfig. Log noisily and skip enforcement so the
		// collector doesn't refuse everything.
		log.Printf("[otel-collector] CONTAINARIUM_OTEL_REQUIRE_AUTH=true but bearer unavailable (%v); collector will NOT enforce auth", err)
		return ""
	}
	log.Printf("[otel-collector] bearer auth ENFORCED on OTLP receivers")
	return bearer
}

// ContainerIPEntry is the identity attributed to a source IP in
// container_ips.json. It carries BOTH the local incus name (for in-cluster
// Grafana, which keys on container_name) and the cloud_container_id (the
// cloud control plane's join key — what cloud-daemon's MetricsService queries
// by; see the cloud's metrics.VictoriaMetrics, which selects
// {container_id="<cloud uuid>"}). CloudContainerID is empty for standalone /
// CLI-created boxes that carry no cloud label.
//
// The source.ip → container.id join that consumes this (the OTel collector's
// "v2" attribution step) is still pending — but capturing the cloud id at the
// source here means that join, however it lands, can stamp the
// cloud-queryable label rather than only the local name.
type ContainerIPEntry struct {
	Name             string `json:"name"`
	CloudContainerID string `json:"cloud_container_id,omitempty"`
}

// WriteContainerIPMap pushes the current source-IP → {name, cloud_container_id}
// map into the collector LXC at containerIPsFile. The collector reads this
// file (v2: reloads-on-mtime) for source-IP-based identity attribution.
//
// Errors are returned (not logged-and-swallowed) so the caller can
// decide whether to retry; in practice callsites log + continue.
func (cs *CoreServices) WriteContainerIPMap(ipMap map[string]ContainerIPEntry) error {
	if cs.otelCollectorIP == "" {
		// Collector not provisioned yet — silently skip. The
		// post-ensure code will re-push the map after EnsureOTelCollector.
		return nil
	}
	payload, err := json.MarshalIndent(ipMap, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal container_ips.json: %w", err)
	}
	payload = append(payload, '\n')
	if err := cs.incusClient.WriteFile(CoreOTelCollectorContainer, containerIPsFile, payload, "0644"); err != nil {
		return fmt.Errorf("failed to push container_ips.json: %w", err)
	}
	return nil
}

// GetOTelCollectorIP returns the collector's IP (empty until ensured).
func (cs *CoreServices) GetOTelCollectorIP() string {
	return cs.otelCollectorIP
}

// GetOTelCollectorEndpoint returns the OTLP/HTTP endpoint to inject
// into monitoring=true containers' OTEL_EXPORTER_OTLP_ENDPOINT.
func (cs *CoreServices) GetOTelCollectorEndpoint() string {
	if cs.otelCollectorIP == "" {
		return ""
	}
	return fmt.Sprintf("http://%s:%d", cs.otelCollectorIP, DefaultOTelOTLPHTTPPort)
}

// waitForOTelCollector polls the collector's internal healthcheck.
func (cs *CoreServices) waitForOTelCollector(ctx context.Context) error {
	log.Printf("Waiting for otelcol-contrib to be ready...")
	for i := 0; i < 30; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		// otelcol-contrib's default healthcheck extension binds 13133.
		if err := cs.incusClient.Exec(CoreOTelCollectorContainer, []string{
			"curl", "-sf", "http://localhost:13133/",
		}); err == nil {
			log.Printf("otelcol-contrib is ready")
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("timeout waiting for otelcol-contrib")
}

// mergeOTelDropLabels returns a sorted, de-duplicated union of two
// drop-label slices. Exported only via Ensure* — keeping it local
// avoids leaking the helper into the public API.
func mergeOTelDropLabels(base, extra []string) []string {
	seen := make(map[string]struct{}, len(base)+len(extra))
	for _, s := range base {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		seen[s] = struct{}{}
	}
	for _, s := range extra {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		seen[s] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// otelReceiverBindAddress returns the address the OTel collector
// should bind its OTLP receivers to. Default is 0.0.0.0 — fine in
// the existing single-LXC deployment where the collector container
// has no external interface (only the incusbr0 bridge IP), but
// audit C-HIGH-5 flagged the literal "0.0.0.0" string as a hazard:
// if a future deployment configures the collector LXC with an
// extra external interface (NAT mapping, direct bridge to a public
// VLAN, etc.) the OTLP ports would suddenly accept un-authenticated
// requests from the internet.
//
// Operators in paranoid environments override via
// CONTAINARIUM_OTEL_COLLECTOR_BIND (e.g. "10.0.3.5" — the
// collector's specific bridge IP) so the listen socket is pinned
// to the bridge interface explicitly.
func otelReceiverBindAddress() string {
	if v := strings.TrimSpace(os.Getenv(appconfig.EnvOTELCollectorBind)); v != "" {
		return v
	}
	return "0.0.0.0"
}

// buildOTelCollectorConfig renders config.yaml for the collector.
// Pure function (no side effects) so it's trivially testable.
//
// When `bearer` is non-empty, the OTLP receivers are gated by the
// bearertokenauth extension — every push must carry
// `Authorization: Bearer <bearer>` or the collector responds with
// 401. Empty bearer omits the auth wiring entirely (pre-2.5
// behavior). See collectorBearerForConfig for the env-gated
// resolution.
func buildOTelCollectorConfig(vmIP string, dropLabels []string, bearer string) string {
	// Compose the OTTL drop-keys regex once. Each label becomes an
	// anchored alternation: ^request_id$|^trace_id$|...
	var dropRegex string
	if len(dropLabels) > 0 {
		parts := make([]string, 0, len(dropLabels))
		for _, l := range dropLabels {
			parts = append(parts, "^"+regexEscape(l)+"$")
		}
		dropRegex = strings.Join(parts, "|")
	}

	bind := otelReceiverBindAddress()

	// Phase 2.5 follow-up — when a bearer is supplied, wire
	// the bearertokenauth extension onto both OTLP protocol
	// receivers. The receiver-level `auth.authenticator` key
	// tells the collector to require a matching token on
	// every push.
	authBlock := ""
	if bearer != "" {
		authBlock = `
        auth:
          authenticator: bearertokenauth`
	}

	var b strings.Builder
	fmt.Fprintf(&b, `receivers:
  otlp:
    protocols:
      http:
        endpoint: %s:4318%s
      grpc:
        endpoint: %s:4317%s

processors:`, bind, authBlock, bind, authBlock)
	b.WriteString(`

  # Anti-spoofing: stamp source.ip from the OTLP client.address so a
  # misbehaving container cannot fake provenance. v1 surfaces the raw
  # IP; v2 will join it with /var/lib/containarium/container_ips.json
  # (source.ip → {name, cloud_container_id}) to materialize a
  # container.id label = the cloud_container_id, which the cloud
  # control plane's MetricsService queries by.
  attributes/identity:
    actions:
      - key: source.ip
        action: upsert
        from_attribute: client.address

`)

	if dropRegex != "" {
		fmt.Fprintf(&b, `  # Cardinality guard: drop high-cardinality / PII labels per
  # docs/OTEL-COLLECTOR-DESIGN.md §5. Operators can extend the list
  # via --otel-drop-labels; defaults are always applied.
  transform:
    metric_statements:
      - context: datapoint
        statements:
          - delete_matching_keys(attributes, %q)

`, dropRegex)
	}

	b.WriteString(`  batch:
    timeout: 5s
    send_batch_size: 1024

`)
	// extensions block: always health_check; bearertokenauth
	// added when bearer is non-empty.
	if bearer != "" {
		fmt.Fprintf(&b, `extensions:
  bearertokenauth:
    scheme: "Bearer"
    token: "%s"
  health_check:
    endpoint: %s:13133

`, bearer, bind)
	} else {
		fmt.Fprintf(&b, `extensions:
  health_check:
    endpoint: %s:13133

`, bind)
	}
	b.WriteString(`exporters:
  otlphttp:
    endpoint: `)
	fmt.Fprintf(&b, "http://%s:%d/opentelemetry\n", vmIP, DefaultVMPort)
	b.WriteString(`    tls:
      insecure: true

service:
`)
	if bearer != "" {
		b.WriteString("  extensions: [bearertokenauth, health_check]\n")
	} else {
		b.WriteString("  extensions: [health_check]\n")
	}
	b.WriteString(`  pipelines:
    metrics:
      receivers: [otlp]
`)
	if dropRegex != "" {
		b.WriteString("      processors: [attributes/identity, transform, batch]\n")
	} else {
		b.WriteString("      processors: [attributes/identity, batch]\n")
	}
	b.WriteString("      exporters: [otlphttp]\n")
	return b.String()
}

// regexEscape escapes the small set of regex metacharacters that
// could appear in an OTel attribute key. Attribute keys per the OTel
// spec are dotted lowercase identifiers, so the realistic risk
// surface is small; we escape conservatively rather than pull in
// regexp.QuoteMeta and a stdlib dependency for a 10-char input.
func regexEscape(s string) string {
	const metas = `.+*?()[]{}|^$\`
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if strings.ContainsRune(metas, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}
