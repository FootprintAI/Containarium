package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/footprintai/containarium/internal/app"
	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/metrics/cloudexport"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"go.opentelemetry.io/otel/sdk/resource"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// defaultMetricsExportSinks is the production sink registry passed to
// SetMetricsExportSinks by NewDualServer at startup. Extracted to its
// own named, unit-tested function rather than an inline map literal at
// the call site — a PR review of #1069 caught exactly this call being
// silently absent from production startup (sinks only ever injected by
// hand in tests), which made every real daemon return Unimplemented
// for GCP regardless of valid credentials. AWS has no Sink
// implementation yet and is intentionally left unregistered — the
// enum-validation check in SetMetricsExport rejects it before any sink
// lookup happens.
func defaultMetricsExportSinks() map[pb.CloudMetricsProvider]cloudexport.Sink {
	return map[pb.CloudMetricsProvider]cloudexport.Sink{
		pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_GCP: cloudexport.NewGCPSink(),
	}
}

// SetMetricsExportSinks wires the provider -> Sink map consulted by
// SetMetricsExport's enable-time credential probe. Called once by
// DualServer at startup with defaultMetricsExportSinks(); tests inject
// fakes so the probe never touches real GCP ADC. A provider absent from
// the map (including AWS, which has no Sink implementation yet) makes
// SetMetricsExport return Unimplemented.
func (s *ContainerServer) SetMetricsExportSinks(sinks map[pb.CloudMetricsProvider]cloudexport.Sink) {
	s.metricsExportMu.Lock()
	defer s.metricsExportMu.Unlock()
	s.metricsExportSinks = sinks
}

func (s *ContainerServer) metricsExportSink(provider pb.CloudMetricsProvider) cloudexport.Sink {
	s.metricsExportMu.RLock()
	defer s.metricsExportMu.RUnlock()
	if s.metricsExportSinks == nil {
		return nil
	}
	return s.metricsExportSinks[provider]
}

// daemonConfigKV is the narrow slice of *app.DaemonConfigStore the
// server actually uses (per-key get/set of daemon_config rows). An
// interface rather than the concrete Postgres type so tests can back
// it with an in-memory map and cover the persist/resume round trip —
// coverage the concrete type made impossible, which is how the
// hydrate-before-wiring ordering bug shipped unnoticed.
type daemonConfigKV interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key, value string) error
}

// SetDaemonConfigStore wires the persistent daemon-config store the
// metrics export config survives restarts through. NewDualServer MUST
// call this before StartMetricsExportIfEnabled — the resume path
// hydrates from this store, and hydrating before it is wired reads the
// disabled default instead of the operator's persisted enable (the
// #1070 live test on a GCP backend caught exactly that ordering: the
// store used to be assigned only much later, via SetAlertManager, so
// resume-on-restart never fired). Nil is ignored so a daemon without
// Postgres keeps the in-memory-only behavior without a typed-nil
// interface sneaking past the != nil checks.
func (s *ContainerServer) SetDaemonConfigStore(store *app.DaemonConfigStore) {
	if store == nil {
		return
	}
	s.daemonConfigStore = store
}

// getMetricsExportConfig returns the current cloud metrics export
// config, hydrating from the persisted store on first access so a
// daemon restart doesn't silently forget an enabled export. Once
// loaded, the in-memory copy is authoritative — SetMetricsExport keeps
// it and the store in sync on every write. When no store is wired
// (yet), the defaults are returned WITHOUT being cached as loaded, so
// a store wired later in startup is still consulted on the next read
// rather than being shadowed by a poisoned "disabled" copy.
func (s *ContainerServer) getMetricsExportConfig(ctx context.Context) cloudexport.Config {
	s.metricsExportMu.RLock()
	loaded := s.metricsExportConfigLoaded
	cfg := s.metricsExportConfig
	s.metricsExportMu.RUnlock()
	if loaded {
		return cfg
	}

	cfg = cloudexport.DefaultConfig()
	if s.daemonConfigStore == nil {
		return cfg
	}
	if raw, err := s.daemonConfigStore.Get(ctx, cloudexport.ConfigStoreKey); err == nil && raw != "" {
		var persisted cloudexport.Config
		if jsonErr := json.Unmarshal([]byte(raw), &persisted); jsonErr == nil {
			cfg = persisted
		} else {
			log.Printf("Warning: failed to parse persisted metrics export config, using defaults: %v", jsonErr)
		}
	}

	s.metricsExportMu.Lock()
	s.metricsExportConfig = cfg
	s.metricsExportConfigLoaded = true
	s.metricsExportMu.Unlock()
	return cfg
}

// saveMetricsExportConfig updates the in-memory config (so a subsequent
// GetMetricsExport reflects it with no daemon restart) and, when a
// daemonConfigStore is wired, persists the whole struct as one
// JSON-encoded value under cloudexport.ConfigStoreKey. One key holding
// the complete struct is a full-config round trip by construction on
// every write — there is no partial-field update that could clobber a
// sibling setting the way a scoped PUT once did to the BYOC ingress
// "listen" array (#1062/#1064).
func (s *ContainerServer) saveMetricsExportConfig(ctx context.Context, cfg cloudexport.Config) {
	s.metricsExportMu.Lock()
	s.metricsExportConfig = cfg
	s.metricsExportConfigLoaded = true
	s.metricsExportMu.Unlock()

	if s.daemonConfigStore == nil {
		return
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		log.Printf("Warning: failed to marshal metrics export config: %v", err)
		return
	}
	if err := s.daemonConfigStore.Set(ctx, cloudexport.ConfigStoreKey, string(raw)); err != nil {
		log.Printf("Warning: failed to persist metrics export config: %v", err)
	}
}

// SetMetricsExport enables or disables opt-in export of host/container
// infra metrics to the host cloud's native monitoring (#1069). Enabling
// requires a supported provider (currently just GCP — AWS is a reserved
// enum value that returns Unimplemented) and a synchronous credential
// probe against that provider; a failed probe returns FailedPrecondition
// with the sink's remediation hint and persists nothing. Disabling
// always succeeds and stops emission within one export interval once
// the collector (#1070/#1071) is wired — for #1069 it flips the
// persisted flag immediately, which is what a not-yet-built collector
// would poll.
func (s *ContainerServer) SetMetricsExport(ctx context.Context, req *pb.SetMetricsExportRequest) (*pb.SetMetricsExportResponse, error) {
	// Mirrors GetSystemInfo: this exposes/controls host-level
	// configuration, not anything tenant-scoped. A user token has no
	// legitimate reason to flip a host's cloud-billing-relevant export
	// toggle.
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	current := s.getMetricsExportConfig(ctx)

	if !req.Enabled {
		current.Enabled = false
		if current.IntervalSeconds == 0 {
			current.IntervalSeconds = cloudexport.DefaultIntervalSeconds
		}
		s.saveMetricsExportConfig(ctx, current)
		// Stop the running collector — emission ends within one
		// interval (in practice immediately: Shutdown flushes then
		// halts the reader).
		s.swapMetricsExportCollector(ctx, nil)
		return &pb.SetMetricsExportResponse{
			Message:         "cloud metrics export disabled",
			Enabled:         false,
			Provider:        current.Provider,
			IntervalSeconds: current.IntervalSeconds,
		}, nil
	}

	switch req.Provider {
	case pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_UNSPECIFIED:
		return nil, status.Error(codes.InvalidArgument, "provider is required to enable cloud metrics export")
	case pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_AWS:
		return nil, status.Error(codes.Unimplemented, "AWS cloud metrics export is not yet implemented — only gcp is supported")
	case pb.CloudMetricsProvider_CLOUD_METRICS_PROVIDER_GCP:
		// supported, fall through to the probe below.
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unknown cloud metrics export provider %v", req.Provider)
	}

	sink := s.metricsExportSink(req.Provider)
	if sink == nil {
		return nil, status.Errorf(codes.Unimplemented, "no metrics export sink registered for provider %v", req.Provider)
	}
	if err := sink.Probe(ctx); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "cloud metrics export credential check failed: %v", err)
	}

	newCfg := cloudexport.Config{
		Enabled:         true,
		Provider:        req.Provider,
		IntervalSeconds: cloudexport.DefaultIntervalSeconds,
	}

	// Build and start the real host-series collector before persisting
	// "enabled" — a build/start failure (exporter construction, Incus
	// dial) returns an error and leaves the prior state untouched, same
	// fail-closed posture as the probe above.
	collector, err := s.buildCollector(ctx, newCfg, sink)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "cloud metrics export could not start: %v", err)
	}
	if err := collector.Start(ctx); err != nil {
		return nil, status.Errorf(codes.Internal, "cloud metrics export failed to start: %v", err)
	}
	s.swapMetricsExportCollector(ctx, collector)
	s.saveMetricsExportConfig(ctx, newCfg)

	return &pb.SetMetricsExportResponse{
		Message:         fmt.Sprintf("cloud metrics export enabled for %s", metricsExportProviderLabel(req.Provider)),
		Enabled:         true,
		Provider:        req.Provider,
		IntervalSeconds: newCfg.IntervalSeconds,
	}, nil
}

// buildCollector routes to the test seam when set, else the real
// Incus-backed builder.
func (s *ContainerServer) buildCollector(ctx context.Context, cfg cloudexport.Config, sink cloudexport.Sink) (*cloudexport.CloudExportCollector, error) {
	if s.metricsExportBuilder != nil {
		return s.metricsExportBuilder(ctx, cfg, sink)
	}
	return s.buildMetricsExportCollector(ctx, cfg, sink)
}

// buildMetricsExportCollector assembles (but does not start) a host-
// series collector for cfg: the production Sources adapter over the
// daemon's Manager/Incus, the provider exporter from sink.NewExporter,
// the provider's monitored-resource identity (gce_instance for GCP) when
// the sink offers one, and the fixed backend_id/hostname/region label
// set. Returns an error if the daemon lacks a Manager or the exporter
// can't be built.
func (s *ContainerServer) buildMetricsExportCollector(ctx context.Context, cfg cloudexport.Config, sink cloudexport.Sink) (*cloudexport.CloudExportCollector, error) {
	if s.manager == nil {
		return nil, fmt.Errorf("no container manager wired")
	}
	sources, err := newServerMetricsSources(s.manager)
	if err != nil {
		return nil, err
	}
	exporter, err := sink.NewExporter(ctx, cloudexport.SinkConfig{})
	if err != nil {
		return nil, fmt.Errorf("build exporter: %w", err)
	}

	var res *resource.Resource
	if rp, ok := sink.(cloudexport.ResourceProvider); ok {
		if r, derr := rp.DetectResource(ctx); derr == nil {
			res = r
		} else {
			log.Printf("Warning: metrics export resource detection failed, using default resource: %v", derr)
		}
	}

	return cloudexport.NewCollector(cloudexport.CollectorOptions{
		Sources:  sources,
		Exporter: exporter,
		Resource: res,
		Labels: cloudexport.Labels{
			BackendID: s.localBackendID(),
			Hostname:  sources.Hostname(),
			Region:    s.region,
		},
		IntervalSeconds: cfg.IntervalSeconds,
	}), nil
}

// swapMetricsExportCollector installs newC as the running collector
// (nil to stop entirely) and shuts down whatever was running before,
// outside the lock so a slow Stop never blocks a concurrent
// GetMetricsExport read.
func (s *ContainerServer) swapMetricsExportCollector(ctx context.Context, newC *cloudexport.CloudExportCollector) {
	s.metricsExportMu.Lock()
	old := s.metricsExportCollector
	s.metricsExportCollector = newC
	s.metricsExportMu.Unlock()
	if old != nil {
		_ = old.Stop(ctx)
	}
}

// StartMetricsExportIfEnabled resumes export on daemon startup when the
// persisted config says it was enabled — so an operator who enabled
// export before a restart doesn't silently lose it. Best-effort: a
// build/start failure (e.g. ADC no longer resolvable) is logged and the
// daemon boots normally; the operator re-enables to retry. Called once
// by DualServer after SetMetricsExportSinks.
func (s *ContainerServer) StartMetricsExportIfEnabled(ctx context.Context) {
	cfg := s.getMetricsExportConfig(ctx)
	if !cfg.Enabled {
		return
	}
	sink := s.metricsExportSink(cfg.Provider)
	if sink == nil {
		log.Printf("Warning: metrics export was enabled for %s but no sink is registered; not resuming", metricsExportProviderLabel(cfg.Provider))
		return
	}
	collector, err := s.buildCollector(ctx, cfg, sink)
	if err != nil {
		log.Printf("Warning: could not resume metrics export on startup: %v", err)
		return
	}
	if err := collector.Start(ctx); err != nil {
		log.Printf("Warning: could not start resumed metrics export collector: %v", err)
		return
	}
	s.swapMetricsExportCollector(ctx, collector)
	log.Printf("Resumed cloud metrics export for %s", metricsExportProviderLabel(cfg.Provider))
}

// GetMetricsExport reports the current cloud metrics export
// configuration and last-known health. last_success_at, last_error, and
// export_failures come from the running collector (#1070); when export
// is disabled (no collector) they are zero-valued.
func (s *ContainerServer) GetMetricsExport(ctx context.Context, req *pb.GetMetricsExportRequest) (*pb.GetMetricsExportResponse, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}

	cfg := s.getMetricsExportConfig(ctx)
	resp := &pb.GetMetricsExportResponse{
		Enabled:         cfg.Enabled,
		Provider:        cfg.Provider,
		IntervalSeconds: cfg.IntervalSeconds,
	}

	s.metricsExportMu.RLock()
	collector := s.metricsExportCollector
	s.metricsExportMu.RUnlock()
	if collector != nil {
		lastSuccess, lastErr, failures := collector.Health()
		if !lastSuccess.IsZero() {
			resp.LastSuccessAt = timestamppb.New(lastSuccess)
		}
		resp.LastError = lastErr
		resp.ExportFailures = failures
	}

	return resp, nil
}

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
