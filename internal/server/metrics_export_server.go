package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/metrics/cloudexport"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SetMetricsExportSinks wires the provider -> Sink map consulted by
// SetMetricsExport's enable-time credential probe. Called once by
// DualServer at startup with the real gcpSink (internal/metrics/
// cloudexport.NewGCPSink()); tests inject fakes so the probe never
// touches real GCP ADC. A provider absent from the map (including AWS,
// which has no Sink implementation yet) makes SetMetricsExport return
// Unimplemented.
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

// getMetricsExportConfig returns the current cloud metrics export
// config, hydrating from the persisted store on first access so a
// daemon restart doesn't silently forget an enabled export. Once
// loaded, the in-memory copy is authoritative — SetMetricsExport keeps
// it and the store in sync on every write.
func (s *ContainerServer) getMetricsExportConfig(ctx context.Context) cloudexport.Config {
	s.metricsExportMu.RLock()
	loaded := s.metricsExportConfigLoaded
	cfg := s.metricsExportConfig
	s.metricsExportMu.RUnlock()
	if loaded {
		return cfg
	}

	cfg = cloudexport.DefaultConfig()
	if s.daemonConfigStore != nil {
		if raw, err := s.daemonConfigStore.Get(ctx, cloudexport.ConfigStoreKey); err == nil && raw != "" {
			var persisted cloudexport.Config
			if jsonErr := json.Unmarshal([]byte(raw), &persisted); jsonErr == nil {
				cfg = persisted
			} else {
				log.Printf("Warning: failed to parse persisted metrics export config, using defaults: %v", jsonErr)
			}
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
	s.saveMetricsExportConfig(ctx, newCfg)

	return &pb.SetMetricsExportResponse{
		Message:         fmt.Sprintf("cloud metrics export enabled for %s", metricsExportProviderLabel(req.Provider)),
		Enabled:         true,
		Provider:        req.Provider,
		IntervalSeconds: newCfg.IntervalSeconds,
	}, nil
}

// GetMetricsExport reports the current cloud metrics export
// configuration and last-known health. last_success_at, last_error, and
// export_failures are zero-valued until the collector (#1070/#1071) is
// wired — #1069 delivers the toggle, config persistence, and the
// enable-time credential probe only.
func (s *ContainerServer) GetMetricsExport(ctx context.Context, req *pb.GetMetricsExportRequest) (*pb.GetMetricsExportResponse, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}

	cfg := s.getMetricsExportConfig(ctx)
	return &pb.GetMetricsExportResponse{
		Enabled:         cfg.Enabled,
		Provider:        cfg.Provider,
		IntervalSeconds: cfg.IntervalSeconds,
	}, nil
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
