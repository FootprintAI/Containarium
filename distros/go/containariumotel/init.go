package containariumotel

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/trace/noop"
)

// ShutdownFunc flushes any in-flight metric batches and tears down
// the SDK. Idempotent — calling it twice is a no-op.
type ShutdownFunc func(context.Context) error

// noopShutdown is returned in the fail-open path (no endpoint
// configured) so callers can defer shutdown(ctx) unconditionally.
func noopShutdown(_ context.Context) error { return nil }

// ErrInitFailed signals a non-fatal init error. Callers should log
// and continue — Init never aborts process startup itself.
var ErrInitFailed = errors.New("containariumotel: init failed")

// initState is package-level to make Init idempotent: repeated calls
// return the existing shutdown handle instead of double-installing
// the MeterProvider.
var (
	initOnce     sync.Once
	initShutdown ShutdownFunc = noopShutdown
	initErr      error
)

// Init wires the OTel SDK with the Containarium telemetry distro
// defaults and returns a shutdown func and any non-fatal error.
//
// Fail-open contract (matches the Python distro): when
// OTEL_EXPORTER_OTLP_ENDPOINT is unset, Init logs a WARN, registers
// nothing, and returns (noopShutdown, nil). The app keeps running.
//
// Idempotent: repeated calls return the existing shutdown handle.
// The wrapping sync.Once guarantees we don't install multiple
// MeterProviders.
func Init(ctx context.Context, opts ...Option) (ShutdownFunc, error) {
	initOnce.Do(func() {
		initShutdown, initErr = doInit(ctx, opts...)
	})
	return initShutdown, initErr
}

func doInit(ctx context.Context, opts ...Option) (ShutdownFunc, error) {
	options := defaultOptions()
	for _, opt := range opts {
		opt(&options)
	}

	cfg := ConfigFromEnv()

	// WithServiceName overrides env only if env isn't already set —
	// matches the Python distro's setdefault-style precedence.
	if options.serviceName != "" && cfg.ServiceName == "" {
		_ = os.Setenv("OTEL_SERVICE_NAME", options.serviceName)
		cfg.ServiceName = options.serviceName
	}

	if cfg.Endpoint == "" {
		log.Printf(
			"containariumotel: OTEL_EXPORTER_OTLP_ENDPOINT not set; " +
				"telemetry will be a no-op. Enable monitoring on the LXC " +
				"with `containarium monitoring enable <username>`.",
		)
		return noopShutdown, nil
	}

	res, err := buildResource(ctx, cfg, options.extraAttrs, version)
	if err != nil {
		log.Printf("containariumotel: build resource failed: %v", err)
		return noopShutdown, fmt.Errorf("%w: %v", ErrInitFailed, err)
	}

	// OTLP/HTTP exporter — reads endpoint, headers, protocol from env
	// directly. Don't pass them as constructor args; that would
	// shadow user overrides we're meant to honor.
	exporter, err := otlpmetrichttp.New(ctx)
	if err != nil {
		log.Printf("containariumotel: create OTLP exporter failed: %v", err)
		return noopShutdown, fmt.Errorf("%w: %v", ErrInitFailed, err)
	}

	reader := sdkmetric.NewPeriodicReader(exporter,
		sdkmetric.WithInterval(options.metricInterval),
		sdkmetric.WithTimeout(options.metricTimeout),
	)
	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(reader),
	)
	otel.SetMeterProvider(provider)

	// No-op tracer provider so apps that call otel.Tracer(...) don't
	// crash — v1 collector is metrics-only (D4). v2 traces pipeline
	// will replace this with a real provider.
	otel.SetTracerProvider(noop.NewTracerProvider())

	var shutdownOnce sync.Once
	shutdown := func(ctx context.Context) error {
		var err error
		shutdownOnce.Do(func() {
			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			err = provider.Shutdown(ctx)
		})
		return err
	}
	return shutdown, nil
}

// _resetForTests resets the module-level init state. Tests only —
// not part of the public API. Lowercase so callers from other
// packages can't reach it.
func _resetForTests() {
	initOnce = sync.Once{}
	initShutdown = noopShutdown
	initErr = nil
}
