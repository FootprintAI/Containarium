"""Distro init — the public entry point.

Contract (per docs/TELEMETRY-DISTRO-DESIGN.md):
- Always fail-open. Missing endpoint → WARN + no-op handle (D10).
- Idempotent. Repeat calls log at DEBUG and return the existing handle.
- The OTLP exporters read OTEL_EXPORTER_OTLP_{ENDPOINT,HEADERS,
  PROTOCOL} from env directly, so we do not pass them as constructor
  args — that would shadow user overrides we're meant to honor.

Transport selection (#386): OTEL_EXPORTER_OTLP_PROTOCOL picks the
exporter. `grpc` uses the gRPC exporters (OTLP :4317); anything else
(default `http/protobuf`) uses the HTTP exporters (OTLP :4318). The
gRPC exporter package is an optional `grpc` extra and is imported
lazily, so HTTP-only installs are unaffected and a missing gRPC
package fails open rather than crashing the app at import time.
"""
from __future__ import annotations

import logging
import os
from typing import Dict, Optional

from opentelemetry import metrics, trace
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

from ._config import DistroConfig
from ._distro import AUTO_INSTRUMENT_ENV_KEY
from ._instrumentations import InstrumentationsArg, register_instrumentations
from ._resource import build_resource

logger = logging.getLogger("containarium_telemetry")

_initialized: bool = False
_shutdown_handle: Optional["Shutdown"] = None


class Shutdown:
    """Idempotent shutdown handle returned by init().

    Holds whatever providers init() actually installed — the meter
    provider, and (when traces are exported) the tracer provider — and
    shuts both down. Either may be None (e.g. the fail-open no-op handle,
    or when the app already had its own tracer provider that we left
    untouched).
    """

    def __init__(
        self,
        provider: Optional[MeterProvider],
        tracer_provider: Optional[TracerProvider] = None,
    ):
        self._provider = provider
        self._tracer_provider = tracer_provider
        self._done = False

    def shutdown(self, timeout_s: float = 5.0) -> None:
        if self._done:
            return
        self._done = True
        if self._provider is not None:
            try:
                self._provider.shutdown(timeout_millis=int(timeout_s * 1000))
            except Exception as e:  # noqa: BLE001 — never raise from shutdown
                logger.warning("containarium_telemetry meter shutdown failed: %s", e)
        if self._tracer_provider is not None:
            try:
                # TracerProvider.shutdown() flushes the BatchSpanProcessor
                # and stops its worker thread. It takes no timeout arg.
                self._tracer_provider.shutdown()
            except Exception as e:  # noqa: BLE001 — never raise from shutdown
                logger.warning("containarium_telemetry tracer shutdown failed: %s", e)

    def __call__(self, timeout_s: float = 5.0) -> None:
        # Lets callers use the handle directly as `handle()` instead of
        # `handle.shutdown()` — convenient with atexit.register().
        self.shutdown(timeout_s)


def init(
    service_name: Optional[str] = None,
    extra_attrs: Optional[Dict[str, str]] = None,
    instrumentations: InstrumentationsArg = "auto",
    metric_export_interval_ms: int = 5_000,
    metric_export_timeout_ms: int = 10_000,
) -> Shutdown:
    """Initialize the distro. Returns an idempotent Shutdown handle.

    Args:
        service_name: Override OTEL_SERVICE_NAME if not already set.
        extra_attrs: Extra resource attributes — win over env attrs
            (precedence #5 in TELEMETRY-DISTRO-DESIGN.md).
        instrumentations: "auto" (default — every installed
            opentelemetry_instrumentor), "off", or a list of names.
            Skipped when invoked from `containarium-instrument` /
            `opentelemetry-instrument` (the runtime handles it).
        metric_export_interval_ms: Periodic export tick. Default 5s,
            matching the sidecar's batch processor.
        metric_export_timeout_ms: Per-export timeout. Default 10s.

    Fail-open: missing OTEL_EXPORTER_OTLP_ENDPOINT logs WARN and returns
    a no-op handle. The app never crashes because telemetry isn't wired.
    """
    global _initialized, _shutdown_handle

    if _initialized:
        logger.debug("init() called twice — returning existing handle")
        return _shutdown_handle  # type: ignore[return-value]

    if service_name:
        # setdefault — explicit user env still wins over the arg.
        os.environ.setdefault("OTEL_SERVICE_NAME", service_name)

    config = DistroConfig.from_env()

    if not config.endpoint:
        logger.warning(
            "containarium_telemetry: OTEL_EXPORTER_OTLP_ENDPOINT not set; "
            "telemetry will be a no-op. Enable monitoring on the LXC with "
            "`containarium monitoring enable <username>`."
        )
        _shutdown_handle = Shutdown(None)
        _initialized = True
        return _shutdown_handle

    protocol = _otlp_protocol(config)

    try:
        resource = build_resource(config, extra_attrs=extra_attrs)

        # Metrics pipeline.
        reader = PeriodicExportingMetricReader(
            _make_metric_exporter(protocol),
            export_interval_millis=metric_export_interval_ms,
            export_timeout_millis=metric_export_timeout_ms,
        )
        provider = MeterProvider(resource=resource, metric_readers=[reader])
        metrics.set_meter_provider(provider)

        # Traces pipeline (#386). Only install our TracerProvider when no
        # real one is set yet (OTel's default is a ProxyTracerProvider) —
        # don't clobber an app that wired its own. We attach the
        # BatchSpanProcessor only when we're the ones setting it, so we
        # never leak an exporter/worker thread onto an unused provider.
        tracer_provider: Optional[TracerProvider] = None
        if type(trace.get_tracer_provider()).__name__ == "ProxyTracerProvider":
            tracer_provider = TracerProvider(resource=resource)
            tracer_provider.add_span_processor(
                BatchSpanProcessor(_make_span_exporter(protocol))
            )
            trace.set_tracer_provider(tracer_provider)
    except Exception as e:  # noqa: BLE001 — fail-open per contract
        logger.warning("containarium_telemetry init failed: %s", e)
        _shutdown_handle = Shutdown(None)
        _initialized = True
        return _shutdown_handle

    # Skip instrumentation registration when invoked from the
    # auto-instrument runtime (containarium-instrument /
    # opentelemetry-instrument) — the runtime registers them itself
    # after we return.
    if os.environ.get(AUTO_INSTRUMENT_ENV_KEY) != "1":
        register_instrumentations(instrumentations)

    _shutdown_handle = Shutdown(provider, tracer_provider)
    _initialized = True
    return _shutdown_handle


def _otlp_protocol(config: DistroConfig) -> str:
    """Normalize OTEL_EXPORTER_OTLP_PROTOCOL.

    Per the OTel spec the value is one of `grpc`, `http/protobuf`, or
    `http/json`; the default (matching the SDK and the distro's prior
    behavior) is `http/protobuf`. Only `grpc` selects the gRPC exporter;
    everything else maps to HTTP.
    """
    return (config.protocol or "http/protobuf").strip().lower()


def _make_metric_exporter(protocol: str):
    """Build the OTLP metric exporter for the selected transport.

    gRPC is imported lazily so the optional `grpc` extra isn't required
    for the default HTTP path.
    """
    if protocol == "grpc":
        from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (
            OTLPMetricExporter,
        )

        return OTLPMetricExporter()
    from opentelemetry.exporter.otlp.proto.http.metric_exporter import (
        OTLPMetricExporter,
    )

    return OTLPMetricExporter()


def _make_span_exporter(protocol: str):
    """Build the OTLP span exporter for the selected transport."""
    if protocol == "grpc":
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
            OTLPSpanExporter,
        )

        return OTLPSpanExporter()
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
        OTLPSpanExporter,
    )

    return OTLPSpanExporter()


def _reset_for_tests() -> None:
    """Reset module-level init state. Tests only — not part of the API."""
    global _initialized, _shutdown_handle
    _initialized = False
    _shutdown_handle = None
