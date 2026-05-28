"""Distro init — the public entry point.

Contract (per docs/TELEMETRY-DISTRO-DESIGN.md):
- Always fail-open. Missing endpoint → WARN + no-op handle (D10).
- Idempotent. Repeat calls log at DEBUG and return the existing handle.
- The OTLPMetricExporter reads OTEL_EXPORTER_OTLP_{ENDPOINT,HEADERS,
  PROTOCOL} from env directly, so we do not pass them as constructor
  args — that would shadow user overrides we're meant to honor.
"""
from __future__ import annotations

import logging
import os
from typing import Dict, Optional

from opentelemetry import metrics, trace
from opentelemetry.exporter.otlp.proto.http.metric_exporter import (
    OTLPMetricExporter,
)
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.trace import NoOpTracerProvider

from ._config import DistroConfig
from ._distro import AUTO_INSTRUMENT_ENV_KEY
from ._instrumentations import InstrumentationsArg, register_instrumentations
from ._resource import build_resource

logger = logging.getLogger("containarium_telemetry")

_initialized: bool = False
_shutdown_handle: Optional["Shutdown"] = None


class Shutdown:
    """Idempotent shutdown handle returned by init()."""

    def __init__(self, provider: Optional[MeterProvider]):
        self._provider = provider
        self._done = False

    def shutdown(self, timeout_s: float = 5.0) -> None:
        if self._done:
            return
        self._done = True
        if self._provider is None:
            return
        try:
            self._provider.shutdown(timeout_millis=int(timeout_s * 1000))
        except Exception as e:  # noqa: BLE001 — never raise from shutdown
            logger.warning("containarium_telemetry shutdown failed: %s", e)

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

    try:
        resource = build_resource(config, extra_attrs=extra_attrs)
        exporter = OTLPMetricExporter()
        reader = PeriodicExportingMetricReader(
            exporter,
            export_interval_millis=metric_export_interval_ms,
            export_timeout_millis=metric_export_timeout_ms,
        )
        provider = MeterProvider(resource=resource, metric_readers=[reader])
        metrics.set_meter_provider(provider)
    except Exception as e:  # noqa: BLE001 — fail-open per contract
        logger.warning("containarium_telemetry init failed: %s", e)
        _shutdown_handle = Shutdown(None)
        _initialized = True
        return _shutdown_handle

    # No-op tracer provider so apps that call trace.get_tracer(...)
    # don't crash — v1 collector accepts metrics only (D4). The v2
    # traces pipeline will replace this with a real provider.
    _set_noop_tracer_provider_if_unset()

    # Skip instrumentation registration when invoked from the
    # auto-instrument runtime (containarium-instrument /
    # opentelemetry-instrument) — the runtime registers them itself
    # after we return.
    if os.environ.get(AUTO_INSTRUMENT_ENV_KEY) != "1":
        register_instrumentations(instrumentations)

    _shutdown_handle = Shutdown(provider)
    _initialized = True
    return _shutdown_handle


def _set_noop_tracer_provider_if_unset() -> None:
    """Install NoOpTracerProvider only if no real one is configured.

    OTel's default `ProxyTracerProvider` already returns no-op spans
    when nothing has been set, so this is mostly belt-and-braces — but
    it makes the v1→v2 transition cleaner (one call to flip).
    """
    current = trace.get_tracer_provider()
    # Only stamp if nothing real has been installed yet. Don't clobber
    # an app that already wired its own tracer.
    if type(current).__name__ == "ProxyTracerProvider":
        trace.set_tracer_provider(NoOpTracerProvider())


def _reset_for_tests() -> None:
    """Reset module-level init state. Tests only — not part of the API."""
    global _initialized, _shutdown_handle
    _initialized = False
    _shutdown_handle = None
