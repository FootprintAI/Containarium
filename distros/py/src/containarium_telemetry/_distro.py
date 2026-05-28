"""OTel Distro + Configurator entry points for the auto-instrument path.

When the user runs `containarium-instrument python app.py` (or the
upstream `opentelemetry-instrument` with this package installed), the
OTel runtime loads:

  1. ContainariumDistro._configure()  — sets exporter env defaults
  2. ContainariumConfigurator._configure() — runs our init()
  3. Then iterates registered opentelemetry_instrumentor entry points
     and calls .instrument() on each.

Our init() detects the auto-instrument context via the
_CONTAINARIUM_TELEMETRY_AUTO_INSTRUMENT env sentinel and skips its own
instrumentation-registration step so we don't double-instrument.
"""
from __future__ import annotations

import logging
import os

from opentelemetry.instrumentation.distro import BaseDistro
from opentelemetry.sdk._configuration import _BaseConfigurator

logger = logging.getLogger("containarium_telemetry")

# Sentinel set by ContainariumConfigurator. init() reads it to decide
# whether to register instrumentors itself or defer to the runtime.
AUTO_INSTRUMENT_ENV_KEY = "_CONTAINARIUM_TELEMETRY_AUTO_INSTRUMENT"


class ContainariumDistro(BaseDistro):
    """OTel Distro plugin — sets exporter env defaults.

    setdefault throughout: the user's explicit env always wins. We're a
    distro, not a policy enforcer.
    """

    def _configure(self, **kwargs) -> None:
        # OTLP metrics by default — matches the central collector.
        os.environ.setdefault("OTEL_METRICS_EXPORTER", "otlp")
        # v1 collector is metrics-only (decision D4); muting trace + log
        # export avoids the SDK fighting an empty endpoint. v2 flips
        # these to "otlp" when Tempo + Loki land.
        os.environ.setdefault("OTEL_TRACES_EXPORTER", "none")
        os.environ.setdefault("OTEL_LOGS_EXPORTER", "none")
        # Pin HTTP/protobuf — the protocol the central collector and
        # otel-sidecar both speak.
        os.environ.setdefault("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf")


class ContainariumConfigurator(_BaseConfigurator):
    """OTel Configurator plugin — installs MeterProvider via init().

    Configurators are responsible for actually wiring up the SDK
    providers (TracerProvider, MeterProvider, LoggerProvider). Only
    one configurator runs in the auto-instrument flow — ours wins
    because we register an entry point.
    """

    def _configure(self, **kwargs) -> None:
        os.environ[AUTO_INSTRUMENT_ENV_KEY] = "1"
        # Lazy import so the OTLP exporter module isn't loaded when
        # only the Distro half of the entry-point pair fires.
        from ._init import init

        init()
