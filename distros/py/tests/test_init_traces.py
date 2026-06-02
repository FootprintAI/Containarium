"""Tests for the traces pipeline + OTLP transport selection (#386)."""
import os
from unittest import mock

import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider as SDKTracerProvider

from containarium_telemetry import init
from containarium_telemetry._config import DistroConfig
from containarium_telemetry._init import (
    _make_metric_exporter,
    _make_span_exporter,
    _otlp_protocol,
    _reset_for_tests,
)


@pytest.fixture(autouse=True)
def _reset():
    _reset_for_tests()
    yield
    _reset_for_tests()


def _cfg(protocol):
    return DistroConfig(
        endpoint="http://127.0.0.1:4318",
        service_name=None,
        resource_attributes=None,
        headers=None,
        protocol=protocol,
        container_id=None,
        backend_id=None,
        tenant_id=None,
        service_version=None,
    )


@pytest.mark.parametrize(
    "raw,expected",
    [
        (None, "http/protobuf"),   # default — unchanged behavior
        ("grpc", "grpc"),
        ("GRPC", "grpc"),          # case-insensitive
        ("  grpc  ", "grpc"),      # trimmed
        ("http/protobuf", "http/protobuf"),
    ],
)
def test_otlp_protocol_normalization(raw, expected):
    assert _otlp_protocol(_cfg(raw)) == expected


def test_metric_exporter_transport_selection():
    assert "proto.http" in type(_make_metric_exporter("http/protobuf")).__module__
    assert "proto.grpc" in type(_make_metric_exporter("grpc")).__module__


def test_span_exporter_transport_selection():
    assert "proto.http" in type(_make_span_exporter("http/protobuf")).__module__
    assert "proto.grpc" in type(_make_span_exporter("grpc")).__module__


def test_init_installs_real_tracer_provider():
    # Before #386 init() installed a NoOpTracerProvider and silently
    # dropped spans; now it installs a real SDK TracerProvider so spans
    # created via trace.get_tracer(...) are actually exported.
    env = {"OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:4318"}
    with mock.patch.dict(os.environ, env, clear=True):
        handle = init(instrumentations="off")
    assert isinstance(trace.get_tracer_provider(), SDKTracerProvider)
    handle.shutdown(timeout_s=1.0)


def test_init_grpc_protocol_constructs_both_exporters(caplog):
    # With grpc selected and the gRPC exporter installed (dev extra),
    # init() builds both the metric and span pipelines without falling
    # open — no "init failed" warning, and a meter provider is wired.
    env = {
        "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:4317",
        "OTEL_EXPORTER_OTLP_PROTOCOL": "grpc",
    }
    with mock.patch.dict(os.environ, env, clear=True):
        with caplog.at_level("WARNING", logger="containarium_telemetry"):
            handle = init(instrumentations="off")
    assert not any("init failed" in r.message for r in caplog.records)
    assert handle._provider is not None  # meter provider wired
    handle.shutdown(timeout_s=1.0)
