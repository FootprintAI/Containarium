"""Integration test: Flask gets auto-instrumented via the [flask] extra.

Verifies the end-to-end auto-instrumentation contract without spinning
up a real HTTP server — we install the FlaskInstrumentor via init(),
then ask it whether OpenTelemetry's global instrumented-state flag is
set on the Flask class.
"""
import os
from unittest import mock

import pytest

pytest.importorskip("flask")
pytest.importorskip("opentelemetry.instrumentation.flask")


def test_auto_instrumentation_registers_flask():
    from opentelemetry.instrumentation.flask import FlaskInstrumentor

    from containarium_telemetry import init
    from containarium_telemetry._init import _reset_for_tests

    _reset_for_tests()
    # Clean up any prior instrumentation state.
    FlaskInstrumentor().uninstrument()

    env = {
        "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:4318",
        "OTEL_SERVICE_NAME": "flask-test",
    }
    with mock.patch.dict(os.environ, env, clear=True):
        handle = init(instrumentations="auto")
        try:
            # The FlaskInstrumentor exposes a singleton flag set by
            # .instrument(); checking it is the idiomatic OTel "did the
            # patch land?" assertion.
            assert FlaskInstrumentor().is_instrumented_by_opentelemetry
        finally:
            handle.shutdown()
            FlaskInstrumentor().uninstrument()
            _reset_for_tests()


def test_off_does_not_register_flask():
    from opentelemetry.instrumentation.flask import FlaskInstrumentor

    from containarium_telemetry import init
    from containarium_telemetry._init import _reset_for_tests

    _reset_for_tests()
    FlaskInstrumentor().uninstrument()
    assert not FlaskInstrumentor().is_instrumented_by_opentelemetry

    env = {"OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:4318"}
    with mock.patch.dict(os.environ, env, clear=True):
        handle = init(instrumentations="off")
        try:
            assert not FlaskInstrumentor().is_instrumented_by_opentelemetry
        finally:
            handle.shutdown()
            _reset_for_tests()
