import os
from unittest import mock

from containarium_telemetry._distro import (
    AUTO_INSTRUMENT_ENV_KEY,
    ContainariumConfigurator,
    ContainariumDistro,
)
from containarium_telemetry._init import _reset_for_tests


def test_distro_sets_env_defaults_when_unset():
    with mock.patch.dict(os.environ, {}, clear=True):
        ContainariumDistro()._configure()
        assert os.environ["OTEL_METRICS_EXPORTER"] == "otlp"
        # Traces + logs muted in v1 (decision D4).
        assert os.environ["OTEL_TRACES_EXPORTER"] == "none"
        assert os.environ["OTEL_LOGS_EXPORTER"] == "none"
        assert os.environ["OTEL_EXPORTER_OTLP_PROTOCOL"] == "http/protobuf"


def test_distro_respects_user_env():
    user_env = {
        "OTEL_METRICS_EXPORTER": "user",
        "OTEL_TRACES_EXPORTER": "user",
        "OTEL_LOGS_EXPORTER": "user",
        "OTEL_EXPORTER_OTLP_PROTOCOL": "user",
    }
    with mock.patch.dict(os.environ, user_env, clear=True):
        ContainariumDistro()._configure()
        assert os.environ["OTEL_METRICS_EXPORTER"] == "user"
        assert os.environ["OTEL_TRACES_EXPORTER"] == "user"
        assert os.environ["OTEL_LOGS_EXPORTER"] == "user"
        assert os.environ["OTEL_EXPORTER_OTLP_PROTOCOL"] == "user"


def test_configurator_sets_auto_instrument_sentinel_before_init():
    _reset_for_tests()
    env = {
        "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:4318",
    }
    with mock.patch.dict(os.environ, env, clear=True):
        ContainariumConfigurator()._configure()
        assert os.environ.get(AUTO_INSTRUMENT_ENV_KEY) == "1"
    _reset_for_tests()


def test_configurator_no_op_when_endpoint_missing():
    # Configurator should still call init() (which fail-opens), not crash.
    _reset_for_tests()
    with mock.patch.dict(os.environ, {}, clear=True):
        ContainariumConfigurator()._configure()
    _reset_for_tests()
