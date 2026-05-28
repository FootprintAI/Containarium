import os
from unittest import mock

from containarium_telemetry._exec_shim import main


def test_no_args_prints_help_returns_2(capsys):
    rc = main([])
    captured = capsys.readouterr()
    assert rc == 2
    assert "containarium-instrument" in captured.out


def test_help_returns_0(capsys):
    rc = main(["--help"])
    captured = capsys.readouterr()
    assert rc == 0
    assert "Usage" in captured.out
    assert "--dry-run" in captured.out


def test_version_returns_0(capsys):
    rc = main(["--version"])
    captured = capsys.readouterr()
    assert rc == 0
    assert "containarium-instrument" in captured.out


def test_dry_run_with_no_endpoint(capsys):
    with mock.patch.dict(os.environ, {}, clear=True):
        rc = main(["--dry-run"])
    captured = capsys.readouterr()
    assert rc == 0
    assert "TELEMETRY WILL BE NO-OP" in captured.out
    assert "containarium.distro" in captured.out


def test_dry_run_with_endpoint(capsys):
    env = {
        "OTEL_EXPORTER_OTLP_ENDPOINT": "http://10.0.3.42:4318",
        "OTEL_SERVICE_NAME": "payment-api",
        "OTEL_EXPORTER_OTLP_HEADERS": "Authorization=Bearer secret-token",
        "CONTAINARIUM_CONTAINER_ID": "alice-container",
    }
    with mock.patch.dict(os.environ, env, clear=True):
        rc = main(["--dry-run"])
    captured = capsys.readouterr()
    assert rc == 0
    assert "10.0.3.42:4318" in captured.out
    assert "payment-api" in captured.out
    assert "alice-container" in captured.out
    # Bearer is redacted by default.
    assert "secret-token" not in captured.out


def test_unknown_command_attempts_execvp(capsys):
    # When `opentelemetry-instrument` isn't on PATH (which is typical in
    # a sandboxed test), we should return 127 and emit a friendly error.
    with mock.patch.dict(os.environ, {"PATH": "/nonexistent"}, clear=True):
        rc = main(["python", "app.py"])
    captured = capsys.readouterr()
    assert rc == 127
    assert "not found" in captured.err
