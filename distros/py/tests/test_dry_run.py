from containarium_telemetry._config import DistroConfig
from containarium_telemetry._dry_run import format_config


def _cfg(**overrides):
    base = dict(
        endpoint=None, service_name=None, resource_attributes=None,
        headers=None, protocol=None,
        container_id=None, backend_id=None, tenant_id=None,
        service_version=None,
    )
    base.update(overrides)
    return DistroConfig(**base)


def test_no_endpoint_reports_no_op():
    out = format_config(_cfg())
    assert "TELEMETRY WILL BE NO-OP" in out
    # Distro stamp always shown — it's the support signal.
    assert "containarium.distro" in out
    assert "py/" in out


def test_endpoint_set_reports_configured():
    out = format_config(_cfg(endpoint="http://10.0.3.42:4318"))
    assert "telemetry pipeline will be configured" in out
    assert "10.0.3.42:4318" in out


def test_bearer_redacted_by_default():
    out = format_config(
        _cfg(
            endpoint="http://x:4318",
            headers="Authorization=Bearer secret-token,X-Other=visible",
        )
    )
    assert "secret-token" not in out
    assert "<redacted>" in out
    # Non-secret headers stay visible.
    assert "X-Other=visible" in out


def test_bearer_visible_when_redact_off():
    out = format_config(
        _cfg(endpoint="http://x:4318", headers="Authorization=Bearer t"),
        redact_bearer=False,
    )
    assert "Bearer t" in out


def test_containarium_identity_section_present():
    out = format_config(
        _cfg(
            endpoint="http://x:4318",
            container_id="alice-container",
            backend_id="node-7",
            tenant_id="alice",
            service_version="v1.0.0",
        )
    )
    assert "alice-container" in out
    assert "node-7" in out
    assert "alice" in out
    assert "v1.0.0" in out
