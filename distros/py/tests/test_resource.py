import os
from unittest import mock

from containarium_telemetry._config import DistroConfig
from containarium_telemetry._resource import (
    CONTAINARIUM_DISTRO_ATTR_KEY,
    build_resource,
)


def _config_with(**overrides):
    """Build a DistroConfig with only the fields named."""
    base = dict(
        endpoint=None,
        service_name=None,
        resource_attributes=None,
        headers=None,
        protocol=None,
        container_id=None,
        backend_id=None,
        tenant_id=None,
        service_version=None,
    )
    base.update(overrides)
    return DistroConfig(**base)


def test_containarium_attrs_stamped():
    cfg = _config_with(
        container_id="alice-container",
        backend_id="node-7",
        tenant_id="alice",
        service_version="v1.2.3",
    )
    # Clear OTEL_RESOURCE_ATTRIBUTES so the env detector doesn't add
    # anything that would collide with our assertions.
    with mock.patch.dict(os.environ, {}, clear=False):
        os.environ.pop("OTEL_RESOURCE_ATTRIBUTES", None)
        r = build_resource(cfg, distro_version="0.20.0")
    attrs = r.attributes
    assert attrs["container.id"] == "alice-container"
    assert attrs["backend.id"] == "node-7"
    assert attrs["service.namespace"] == "alice"
    assert attrs["service.version"] == "v1.2.3"


def test_distro_stamp_present_and_defended():
    cfg = _config_with(container_id="alice-container")
    # Even if the caller tries to override containarium.distro via
    # extra_attrs, the stamp wins because it's merged last.
    r = build_resource(
        cfg,
        extra_attrs={CONTAINARIUM_DISTRO_ATTR_KEY: "evil/override"},
        distro_version="0.20.0",
    )
    assert r.attributes[CONTAINARIUM_DISTRO_ATTR_KEY] == "py/0.20.0"


def test_otel_resource_attributes_env_wins_over_containarium():
    # User-set OTEL_RESOURCE_ATTRIBUTES should win over Containarium's
    # env-stamped attrs. This is precedence row #4 > #3 in the design.
    cfg = _config_with(
        container_id="alice-container",
        tenant_id="alice",
    )
    with mock.patch.dict(
        os.environ,
        {"OTEL_RESOURCE_ATTRIBUTES": "container.id=overridden,extra.key=hello"},
        clear=False,
    ):
        r = build_resource(cfg, distro_version="0.20.0")
    assert r.attributes["container.id"] == "overridden"
    assert r.attributes["extra.key"] == "hello"
    # Non-overridden Containarium attr survives.
    assert r.attributes["service.namespace"] == "alice"


def test_extra_attrs_win_over_env():
    cfg = _config_with(container_id="alice-container")
    with mock.patch.dict(
        os.environ,
        {"OTEL_RESOURCE_ATTRIBUTES": "k=from-env"},
        clear=False,
    ):
        r = build_resource(
            cfg,
            extra_attrs={"k": "from-extra"},
            distro_version="0.20.0",
        )
    assert r.attributes["k"] == "from-extra"


def test_missing_containarium_attrs_omitted():
    # Only container_id set — other Containarium attrs absent, not
    # stamped as empty strings.
    cfg = _config_with(container_id="alice-container")
    with mock.patch.dict(os.environ, {}, clear=False):
        os.environ.pop("OTEL_RESOURCE_ATTRIBUTES", None)
        r = build_resource(cfg, distro_version="0.20.0")
    assert "backend.id" not in r.attributes
    assert "service.namespace" not in r.attributes
    assert "service.version" not in r.attributes
