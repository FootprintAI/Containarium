from containarium_telemetry._config import DistroConfig


def test_from_env_empty():
    cfg = DistroConfig.from_env(env={})
    assert cfg.endpoint is None
    assert cfg.service_name is None
    assert cfg.container_id is None
    assert cfg.backend_id is None
    assert cfg.tenant_id is None
    assert cfg.service_version is None
    assert cfg.resource_attributes is None
    assert cfg.headers is None
    assert cfg.protocol is None


def test_from_env_populated():
    env = {
        "OTEL_EXPORTER_OTLP_ENDPOINT": "http://10.0.3.42:4318",
        "OTEL_SERVICE_NAME": "payment-api",
        "OTEL_RESOURCE_ATTRIBUTES": "container.id=alice,backend.id=node-7",
        "OTEL_EXPORTER_OTLP_HEADERS": "Authorization=Bearer abc",
        "OTEL_EXPORTER_OTLP_PROTOCOL": "http/protobuf",
        "CONTAINARIUM_CONTAINER_ID": "alice-container",
        "CONTAINARIUM_BACKEND_ID": "node-7",
        "CONTAINARIUM_TENANT_ID": "alice",
        "SERVICE_VERSION": "v1.2.3",
    }
    cfg = DistroConfig.from_env(env=env)
    assert cfg.endpoint == "http://10.0.3.42:4318"
    assert cfg.service_name == "payment-api"
    assert cfg.resource_attributes == "container.id=alice,backend.id=node-7"
    assert cfg.headers == "Authorization=Bearer abc"
    assert cfg.protocol == "http/protobuf"
    assert cfg.container_id == "alice-container"
    assert cfg.backend_id == "node-7"
    assert cfg.tenant_id == "alice"
    assert cfg.service_version == "v1.2.3"


def test_empty_string_is_treated_as_unset():
    # Compose interpolation can produce empty strings when the source
    # env is unset (`${SERVICE_VERSION:-}`). Empty == not set, so the
    # downstream resource attrs don't stamp `service.version=""`.
    env = {
        "OTEL_EXPORTER_OTLP_ENDPOINT": "http://localhost:4318",
        "SERVICE_VERSION": "",
    }
    cfg = DistroConfig.from_env(env=env)
    assert cfg.endpoint == "http://localhost:4318"
    assert cfg.service_version is None


def test_config_is_frozen():
    cfg = DistroConfig.from_env(env={})
    try:
        cfg.endpoint = "http://x"  # type: ignore[misc]
    except (AttributeError, Exception):
        return
    raise AssertionError("DistroConfig should be frozen")
