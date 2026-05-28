"""Env-driven configuration for the distro.

The dataclass exists so tests can construct it directly without
monkey-patching os.environ — every other module in the distro reads
from a DistroConfig, never from os.getenv().
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class DistroConfig:
    # OTel-standard env vars (the SDK also reads these directly; we
    # capture them here for diagnostics and for code paths that need
    # to branch on their presence).
    endpoint: Optional[str]
    service_name: Optional[str]
    resource_attributes: Optional[str]
    headers: Optional[str]
    protocol: Optional[str]

    # Containarium-stamped env vars (split form per
    # docs/OTEL-AGENT-RELAY-DESIGN.md decision #5).
    container_id: Optional[str]
    backend_id: Optional[str]
    tenant_id: Optional[str]

    # Tenant-controlled, used for service.version stamping.
    service_version: Optional[str]

    @classmethod
    def from_env(cls, env: Optional[dict] = None) -> "DistroConfig":
        e = env if env is not None else os.environ

        def get(key: str) -> Optional[str]:
            v = e.get(key)
            if v is None or v == "":
                return None
            return v

        return cls(
            endpoint=get("OTEL_EXPORTER_OTLP_ENDPOINT"),
            service_name=get("OTEL_SERVICE_NAME"),
            resource_attributes=get("OTEL_RESOURCE_ATTRIBUTES"),
            headers=get("OTEL_EXPORTER_OTLP_HEADERS"),
            protocol=get("OTEL_EXPORTER_OTLP_PROTOCOL"),
            container_id=get("CONTAINARIUM_CONTAINER_ID"),
            backend_id=get("CONTAINARIUM_BACKEND_ID"),
            tenant_id=get("CONTAINARIUM_TENANT_ID"),
            service_version=get("SERVICE_VERSION"),
        )
