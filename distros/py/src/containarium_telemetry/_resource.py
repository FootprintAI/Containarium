"""Resource composition per the precedence in TELEMETRY-DISTRO-DESIGN.md.

Precedence, low to high (later wins):

  1. SDK defaults                              (Resource.create internals)
  2. Standard OTel detectors (host, process)   (Resource.create internals)
  3. Containarium env attrs                    (our cont_attrs)
  4. OTEL_RESOURCE_ATTRIBUTES env              (OTELResourceDetector)
  5. Caller's extra_attrs                      (raw Resource)
  6. containarium.distro stamp                 (defended — wins all)

Two implementation traps worth a comment:

* Resource.create() runs every default detector AND OTELResourceDetector,
  then merges the passed attrs *over* all of them. That puts our
  containarium attrs above OTEL_RESOURCE_ATTRIBUTES, which is the
  *opposite* of the precedence above. Fixed by re-merging
  OTELResourceDetector().detect() after Resource.create() returns.

* For layers 5 and 6 we use raw `Resource(...)` instead of
  Resource.create(). Otherwise OTELResourceDetector fires *inside*
  the sub-resource, re-introducing OTEL_RESOURCE_ATTRIBUTES into the
  merge — which then wins over the extra_attrs we just stamped.
"""
from __future__ import annotations

from typing import Dict, Optional

from opentelemetry.sdk.resources import OTELResourceDetector, Resource

from ._config import DistroConfig
from ._version import __version__


CONTAINARIUM_DISTRO_ATTR_KEY = "containarium.distro"


def build_resource(
    config: DistroConfig,
    extra_attrs: Optional[Dict[str, str]] = None,
    distro_version: Optional[str] = None,
) -> Resource:
    if distro_version is None:
        distro_version = __version__

    cont_attrs: Dict[str, str] = {}
    if config.container_id:
        cont_attrs["container.id"] = config.container_id
    if config.backend_id:
        cont_attrs["backend.id"] = config.backend_id
    if config.tenant_id:
        cont_attrs["service.namespace"] = config.tenant_id
    if config.service_version:
        cont_attrs["service.version"] = config.service_version

    resource = Resource.create(cont_attrs)
    # Re-stamp OTEL_RESOURCE_ATTRIBUTES on top so user-set env attrs win
    # over our Containarium-stamped attrs (see module docstring).
    resource = resource.merge(OTELResourceDetector().detect())

    if extra_attrs:
        # Raw Resource so the env detector doesn't fire again inside
        # Resource.create and re-override extra_attrs.
        resource = resource.merge(Resource(extra_attrs))

    # Defended distro stamp — applied last so nothing can override it.
    # This is a support signal, not a tenant-controlled attribute.
    resource = resource.merge(
        Resource({CONTAINARIUM_DISTRO_ATTR_KEY: f"py/{distro_version}"})
    )
    return resource
