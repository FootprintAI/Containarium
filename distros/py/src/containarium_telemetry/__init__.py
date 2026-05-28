"""Containarium telemetry distro for Python.

Public API:

    from containarium_telemetry import init, Shutdown

    handle = init()
    ...
    handle.shutdown(timeout_s=5.0)

See docs/TELEMETRY-DISTRO-DESIGN.md for the full contract.
"""
from ._init import Shutdown, init
from ._version import __version__

__all__ = ["init", "Shutdown", "__version__"]
