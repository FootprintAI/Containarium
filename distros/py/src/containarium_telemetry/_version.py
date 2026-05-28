"""Distro version string.

Resolved from the installed package metadata so there's a single source
of truth (`version =` in pyproject.toml). Falls back to a sentinel only
when the package isn't installed — e.g. running tests from a source
checkout without `pip install -e .`.
"""
try:
    from importlib.metadata import PackageNotFoundError, version

    try:
        __version__ = version("containarium-telemetry")
    except PackageNotFoundError:
        __version__ = "0.0.0+unknown"
except ImportError:  # pragma: no cover — Python < 3.8 path; unreachable per requires-python
    __version__ = "0.0.0+unknown"
