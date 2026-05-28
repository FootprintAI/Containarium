"""containarium-instrument console script.

Thin alias over `opentelemetry-instrument` (decision D8 — always
installed). Adds:

  - `--dry-run`: prints resolved config and exits without launching
    the app (D12).
  - `--version` / `--help`: branding + usage.

Anything else execvp()s `opentelemetry-instrument` with the same args
and lets the upstream runtime drive the auto-instrument flow. Our
Distro + Configurator are registered as opentelemetry entry points, so
the upstream `opentelemetry-instrument` picks up our customizations
without us forking its argv parser.
"""
from __future__ import annotations

import os
import sys
from typing import List, Optional


def main(argv: Optional[List[str]] = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    if not argv or argv[0] in ("-h", "--help"):
        _print_help()
        return 0 if argv else 2

    if argv[0] in ("-V", "--version"):
        from ._version import __version__

        print(f"containarium-instrument {__version__}")
        return 0

    if argv[0] == "--dry-run":
        return _dry_run()

    # Delegate to upstream. execvp replaces the process so any state
    # we set on the way in (e.g. env defaults from importing this
    # module's deps) carries forward.
    cmd = "opentelemetry-instrument"
    try:
        os.execvp(cmd, [cmd] + argv)
    except FileNotFoundError:
        print(
            f"containarium-instrument: '{cmd}' not found in PATH. "
            "Reinstall containarium-telemetry to pull the "
            "opentelemetry-instrumentation dep, or pip install "
            "opentelemetry-instrumentation directly.",
            file=sys.stderr,
        )
        return 127
    # Unreachable on success — execvp replaces the process.
    return 0


def _dry_run() -> int:
    from ._config import DistroConfig
    from ._dry_run import format_config

    config = DistroConfig.from_env()
    print(format_config(config))
    return 0


def _print_help() -> None:
    print(
        """containarium-instrument — Run a Python app with the Containarium telemetry distro.

Usage:
  containarium-instrument [--dry-run | --version | --help] <command> [args ...]

Options:
  --dry-run    Print the resolved telemetry config (endpoint, resource
               attrs, redacted headers, distro version) and exit. Does
               NOT launch the wrapped command.
  --version    Print distro version and exit.
  --help       Show this help and exit.

Without a flag, exec()s opentelemetry-instrument with the same args.
Our Distro + Configurator are registered as OTel entry points, so
auto-instrumentation picks up the Containarium identity stamping and
OTLP/HTTP defaults transparently.

Examples:
  containarium-instrument python app.py
  containarium-instrument --dry-run
  containarium-instrument python -m flask run
"""
    )
